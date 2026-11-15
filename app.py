"""ShardGate dashboard: per-user encrypted vaults, Q&A, compromise simulation, audit trail.

Each account gets its own AES-256-GCM vault with a 2-of-3 Shamir-split master key.
Seeds a demo vault on registration so a new user can explore immediately.
"""
import os
import shutil

from flask import Flask, g, jsonify, request, render_template, send_from_directory

from shardgate.agent import ShardGateAgent
from shardgate.audit import AuditLog
from shardgate.guardian import KeyGuardian
from shardgate.vault import Vault
from shardgate import auth as accounts
from shardgate.auth import (
    auth_rate_limited, authenticate, clear_session_cookie, delete_account,
    export_user_data, issue_token, login_failed, login_locked, register_user,
    require_auth, set_session_cookie, user_dir,
)

app = Flask(__name__)

SEED_DOCS = {
    "intro_to_secret_sharing.txt": (
        "Shamir's Secret Sharing, invented by Adi Shamir in 1979, splits a secret into "
        "n shares using a random polynomial of degree k-1 over a finite field. Any k "
        "shares reconstruct the secret by Lagrange interpolation at zero, but any k-1 "
        "shares reveal absolutely nothing about it. This is information-theoretic "
        "security: even an attacker with unlimited computing power learns nothing. "
        "ShardGate uses a 2-of-3 split, so the master key never exists whole on disk."
    ),
    "aes_gcm_notes.txt": (
        "AES-256-GCM is an authenticated encryption mode. Besides confidentiality it "
        "produces an authentication tag, so any single flipped bit in the ciphertext "
        "makes decryption fail loudly instead of returning corrupted plaintext. "
        "ShardGate stores every document as nonce, tag, ciphertext and treats a failed "
        "tag check as evidence of tampering, refusing to answer and writing an audit "
        "event."
    ),
}


def build_services(vault_dir, seed=True):
    fresh = not os.path.exists(os.path.join(vault_dir, "index.json"))
    if seed and fresh:
        key = os.urandom(32)
        g = KeyGuardian(key, threshold=2, shares=3, vault_dir=vault_dir)
        v = Vault(vault_dir)
        for name, text in SEED_DOCS.items():
            v.write_with(g, name, text.encode())
        del key
    g = accounts._guardian_for(vault_dir)
    v = Vault(vault_dir)
    a = AuditLog(os.path.join(vault_dir, "audit.log"))
    return ShardGateAgent(g, v, audit=a)


def user_agent(user):
    return build_services(user_dir(user), seed=False)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/privacy.html")
def privacy():
    return send_from_directory("static", "privacy.html")


@app.route("/about.html")
def about():
    return send_from_directory("static", "about.html")


@app.route("/api/auth/register", methods=["POST"])
def auth_register():
    if auth_rate_limited():
        return jsonify({"error": "too many attempts; try again later"}), 429
    body = request.json or {}
    user, err = register_user(body.get("email", ""), body.get("password", ""))
    if err:
        return jsonify({"error": err}), 400
    build_services(user_dir(user), seed=True)
    token = issue_token(user)
    resp = jsonify({"user": {"id": user["id"], "email": user["email"]}})
    set_session_cookie(resp, token)
    return resp, 201


@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    body = request.json or {}
    email = (body.get("email") or "").strip().lower()
    if auth_rate_limited():
        return jsonify({"error": "too many attempts; try again later"}), 429
    if login_locked(email):
        return jsonify({"error": "too many failed logins; try again in 15 minutes"}), 429
    user = authenticate(email, body.get("password", ""))
    if not user:
        login_failed(email)
        return jsonify({"error": "invalid email or password"}), 401
    token = issue_token(user)
    resp = jsonify({"user": {"id": user["id"], "email": user["email"]}})
    set_session_cookie(resp, token)
    return resp


@app.route("/api/auth/me")
@require_auth
def auth_me():
    return jsonify({"user": {"id": g.user["id"], "email": g.user["email"]}})


@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    resp = jsonify({"ok": True})
    return clear_session_cookie(resp)


@app.route("/api/auth/export")
@require_auth
def auth_export():
    return jsonify(export_user_data(g.user))


@app.route("/api/auth/me", methods=["DELETE"])
@require_auth
def auth_delete():
    delete_account(g.user)
    resp = jsonify({"ok": True, "deleted": True})
    return clear_session_cookie(resp)


@app.route("/api/status")
@require_auth
def status():
    agent = user_agent(g.user)
    present = agent.guardian.present_shards()
    return jsonify({
        "threshold": agent.guardian.threshold,
        "shares": agent.guardian.shares,
        "present_shards": present,
        "docs": [{"name": n, "size": agent.vault.doc_size(n)} for n in agent.vault.list_docs()],
        "audit": agent.audit.tail(10),
    })


@app.route("/api/ask", methods=["POST"])
@require_auth
def ask():
    q = (request.json or {}).get("question", "").strip()
    if not q:
        return jsonify({"error": "empty question"}), 400
    if len(q) > 2000:
        return jsonify({"error": "question too long"}), 400
    return jsonify(user_agent(g.user).ask(q))


@app.route("/api/documents", methods=["POST"])
@require_auth
def add_document():
    body = request.json or {}
    name = (body.get("name") or "").strip() or "untitled.txt"
    text = body.get("text", "")
    if not text:
        return jsonify({"error": "empty document"}), 400
    if len(text) > 200_000:
        return jsonify({"error": "document too large (200k character limit)"}), 400
    safe = "".join(c for c in name if c.isalnum() or c in "._- ")[:120].strip() or "untitled.txt"
    agent = user_agent(g.user)
    agent.vault.write_with(agent.guardian, safe, text.encode())
    agent.audit.log("DOC_ADDED", safe)
    return jsonify({"ok": True, "name": safe})


@app.route("/api/compromise", methods=["POST"])
@require_auth
def compromise():
    body = request.json or {}
    i = int(body.get("shard", 3))
    if i not in (1, 2, 3):
        return jsonify({"error": "shard must be 1, 2 or 3"}), 400
    agent = user_agent(g.user)
    ok = agent.guardian.destroy_shard(i)
    agent.audit.log("SHARD_DESTROYED" if ok else "SHARD_ALREADY_GONE", f"shard {i}")
    return jsonify({"ok": ok, "shard": i, "present": agent.guardian.present_shards()})


@app.route("/api/reset", methods=["POST"])
@require_auth
def reset():
    d = user_dir(g.user)
    shutil.rmtree(d, ignore_errors=True)
    build_services(d, seed=True)
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
