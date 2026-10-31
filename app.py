"""ShardGate dashboard: vault status, Q&A, compromise simulation, audit trail.

Seeds a demo vault on first run so the judge demo works immediately.
"""
import os
from flask import Flask, jsonify, request, render_template

from shardgate.agent import ShardGateAgent
from shardgate.audit import AuditLog
from shardgate.guardian import KeyGuardian
from shardgate.vault import Vault

VAULT_DIR = os.environ.get("SHARDGATE_VAULT", "vault")
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

def build_services(seed=True):
    fresh = not os.path.exists(os.path.join(VAULT_DIR, "index.json"))
    if seed and fresh:
        key = os.urandom(32)
        g = KeyGuardian(key, threshold=2, shares=3, vault_dir=VAULT_DIR)
        v = Vault(VAULT_DIR)
        for name, text in SEED_DOCS.items():
            v.write_with(g, name, text.encode())
        del key
    g = KeyGuardian.__new__(KeyGuardian)
    g.threshold = 2
    g.shares = 3
    g.vault_dir = VAULT_DIR
    g.shard_paths = {i: os.path.join(VAULT_DIR, f"shard_{i}.key") for i in (1, 2, 3)}
    v = Vault(VAULT_DIR)
    a = AuditLog(os.path.join(VAULT_DIR, "audit.log"))
    return ShardGateAgent(g, v, audit=a)

agent = build_services()

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/status")
def status():
    present = agent.guardian.present_shards()
    return jsonify({
        "threshold": agent.guardian.threshold,
        "shares": agent.guardian.shares,
        "present_shards": present,
        "docs": [{"name": n, "size": agent.vault.doc_size(n)} for n in agent.vault.list_docs()],
        "audit": agent.audit.tail(10),
    })

@app.route("/api/ask", methods=["POST"])
def ask():
    q = (request.json or {}).get("question", "").strip()
    if not q:
        return jsonify({"error": "empty question"}), 400
    return jsonify(agent.ask(q))

@app.route("/api/documents", methods=["POST"])
def add_document():
    body = request.json or {}
    name = (body.get("name") or "").strip() or "untitled.txt"
    text = body.get("text", "")
    if not text:
        return jsonify({"error": "empty document"}), 400
    agent.vault.write_with(agent.guardian, name, text.encode())
    return jsonify({"ok": True, "name": name})

@app.route("/api/compromise", methods=["POST"])
def compromise():
    body = request.json or {}
    i = int(body.get("shard", 3))
    ok = agent.guardian.destroy_shard(i)
    agent.audit.log("SHARD_DESTROYED" if ok else "SHARD_ALREADY_GONE", f"shard {i}")
    return jsonify({"ok": ok, "shard": i, "present": agent.guardian.present_shards()})

@app.route("/api/reset", methods=["POST"])
def reset():
    global agent
    import shutil
    shutil.rmtree(VAULT_DIR, ignore_errors=True)
    agent = build_services(seed=True)
    return jsonify({"ok": True})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
