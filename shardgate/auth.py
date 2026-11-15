"""ShardGate user accounts: SQLite users, bcrypt passwords, JWT session cookie,
per-IP rate limits and login lockout, data export and full account deletion."""
import os
import shutil
import sqlite3
import time
from collections import defaultdict, deque
from functools import wraps

import bcrypt
import jwt
from flask import g, jsonify, request

DATA_ROOT = os.environ.get("SHARDGATE_DATA", "data")
DB_PATH = os.path.join(DATA_ROOT, "shardgate.db")
SESSION_COOKIE = "shardgate_session"
SESSION_TTL = 7 * 24 * 3600

JWT_SECRET = os.environ.get("SHARDGATE_JWT_SECRET", "")
if not JWT_SECRET:
    # Ephemeral fallback for local runs: sessions die on restart. On a real host
    # SHARDGATE_JWT_SECRET must be set so sessions survive deploys.
    JWT_SECRET = os.urandom(32).hex()

AUTH_WINDOW_SECONDS = 900
AUTH_WINDOW_LIMIT = 30          # register/login attempts per IP per window
LOCKOUT_FAILS = 5              # failed logins per ip+email before lockout
LOCKOUT_WINDOW = 900

_auth_hits = defaultdict(deque)
_lockout = defaultdict(deque)


def _db():
    os.makedirs(DATA_ROOT, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at REAL NOT NULL
        )"""
    )
    return conn


def _client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    return (fwd.split(",")[0].strip() or request.remote_addr or "?") if fwd else (request.remote_addr or "?")


def _window_check(store, key, limit, window):
    now = time.time()
    hits = store[key]
    while hits and now - hits[0] > window:
        hits.popleft()
    if len(hits) >= limit:
        return False
    hits.append(now)
    return True


def auth_rate_limited():
    """True when this IP has burned its register/login budget for the window."""
    return not _window_check(_auth_hits, _client_ip(), AUTH_WINDOW_LIMIT, AUTH_WINDOW_SECONDS)


def login_locked(email):
    key = _client_ip() + "|" + email.lower()
    fails = _lockout[key]
    now = time.time()
    while fails and now - fails[0] > LOCKOUT_WINDOW:
        fails.popleft()
    return len(fails) >= LOCKOUT_FAILS


def login_failed(email):
    _lockout[_client_ip() + "|" + email.lower()].append(time.time())


def register_user(email, password):
    email = (email or "").strip().lower()
    if not email or "@" not in email or "." not in email.split("@")[-1]:
        return None, "enter a valid email address"
    if len(password or "") < 8:
        return None, "password must be at least 8 characters"
    conn = _db()
    try:
        exists = conn.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone()
        if exists:
            return None, "an account with this email already exists"
        digest = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()
        cur = conn.execute(
            "INSERT INTO users (email, password_hash, created_at) VALUES (?, ?, ?)",
            (email, digest, time.time()),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row), None
    finally:
        conn.close()


def authenticate(email, password):
    email = (email or "").strip().lower()
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if not row:
            return None
        if not bcrypt.checkpw((password or "").encode(), row["password_hash"].encode()):
            return None
        return dict(row)
    finally:
        conn.close()


def get_user(user_id):
    conn = _db()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def issue_token(user):
    return jwt.encode({"sub": str(user["id"]), "exp": int(time.time()) + SESSION_TTL},
                      JWT_SECRET, algorithm="HS256")


def set_session_cookie(response, token):
    response.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True,
                        samesite="Strict", secure=True, path="/")
    return response


def clear_session_cookie(response):
    response.set_cookie(SESSION_COOKIE, "", max_age=0, httponly=True,
                        samesite="Strict", secure=True, path="/")
    return response


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = request.cookies.get(SESSION_COOKIE)
        if not token:
            return jsonify({"error": "sign in required"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.PyJWTError:
            return jsonify({"error": "session expired; sign in again"}), 401
        user = get_user(int(payload["sub"]))
        if not user:
            return jsonify({"error": "account no longer exists"}), 401
        g.user = user
        return fn(*args, **kwargs)
    return wrapper


def user_dir(user):
    return os.path.join(DATA_ROOT, "users", str(user["id"]), "vault")


def export_user_data(user):
    from .cipher import decrypt
    d = user_dir(user)
    docs = []
    if os.path.exists(os.path.join(d, "index.json")):
        v = Vault(d)
        g = _guardian_for(d)
        for name in v.list_docs():
            plain = v.decrypt_doc(g, name).decode("utf-8", "replace")
            docs.append({"name": name, "text": plain})
    return {
        "account": {"email": user["email"], "created_at": user["created_at"]},
        "documents": docs,
        "note": "documents are returned decrypted; they were AES-256-GCM encrypted at rest",
    }


def delete_account(user):
    conn = _db()
    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user["id"],))
        conn.commit()
    finally:
        conn.close()
    shutil.rmtree(os.path.dirname(user_dir(user)), ignore_errors=True)


def _guardian_for(vault_dir):
    from .guardian import KeyGuardian
    g = KeyGuardian.__new__(KeyGuardian)
    g.threshold = 2
    g.shares = 3
    g.vault_dir = vault_dir
    g.shard_paths = {i: os.path.join(vault_dir, f"shard_{i}.key") for i in (1, 2, 3)}
    return g


from .vault import Vault  # noqa: E402  (needed by export_user_data)
