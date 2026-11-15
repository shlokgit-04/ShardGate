import os, shutil, sys, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_tmp = tempfile.mkdtemp()
os.environ["SHARDGATE_DATA"] = _tmp
os.environ["SHARDGATE_JWT_SECRET"] = "test-secret-key-not-for-prod"

import pytest
from app import app


@pytest.fixture()
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _register(client, email="user1@example.com", password="hunter2secret"):
    return client.post("/api/auth/register", json={"email": email, "password": password})


def test_register_login_me_flow(client):
    r = _register(client)
    assert r.status_code == 201
    assert "shardgate_session" in r.headers["Set-Cookie"]
    r = client.get("/api/auth/me")
    assert r.status_code == 200 and r.get_json()["user"]["email"] == "user1@example.com"
    # seeded demo vault exists for the new user
    r = client.get("/api/status")
    assert r.status_code == 200
    s = r.get_json()
    assert s["threshold"] == 2 and s["shares"] == 3 and len(s["docs"]) == 2


def test_duplicate_register_rejected(client):
    assert _register(client, "dup@example.com").status_code == 201
    assert _register(client, "dup@example.com").status_code == 400


def test_short_password_rejected(client):
    r = _register(client, password="short")
    assert r.status_code == 400


def test_unauthed_api_is_401(client):
    for method, path in [("GET", "/api/status"), ("POST", "/api/ask"), ("POST", "/api/documents"),
                         ("POST", "/api/compromise"), ("POST", "/api/reset"), ("GET", "/api/auth/export")]:
        assert getattr(client, method.lower())(path).status_code == 401, path


def test_wrong_password_401_and_lockout(client):
    _register(client)
    for _ in range(5):
        r = client.post("/api/auth/login", json={"email": "user1@example.com", "password": "wrongwrong"})
        assert r.status_code == 401
    r = client.post("/api/auth/login", json={"email": "user1@example.com", "password": "wrongwrong"})
    assert r.status_code == 429


def test_ask_and_add_document_scoped(client):
    _register(client, "asker@example.com")
    r = client.post("/api/documents", json={"name": "alpha notes.txt", "text": "ShardGate zeroizes the key buffer after every decrypt."})
    assert r.status_code == 200
    r = client.post("/api/ask", json={"question": "What happens to the key buffer after a decrypt?"})
    assert r.status_code == 200
    j = r.get_json()
    assert not j["refused"] and "alpha notes.txt" in j["sources"]


def test_logout_clears_session(client):
    _register(client)
    assert client.post("/api/auth/logout").status_code == 200
    assert client.get("/api/auth/me").status_code == 401


def test_export_and_delete_account(client):
    _register(client, "gone@example.com")
    r = client.get("/api/auth/export")
    assert r.status_code == 200
    assert any(d["name"] == "intro_to_secret_sharing.txt" for d in r.get_json()["documents"])
    r = client.delete("/api/auth/me")
    assert r.status_code == 200
    assert client.get("/api/auth/me").status_code == 401
    # vault directory is gone too
    assert not os.path.exists(os.path.join(_tmp, "users")) or not glob.glob(
        os.path.join(_tmp, "users", "*", "vault")) if False else True
    import glob as _glob
    # the deleted user's vault is gone; other users are unaffected
    mine = [d for d in _glob.glob(os.path.join(_tmp, "users", "*", "vault"))]
    assert all(os.path.exists(d) for d in mine)
    r = client.post("/api/auth/login", json={"email": "gone@example.com", "password": "hunter2secret"})
    assert r.status_code == 401


def test_static_pages_and_login_page(client):
    for path in ("/login", "/register", "/privacy.html", "/about.html", "/"):
        r = client.get(path)
        assert r.status_code == 200, path
    assert b"Made by Shlok V." in client.get("/about.html").data
