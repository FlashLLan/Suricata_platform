"""Tests for /api/auth — register, login, /me, and auth guards."""
from tests.conftest import register_and_login


# ─── Register ─────────────────────────────────────────────────────────────────

class TestRegister:
    def test_register_success(self, client):
        resp = client.post("/api/auth/register", json={"email": "a@b.com", "password": "secret"})
        assert resp.status_code == 201
        body = resp.json()
        assert body["email"] == "a@b.com"
        assert "id" in body
        assert "password" not in body           # never expose the hash
        assert "password_hash" not in body

    def test_register_duplicate_email(self, client):
        payload = {"email": "dup@test.com", "password": "pass"}
        client.post("/api/auth/register", json=payload)
        resp = client.post("/api/auth/register", json=payload)
        assert resp.status_code == 400
        assert "already registered" in resp.json()["detail"].lower()

    def test_register_invalid_email(self, client):
        resp = client.post("/api/auth/register", json={"email": "not-an-email", "password": "pass"})
        assert resp.status_code == 422    # pydantic validation error


# ─── Login ────────────────────────────────────────────────────────────────────

class TestLogin:
    def test_login_success(self, client):
        client.post("/api/auth/register", json={"email": "u@test.com", "password": "mypass"})
        resp = client.post("/api/auth/login", data={"username": "u@test.com", "password": "mypass"})
        assert resp.status_code == 200
        body = resp.json()
        assert "access_token" in body
        assert body["token_type"] == "bearer"

    def test_login_wrong_password(self, client):
        client.post("/api/auth/register", json={"email": "u@test.com", "password": "correct"})
        resp = client.post("/api/auth/login", data={"username": "u@test.com", "password": "wrong"})
        assert resp.status_code == 401

    def test_login_unknown_email(self, client):
        resp = client.post("/api/auth/login", data={"username": "ghost@test.com", "password": "x"})
        assert resp.status_code == 401


# ─── /me ─────────────────────────────────────────────────────────────────────

class TestMe:
    def test_me_authenticated(self, client):
        headers = register_and_login(client, "me@test.com")
        resp = client.get("/api/auth/me", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["email"] == "me@test.com"

    def test_me_no_token(self, client):
        resp = client.get("/api/auth/me")
        assert resp.status_code == 401

    def test_me_bad_token(self, client):
        resp = client.get("/api/auth/me", headers={"Authorization": "Bearer garbage"})
        assert resp.status_code == 401
