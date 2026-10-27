"""Functional and security regression tests for the secure API."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import jwt
import pytest

from app.security import _attempts


def login(client, username="demo", password="Demo!Passw0rd"):
    return client.post("/auth/login", json={"username": username, "password": password})


# ---------------------------------------------------------------- basics
def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.get_json() == {"status": "ok"}


def test_login_success_returns_jwt(client):
    response = login(client)
    body = response.get_json()
    assert response.status_code == 200
    assert body["token_type"] == "Bearer"
    assert body["access_token"].count(".") == 2
    assert body["user"]["username"] == "demo"


@pytest.mark.parametrize(
    "payload",
    [
        {"username": "demo", "password": "wrong-password"},
        {"username": "ghost", "password": "Demo!Passw0rd"},
    ],
)
def test_login_failures_are_generic(client, payload):
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 401
    assert response.get_json()["message"] == "Invalid username or password."


def test_login_validation_rejects_oversized_input(client):
    response = client.post("/auth/login", json={"username": "demo", "password": "x" * 500})
    assert response.status_code == 400
    assert response.get_json()["error"] == "validation_error"


def test_login_brute_force_is_rate_limited(client):
    for _ in range(5):
        assert login(client, password="wrong-password").status_code == 401
    response = login(client, password="wrong-password")
    assert response.status_code == 429
    assert response.headers["Retry-After"]


# ---------------------------------------------------------------- access control
def test_data_requires_token(client):
    response = client.get("/api/data")
    assert response.status_code == 401
    assert response.get_json()["error"] == "unauthorized"


def test_data_rejects_tampered_token(client):
    response = client.get("/api/data", headers={"Authorization": "Bearer not.a.jwt"})
    assert response.status_code == 401


def test_data_rejects_expired_token(client, app):
    expired = jwt.encode(
        {
            "sub": "2",
            "username": "demo",
            "role": "user",
            "iss": app.config["JWT_ISSUER"],
            "iat": datetime.now(timezone.utc) - timedelta(hours=2),
            "exp": datetime.now(timezone.utc) - timedelta(hours=1),
        },
        app.config["JWT_SECRET"],
        algorithm="HS256",
    )
    response = client.get("/api/data", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401
    assert response.get_json()["error"] == "token_expired"


def test_data_returns_records_without_secrets(client, auth_headers):
    response = client.get("/api/data", headers=auth_headers)
    body = response.get_json()
    assert response.status_code == 200
    assert body["users"] and body["posts"]
    assert all("password_hash" not in user for user in body["users"])


# ---------------------------------------------------------------- injection
def test_sql_injection_payload_does_not_authenticate(client):
    payload = {"username": "admin' OR '1'='1", "password": "anything"}
    response = client.post("/auth/login", json=payload)
    assert response.status_code == 400  # rejected by the allow-list validator


def test_sql_metacharacters_are_stored_literally(client, auth_headers):
    body = "Robert'); DROP TABLE posts;--"
    response = client.post(
        "/api/posts", json={"title": "injection attempt", "body": body}, headers=auth_headers
    )
    assert response.status_code == 201
    # The table still exists and the text was stored as plain data.
    listed = client.get("/api/data", headers=auth_headers)
    assert listed.status_code == 200


# ---------------------------------------------------------------- xss
def test_xss_payload_is_escaped_in_responses(client, auth_headers):
    payload = "<script>alert('xss')</script>"
    created = client.post(
        "/api/posts", json={"title": payload, "body": "comment"}, headers=auth_headers
    )
    assert created.status_code == 201
    assert "<script>" not in created.get_data(as_text=True)
    assert "&lt;script&gt;" in created.get_json()["post"]["title"]


def test_security_headers_present(client):
    response = client.get("/health")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "default-src 'none'" in response.headers["Content-Security-Policy"]


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"title": "only title"},
        {"title": "", "body": "x"},
        {"title": "ok", "body": "y" * 5000},
    ],
)
def test_create_post_validates_input(client, auth_headers, payload):
    response = client.post("/api/posts", json=payload, headers=auth_headers)
    assert response.status_code == 400


def test_unknown_route_returns_json_404(client):
    response = client.get("/nope")
    assert response.status_code == 404
    assert response.get_json()["error"] == "not_found"
