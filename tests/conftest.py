from __future__ import annotations

import pytest

from app import create_app
from app.config import TestConfig
from app.security import _attempts


@pytest.fixture
def app(tmp_path):
    class TestingConfig(TestConfig):
        DATABASE = str(tmp_path / "test.db")
        JWT_SECRET = "unit-test-secret-key-not-used-in-production"
        BCRYPT_ROUNDS = 4
        ACCESS_TOKEN_TTL_MINUTES = 15

    application = create_app(TestingConfig)
    yield application


@pytest.fixture
def client(app):
    with app.test_client() as test_client:
        yield test_client


@pytest.fixture(autouse=True)
def clear_login_throttle():
    _attempts.clear()
    yield
    _attempts.clear()


@pytest.fixture
def auth_headers(client):
    response = client.post("/auth/login", json={"username": "demo", "password": "Demo!Passw0rd"})
    assert response.status_code == 200, response.get_json()
    token = response.get_json()["access_token"]
    return {"Authorization": f"Bearer {token}"}
