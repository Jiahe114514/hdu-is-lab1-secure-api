"""Authentication, output encoding and brute-force protection helpers."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

import bcrypt
import jwt
from flask import current_app, g, jsonify, request
from markupsafe import escape as html_escape

# --------------------------------------------------------------------------
# Password storage
# --------------------------------------------------------------------------
# bcrypt is deliberately slow and salts every hash, so a stolen database
# cannot be attacked with pre-computed rainbow tables or cheap GPU cracking.
# A fixed dummy hash is verified for unknown users so that response times do
# not reveal whether a username exists (user-enumeration mitigation).

_DUMMY_HASH = bcrypt.hashpw(b"dummy-password-for-timing", bcrypt.gensalt(rounds=4)).decode()


def hash_password(plain_password: str) -> str:
    rounds = current_app.config.get("BCRYPT_ROUNDS", 12)
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=rounds)).decode("utf-8")


def verify_password(plain_password: str, password_hash: str | None) -> bool:
    candidate = (password_hash or _DUMMY_HASH).encode("utf-8")
    try:
        matched = bcrypt.checkpw(plain_password.encode("utf-8"), candidate)
    except ValueError:
        return False
    return bool(matched) and password_hash is not None


# --------------------------------------------------------------------------
# JWT
# --------------------------------------------------------------------------

def create_access_token(user_id: int, username: str, role: str) -> tuple[str, int]:
    """Return ``(token, ttl_seconds)`` for the authenticated user."""
    ttl_minutes = current_app.config["ACCESS_TOKEN_TTL_MINUTES"]
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iss": current_app.config["JWT_ISSUER"],
        "iat": now,
        "exp": now + timedelta(minutes=ttl_minutes),
    }
    token = jwt.encode(
        payload,
        current_app.config["JWT_SECRET"],
        algorithm=current_app.config["JWT_ALGORITHM"],
    )
    return token, ttl_minutes * 60


def decode_access_token(token: str) -> dict:
    return jwt.decode(
        token,
        current_app.config["JWT_SECRET"],
        algorithms=[current_app.config["JWT_ALGORITHM"]],
        issuer=current_app.config["JWT_ISSUER"],
        options={"require": ["exp", "iat", "sub"]},
    )


def unauthorized(message: str, code: str = "unauthorized"):
    response = jsonify({"error": code, "message": message})
    response.status_code = 401
    response.headers["WWW-Authenticate"] = 'Bearer realm="secure-api"'
    return response


def require_auth(view):
    """Reject any request that does not present a valid ``Bearer`` token."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            return unauthorized("Missing bearer token.")

        try:
            payload = decode_access_token(token.strip())
        except jwt.ExpiredSignatureError:
            return unauthorized("Token has expired.", "token_expired")
        except jwt.InvalidTokenError:
            return unauthorized("Token is invalid.")

        from .db import get_db

        row = get_db().execute(
            "SELECT id, username, role FROM users WHERE id = ?", (int(payload["sub"]),)
        ).fetchone()
        if row is None:
            return unauthorized("Token subject no longer exists.")

        g.current_user = {"id": row["id"], "username": row["username"], "role": row["role"]}
        return view(*args, **kwargs)

    return wrapper


# --------------------------------------------------------------------------
# Login throttling
# --------------------------------------------------------------------------
_attempts: dict[str, deque] = defaultdict(deque)


def login_is_throttled(key: str) -> bool:
    window = current_app.config["LOGIN_WINDOW_SECONDS"]
    limit = current_app.config["LOGIN_MAX_ATTEMPTS"]
    now = time.monotonic()
    bucket = _attempts[key]
    while bucket and now - bucket[0] > window:
        bucket.popleft()
    return len(bucket) >= limit


def register_failed_login(key: str) -> None:
    _attempts[key].append(time.monotonic())


def reset_login_attempts(key: str) -> None:
    _attempts.pop(key, None)


# --------------------------------------------------------------------------
# Output encoding (XSS defence in depth)
# --------------------------------------------------------------------------
def encode_for_html(value):
    """Recursively HTML-escape every string in a payload.

    JSON responses are not executed by browsers, but the same data is often
    rendered by a client later on.  Escaping at the API boundary means a
    stored ``<script>`` payload can never become live markup downstream.
    """
    if isinstance(value, str):
        return str(html_escape(value))
    if isinstance(value, dict):
        return {key: encode_for_html(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [encode_for_html(item) for item in value]
    return value
