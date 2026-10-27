"""POST /auth/login - authenticate a user and issue a JWT."""

from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, jsonify, request

from ..db import get_db
from ..security import (
    create_access_token,
    encode_for_html,
    login_is_throttled,
    register_failed_login,
    reset_login_attempts,
    verify_password,
)
from ..validation import ValidationError, clean_password, clean_username, require_json_object

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")


def _throttle_key(username: str) -> str:
    return f"{request.remote_addr or 'unknown'}:{username}"


@auth_bp.post("/login")
def login():
    payload = request.get_json(silent=True)
    try:
        payload = require_json_object(payload)
        username = clean_username(payload.get("username"))
        password = clean_password(
            payload.get("password"),
            min_length=current_app.config["PASSWORD_MIN_LENGTH"],
            max_length=current_app.config["PASSWORD_MAX_LENGTH"],
        )
    except ValidationError as exc:
        return jsonify({"error": "validation_error", "message": str(exc)}), 400

    key = _throttle_key(username)
    if login_is_throttled(key):
        response = jsonify(
            {
                "error": "too_many_attempts",
                "message": "Too many failed login attempts. Try again later.",
            }
        )
        response.status_code = 429
        response.headers["Retry-After"] = str(current_app.config["LOGIN_WINDOW_SECONDS"])
        return response

    # Parameterised query: the username can never alter the SQL statement.
    row = get_db().execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    ).fetchone()

    if row is None or not verify_password(password, row["password_hash"]):
        register_failed_login(key)
        # A single generic message prevents username enumeration.
        return jsonify({"error": "invalid_credentials", "message": "Invalid username or password."}), 401

    reset_login_attempts(key)
    token, expires_in = create_access_token(row["id"], row["username"], row["role"])
    return jsonify(
        encode_for_html(
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": expires_in,
                "user": {"id": row["id"], "username": row["username"], "role": row["role"]},
            }
        )
    ), 200
