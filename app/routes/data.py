"""Protected data endpoints.

GET  /api/data    - read the data set (authenticated users only)
POST /api/posts   - create a post   (authenticated users only, added endpoint)
"""

from __future__ import annotations

from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from ..db import get_db
from ..security import encode_for_html, require_auth
from ..validation import ValidationError, clean_text, require_json_object

data_bp = Blueprint("data", __name__, url_prefix="/api")


@data_bp.get("/data")
@require_auth
def get_data():
    connection = get_db()
    users = connection.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY id"
    ).fetchall()
    posts = connection.execute(
        """
        SELECT p.id, p.title, p.body, p.created_at, u.username AS author
        FROM posts AS p
        JOIN users AS u ON u.id = p.author_id
        ORDER BY p.id
        """
    ).fetchall()

    return jsonify(
        encode_for_html(
            {
                "requested_by": g.current_user,
                "users": [dict(row) for row in users],
                "posts": [dict(row) for row in posts],
            }
        )
    ), 200


@data_bp.post("/posts")
@require_auth
def create_post():
    payload = request.get_json(silent=True)
    try:
        payload = require_json_object(payload)
        title = clean_text(
            payload.get("title"),
            field="title",
            max_length=current_app.config["POST_TITLE_MAX_LENGTH"],
        )
        body = clean_text(
            payload.get("body"),
            field="body",
            max_length=current_app.config["POST_BODY_MAX_LENGTH"],
        )
    except ValidationError as exc:
        return jsonify({"error": "validation_error", "message": str(exc)}), 400

    connection = get_db()
    created_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    cursor = connection.execute(
        "INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        (g.current_user["id"], title, body, created_at),
    )
    connection.commit()

    created = connection.execute(
        "SELECT id, title, body, created_at FROM posts WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    return jsonify(
        encode_for_html(
            {
                "message": "Post created.",
                "post": dict(created),
                "author": g.current_user["username"],
            }
        )
    ), 201
