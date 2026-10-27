"""SQLite access layer.

All statements use *parameter binding* (``?`` placeholders).  No SQL text is
ever assembled by string concatenation or f-strings, which is the primary
defence against SQL injection (OWASP A03:2021 - Injection).
"""

from __future__ import annotations

import os
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    role          TEXT    NOT NULL DEFAULT 'user',
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    author_id  INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    title      TEXT    NOT NULL,
    body       TEXT    NOT NULL,
    created_at TEXT    NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    """Return a per-request connection stored on the Flask ``g`` object."""
    if "db" not in g:
        connection = sqlite3.connect(current_app.config["DATABASE"])
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        g.db = connection
    return g.db


def close_db(_exc: BaseException | None = None) -> None:
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def init_db() -> None:
    """Create the schema and seed demo accounts when the database is empty."""
    connection = get_db()
    connection.executescript(SCHEMA)
    connection.commit()

    existing = connection.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
    if existing:
        return

    # Imported lazily to avoid a circular import at module load time.
    from .security import hash_password

    now = "2026-01-01T00:00:00+00:00"
    seed_users = [
        ("admin", os.environ.get("SEED_ADMIN_PASSWORD", "Admin!Passw0rd"), "admin"),
        ("demo", os.environ.get("SEED_DEMO_PASSWORD", "Demo!Passw0rd"), "user"),
    ]
    connection.executemany(
        "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
        [(name, hash_password(secret), role, now) for name, secret, role in seed_users],
    )
    connection.executemany(
        "INSERT INTO posts (author_id, title, body, created_at) VALUES (?, ?, ?, ?)",
        [
            (1, "Welcome to the secure API", "This row is served from SQLite.", now),
            (2, "Second post", "Demonstrates the protected data endpoint.", now),
        ],
    )
    connection.commit()


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    os.makedirs(os.path.dirname(app.config["DATABASE"]), exist_ok=True)
    with app.app_context():
        init_db()
