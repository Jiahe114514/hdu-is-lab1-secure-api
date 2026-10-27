"""Application configuration.

Every secret is read from the environment so that no credential is ever
committed to the repository.  In CI the value comes from GitHub Actions
secrets; for local development a throw-away fallback is generated.
"""

from __future__ import annotations

import os
import secrets


class Config:
    """Base configuration shared by every environment."""

    # --- Storage -----------------------------------------------------
    DATABASE = os.environ.get("DATABASE_PATH", os.path.join(os.getcwd(), "instance", "app.db"))

    # --- JWT ---------------------------------------------------------
    # A random secret is generated when nothing is provided so that the
    # development server still refuses to run with a well-known key.
    JWT_SECRET = os.environ.get("JWT_SECRET", secrets.token_urlsafe(48))
    JWT_ALGORITHM = "HS256"
    JWT_ISSUER = "hdu-is-lab1-secure-api"
    ACCESS_TOKEN_TTL_MINUTES = int(os.environ.get("ACCESS_TOKEN_TTL_MINUTES", "15"))

    # --- Password policy --------------------------------------------
    PASSWORD_MIN_LENGTH = 8
    PASSWORD_MAX_LENGTH = 128
    USERNAME_MIN_LENGTH = 3
    USERNAME_MAX_LENGTH = 32
    BCRYPT_ROUNDS = 12

    # --- Login throttling (brute-force mitigation) -------------------
    LOGIN_MAX_ATTEMPTS = 5
    LOGIN_WINDOW_SECONDS = 300

    # --- Content limits ---------------------------------------------
    POST_TITLE_MAX_LENGTH = 120
    POST_BODY_MAX_LENGTH = 2000

    TESTING = False


class TestConfig(Config):
    TESTING = True
