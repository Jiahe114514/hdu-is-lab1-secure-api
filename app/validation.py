"""Request validation helpers.

Validation is allow-list based: a value is accepted only when it matches the
expected shape.  Everything else produces a structured 400 response.
"""

from __future__ import annotations

import re

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


class ValidationError(ValueError):
    """Raised when a request body does not satisfy the contract."""


def require_json_object(payload) -> dict:
    if not isinstance(payload, dict):
        raise ValidationError("Request body must be a JSON object.")
    return payload


def clean_username(value) -> str:
    if not isinstance(value, str):
        raise ValidationError("Field 'username' must be a string.")
    value = value.strip()
    if not USERNAME_RE.fullmatch(value):
        raise ValidationError("Field 'username' must be 3-32 characters of [A-Za-z0-9_.-].")
    return value


def clean_password(value, *, min_length: int, max_length: int) -> str:
    if not isinstance(value, str):
        raise ValidationError("Field 'password' must be a string.")
    if not min_length <= len(value) <= max_length:
        raise ValidationError(
            f"Field 'password' must be between {min_length} and {max_length} characters."
        )
    return value


def clean_text(value, *, field: str, max_length: int, min_length: int = 1) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"Field '{field}' must be a string.")
    value = value.strip()
    if not min_length <= len(value) <= max_length:
        raise ValidationError(
            f"Field '{field}' must be between {min_length} and {max_length} characters."
        )
    return value
