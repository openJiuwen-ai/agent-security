"""Demo web authentication: password hashing, account loading, CSRF helpers.

This module never logs or returns passwords. Accounts map a login name to a
role (``admin`` or ``user``) and, for users, to an administrator-configured
``user_id``. Passwords are stored only as Argon2id hashes.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Any

import yaml

try:  # argon2-cffi is only required for the web extras
    from argon2 import PasswordHasher
except Exception:  # pragma: no cover - exercised only without the web extras
    PasswordHasher = None  # type: ignore[assignment]

_HASHER = PasswordHasher() if PasswordHasher is not None else None
_DUMMY_HASH: str | None = None


class AuthError(Exception):
    """Raised when the accounts file or a credential operation is invalid."""


def _require_hasher() -> None:
    if _HASHER is None:
        raise AuthError("argon2-cffi is required for web authentication")


def hash_password(password: str) -> str:
    _require_hasher()
    if not isinstance(password, str) or not password:
        raise AuthError("password must be a non-empty string")
    return _HASHER.hash(password)  # type: ignore[union-attr]


def verify_password(password_hash: str, password: str) -> bool:
    if _HASHER is None or not isinstance(password_hash, str):
        return False
    try:
        return bool(_HASHER.verify(password_hash, password))  # type: ignore[union-attr]
    except Exception:  # mismatches and malformed hashes all fail closed
        return False


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password-for-timing")
    return _DUMMY_HASH


def load_accounts(path: str | Path) -> dict[str, dict[str, Any]]:
    """Load and validate the accounts YAML file."""
    try:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise AuthError(f"cannot read accounts file: {path}") from exc
    if not isinstance(data, dict) or data.get("version") != 1:
        raise AuthError("accounts file must be a mapping with version: 1")
    accounts = data.get("accounts")
    if not isinstance(accounts, dict) or not accounts:
        raise AuthError("accounts file has no accounts")
    result: dict[str, dict[str, Any]] = {}
    for name, raw in accounts.items():
        if not isinstance(name, str) or not isinstance(raw, dict):
            raise AuthError("invalid account entry")
        role = raw.get("role")
        if role not in ("admin", "user"):
            raise AuthError(f"account {name!r} has invalid role")
        if not isinstance(raw.get("password_hash"), str) or not raw["password_hash"]:
            raise AuthError(f"account {name!r} has no password_hash")
        user_id = raw.get("user_id")
        if role == "user":
            if not isinstance(user_id, str) or not user_id:
                raise AuthError(f"account {name!r} with role user needs user_id")
        else:
            user_id = None
        result[name] = {
            "role": role,
            "user_id": user_id,
            "display": str(raw.get("display", name)),
            "disabled": bool(raw.get("disabled", False)),
            "password_hash": raw["password_hash"],
        }
    return result


def authenticate(accounts: dict[str, dict[str, Any]], username: str, password: str) -> dict[str, Any] | None:
    """Verify a login; return a principal dict or ``None``."""
    account = accounts.get(username)
    if account is None:
        # Constant-ish time: perform a hash verification even for unknown users.
        if _HASHER is not None:
            verify_password(_dummy_hash(), password)
        return None
    if account["disabled"] or not verify_password(account["password_hash"], password):
        return None
    return {
        "username": username,
        "role": account["role"],
        "user_id": account["user_id"],
        "display": account["display"],
    }


def new_csrf_token() -> str:
    return os.urandom(32).hex()


def check_csrf(session_token: object, form_token: object) -> bool:
    return (
        isinstance(session_token, str)
        and isinstance(form_token, str)
        and bool(session_token)
        and hmac.compare_digest(session_token, form_token)
    )
