"""Unit tests for the privileged TUI launcher (scheme A)."""

from __future__ import annotations

import pytest
import yaml

from hypershell.tui_launcher import LauncherError, resolve_user_id


def _accounts(tmp_path):
    from hypershell.web.auth import hash_password, load_accounts

    path = tmp_path / "accounts.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "accounts": {
                    "admin": {"role": "admin", "display": "Admin", "password_hash": hash_password("pw")},
                    "u1": {"role": "user", "user_id": "u1", "password_hash": hash_password("pw")},
                },
            }
        ),
        encoding="utf-8",
    )
    return load_accounts(path)


def test_resolve_user_id(tmp_path):
    pytest.importorskip("argon2")
    accounts = _accounts(tmp_path)
    assert resolve_user_id(accounts, "u1", "pw") == "u1"


def test_reject_admin_account(tmp_path):
    pytest.importorskip("argon2")
    accounts = _accounts(tmp_path)
    with pytest.raises(LauncherError):
        resolve_user_id(accounts, "admin", "pw")


def test_reject_bad_password(tmp_path):
    pytest.importorskip("argon2")
    accounts = _accounts(tmp_path)
    with pytest.raises(LauncherError):
        resolve_user_id(accounts, "u1", "wrong")
