"""Unit tests for the demo web layer (no server / root required)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from hypershell.config import ConfigError
from hypershell.web.config_store import ConfigStore

BASE = Path(__file__).resolve().parents[1]
SAMPLE = BASE / "examples" / "demo" / "hypershell.yaml"


def _valid_text() -> str:
    return SAMPLE.read_text(encoding="utf-8")


def test_validate_accepts_sample():
    store = ConfigStore(BASE / "examples/demo/hypershell.yaml", BASE / ".test-tmp/b", BASE / ".test-tmp/a.jsonl")
    ok, result = store.validate(_valid_text())
    assert ok, result


def test_save_backs_up_and_audits(tmp_path):
    admin = tmp_path / "admin.yaml"
    admin.write_text(_valid_text(), encoding="utf-8")
    store = ConfigStore(admin, tmp_path / "backups", tmp_path / "audit.jsonl")
    saved = store.save(_valid_text(), actor="tester")
    assert saved["ok"] and saved["backup"]
    assert list((tmp_path / "backups").glob("admin-*.yaml"))
    assert "CONFIG_SAVED" in (tmp_path / "audit.jsonl").read_text(encoding="utf-8")


def test_duplicate_key_rejected(tmp_path):
    store = ConfigStore(tmp_path / "admin.yaml", tmp_path / "b", tmp_path / "a.jsonl")
    bad = _valid_text().replace("version: 1", "version: 1\nversion: 1", 1)
    ok, result = store.validate(bad)
    assert not ok
    assert result["error"]["code"] == "INVALID_CONFIG"
    with pytest.raises(ConfigError):
        store.save(bad, actor="tester")


def test_unknown_field_rejected(tmp_path):
    store = ConfigStore(tmp_path / "admin.yaml", tmp_path / "b", tmp_path / "a.jsonl")
    data = yaml.safe_load(_valid_text())
    data["unexpected"] = True
    ok, result = store.validate(yaml.safe_dump(data))
    assert not ok


# ---- auth (requires argon2-cffi, i.e. the ``web`` extra) ----
from hypershell.web.auth import (  # noqa: E402
    AuthError,
    authenticate,
    hash_password,
    load_accounts,
    verify_password,
)


def test_password_roundtrip():
    pytest.importorskip("argon2")
    digest = hash_password("s3cret")
    assert verify_password(digest, "s3cret")
    assert not verify_password(digest, "wrong")


def test_accounts_load_and_authenticate(tmp_path):
    pytest.importorskip("argon2")
    accounts_path = tmp_path / "accounts.yaml"
    accounts_path.write_text(
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
    accounts = load_accounts(accounts_path)
    assert authenticate(accounts, "admin", "pw")["role"] == "admin"
    assert authenticate(accounts, "u1", "pw")["user_id"] == "u1"
    assert authenticate(accounts, "u1", "bad") is None
    assert authenticate(accounts, "missing", "pw") is None


def test_user_role_requires_user_id(tmp_path):
    pytest.importorskip("argon2")
    accounts_path = tmp_path / "bad.yaml"
    accounts_path.write_text(
        yaml.safe_dump(
            {
                "version": 1,
                "accounts": {"u1": {"role": "user", "password_hash": hash_password("pw")}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(AuthError):
        load_accounts(accounts_path)
