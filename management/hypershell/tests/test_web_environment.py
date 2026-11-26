"""Documented environment settings must reach the server and app factory."""

import os
from pathlib import Path
import secrets
import subprocess
import sys
from unittest.mock import Mock

import pytest

uvicorn = pytest.importorskip("uvicorn")
pytest.importorskip("fastapi")
from hypershell.web import __main__ as entry  # noqa: E402
from hypershell.web import app  # noqa: E402


@pytest.fixture
def web_startup(monkeypatch, tmp_path):
    default_file = tmp_path / "legacy" / "web-secret"
    monkeypatch.setattr(entry, "_LEGACY_SECRET_FILE", default_file)
    monkeypatch.delenv("HYPERSHELL_WEB_SECRET", raising=False)
    create = Mock(return_value=object())
    run = Mock()
    monkeypatch.setattr(app, "create_app", create)
    monkeypatch.setattr(uvicorn, "run", run)
    return create, run, default_file


def _write_key_file(path, contents):
    path.write_bytes(contents)
    path.chmod(0o600)


def test_documented_environment_names(monkeypatch, tmp_path, web_startup):
    create, run, _ = web_startup
    secret_file = tmp_path / "web-secret"
    signing_key = secrets.token_hex(32)
    _write_key_file(secret_file, (signing_key + "\n").encode("utf-8"))
    settings = {
        "WEB_HOST": "localhost",
        "WEB_PORT": "8123",
        "ADMIN_CONFIG": str(tmp_path / "admin.yaml"),
        "RUNTIME": str(tmp_path / "runtime.yaml"),
        "ACCOUNTS": str(tmp_path / "accounts.yaml"),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "WEB_AUDIT": str(tmp_path / "audit.jsonl"),
        "WEB_SECRET": str(secret_file),
    }
    for key, value in settings.items():
        monkeypatch.setenv("HYPERSHELL_" + key, value)
    assert entry.main([]) == 0
    assert create.call_args.kwargs["config_path"] == settings["ADMIN_CONFIG"]
    assert create.call_args.kwargs["accounts_path"] == settings["ACCOUNTS"]
    assert create.call_args.kwargs["secret_key"] == signing_key
    assert secret_file.read_text(encoding="utf-8") == signing_key + "\n"
    run.assert_called_once_with(create.return_value, host="localhost", port=8123, log_level="info")


def test_explicit_secret_file_overrides_environment(web_startup, monkeypatch, tmp_path):
    create, _, _ = web_startup
    monkeypatch.setenv("HYPERSHELL_WEB_SECRET", str(tmp_path / "missing-default"))
    secret_file = tmp_path / "supplied-key"
    signing_key = secrets.token_hex(32)
    _write_key_file(secret_file, signing_key.encode("utf-8"))

    assert entry.main(["--secret-file", str(secret_file)]) == 0
    assert create.call_args.kwargs["secret_key"] == signing_key


def test_existing_legacy_secret_file_is_reused(web_startup):
    create, _, default_file = web_startup
    default_file.parent.mkdir()
    signing_key = secrets.token_hex(32)
    _write_key_file(default_file, signing_key.encode("utf-8"))

    assert entry.main([]) == entry.main([]) == 0
    assert [call.kwargs["secret_key"] for call in create.call_args_list] == [signing_key, signing_key]
    assert default_file.read_text(encoding="utf-8") == signing_key


def test_demo_generates_a_key_without_creating_a_file(web_startup):
    create, _, default_file = web_startup

    assert entry.main([]) == entry.main([]) == 0
    signing_keys = [call.kwargs["secret_key"] for call in create.call_args_list]
    assert all(len(key) == 64 for key in signing_keys)
    assert len(set(signing_keys)) == 2
    assert not default_file.parent.exists()


@pytest.mark.parametrize(
    "contents, mode, message",
    [
        (None, 0o600, "cannot read session signing key file"),
        (b" \n", 0o600, "nonempty UTF-8"),
        (b"\xff", 0o600, "nonempty UTF-8"),
        pytest.param(
            b"test fixture",
            0o640,
            "no group or other permissions",
            marks=pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions"),
        ),
    ],
)
def test_invalid_configured_key_stops_startup(tmp_path, contents, mode, message):
    environment_key = tmp_path / "environment-key"
    _write_key_file(environment_key, secrets.token_hex(32).encode("utf-8"))
    secret_file = tmp_path / "configured-key"
    if contents is not None:
        _write_key_file(secret_file, contents)
        secret_file.chmod(mode)

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hypershell.web",
            "--secret-file",
            str(secret_file),
            "--accounts",
            str(tmp_path / "no-accounts"),
            "--host",
            "localhost",
            "--port",
            "0",
            "--relay-port-base",
            "0",
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "HYPERSHELL_WEB_SECRET": str(environment_key)},
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 2
    assert message in result.stderr
    assert secret_file.exists() == (contents is not None)
