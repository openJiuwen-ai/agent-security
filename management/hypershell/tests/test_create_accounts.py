"""Account provisioning must not ship passwords or overwrite credentials."""

from importlib.util import module_from_spec, spec_from_file_location
from io import StringIO
import os
from pathlib import Path
import subprocess
import sys

import pytest

pytest.importorskip("argon2")
from hypershell.web.auth import authenticate, load_accounts  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/dev/create_accounts.py"
spec = spec_from_file_location("create_accounts", SCRIPT)
provision = module_from_spec(spec)
spec.loader.exec_module(provision)


def _run_provision(path, *options, stdin="", interactive=False):
    if interactive:
        # Supply prompt answers without opening a terminal in the test runner.
        program = (
            "import getpass, runpy, sys\n"
            "from unittest.mock import Mock\n"
            "getpass.getpass = Mock(side_effect=sys.stdin.read().splitlines())\n"
            "sys.argv = sys.argv[1:]\n"
            "runpy.run_path(sys.argv[0], run_name='__main__')\n"
        )
        command = [sys.executable, "-c", program, str(SCRIPT)]
    else:
        command = [sys.executable, str(SCRIPT), "--password-stdin"]
    return subprocess.run(
        [*command, "--out", str(path), *options],
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        input=stdin,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def test_per_account_passwords_are_hashed_and_not_printed(tmp_path, monkeypatch, capsys):
    out = tmp_path / "accounts.yaml"
    passwords = ["admin-test-password", "user-one-password", "user-two-password"]
    monkeypatch.setattr("sys.stdin", StringIO("\n".join(passwords) + "\n"))
    assert provision.main(["--out", str(out), "--password-stdin"]) == 0
    accounts = load_accounts(out)
    for name, password in zip(["admin", "u1", "u2"], passwords):
        assert authenticate(accounts, name, password)
        assert password not in out.read_text(encoding="utf-8")
    assert authenticate(accounts, "u1", passwords[0]) is None
    output = capsys.readouterr()
    assert all(password not in output.out + output.err for password in passwords)


@pytest.mark.parametrize("stdin", ["", "short\n", "admin-test-password\n"])
def test_incomplete_or_weak_input_creates_no_accounts(tmp_path, stdin):
    out = tmp_path / "accounts.yaml"
    result = _run_provision(out, stdin=stdin)
    assert result.returncode == 2
    assert "at least 12 characters" in result.stderr
    assert not out.exists()


def test_existing_credentials_and_admin_name_collision_are_rejected(tmp_path):
    out = tmp_path / "accounts.yaml"
    out.write_text("keep existing", encoding="utf-8")
    existing = _run_provision(out)
    assert existing.returncode == 2
    assert "refusing to overwrite credentials" in existing.stderr
    assert out.read_text(encoding="utf-8") == "keep existing"
    other = tmp_path / "other.yaml"
    collision = _run_provision(other, "--admin-user", "u1")
    assert collision.returncode == 2
    assert "must be non-empty and unique" in collision.stderr
    assert not other.exists()


def test_interactive_confirmation_required(tmp_path):
    out = tmp_path / "accounts.yaml"
    result = _run_provision(out, stdin="admin-test-password\ndifferent-password\n", interactive=True)
    assert result.returncode == 2
    assert "passwords do not match" in result.stderr
    assert not out.exists()
