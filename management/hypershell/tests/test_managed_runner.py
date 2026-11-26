"""Safety contracts for the live-demo control path."""

from pathlib import Path
import sys

import pytest

from hypershell.cli import main
from hypershell.runner.client import RunnerError
from hypershell.runner.managed import verify_projection, engine_command_matches


def test_engine_defaults_do_not_mask_changes_to_requested_fields():
    expected = {
        "network": {"egress": {"default": "deny", "allowed_ports": [443]}},
        "cgroup": {"cpu_max": (100000, 100000)},
    }
    actual = {
        "network": {"mode": "isolated", "egress": {"default": "deny", "allowed_ports": [443], "blocked_ips": []}},
        "cgroup": {"cpu_max": [100000, 100000], "pids_max": 128},
    }
    verify_projection(expected, actual)
    actual["network"]["egress"]["default"] = "allow"
    with pytest.raises(RunnerError, match="mismatch"):
        verify_projection(expected, actual)


@pytest.mark.parametrize("actual", [{}, {"mounts": []}, {"mounts": [{"mode": "rw"}]}])
def test_missing_or_widened_mount_is_rejected(actual):
    with pytest.raises(RunnerError):
        verify_projection({"mounts": [{"mode": "ro"}]}, actual)


def test_live_commands_reject_non_admin_before_reading_supplied_files(monkeypatch, capsys):
    monkeypatch.setattr("hypershell.runner.managed.os.geteuid", lambda: 1000, raising=False)
    code = main(
        ["start", "--config", "nonexistent", "--runtime", "nonexistent", "--user", "root", "--request", "nonexistent"]
    )
    assert code == 2
    assert "require a Linux administrator" in capsys.readouterr().err


def test_live_cli_does_not_accept_demo_identity_flag():
    import subprocess

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "hypershell",
            "start",
            "--config",
            "a",
            "--runtime",
            "b",
            "--user",
            "u1",
            "--request",
            "c",
            "--demo-user",
            "u1",
        ],
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 2
    assert "unrecognized arguments: --demo-user u1" in result.stderr


@pytest.mark.parametrize("phase", ["creating", "failed", "error", "stopped", None, "PRIVATE_BACKEND_ERROR"])
def test_failed_daemon_creation_cannot_advance_to_network_rules(phase):
    from types import SimpleNamespace
    from hypershell.runner.managed import ManagedRunner

    runner = object.__new__(ManagedRunner)
    runner.client = SimpleNamespace(call=lambda *args: {"phase": phase})
    with pytest.raises(RunnerError, match="daemon was not ready") as error:
        runner.require_sandbox_ready("sandbox-id")
    assert "PRIVATE_BACKEND_ERROR" not in str(error.value.details)


def test_backend_contract_probe_excludes_cwd_and_bytecode(monkeypatch):
    from types import SimpleNamespace
    from hypershell.runner.managed import ManagedRunner

    runner = object.__new__(ManagedRunner)
    runner.bin = Path("/runtime/bin")
    monkeypatch.setattr(runner, "require_runtime_bundle", lambda: {})
    monkeypatch.setattr(runner, "engine_environment", lambda: {"PATH": "/usr/bin:/bin"})

    def execute(command, **kwargs):
        assert command[1:4] == ["-I", "-B", "-c"]
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("hypershell.runner.managed.subprocess.run", execute)
    runner.verify_engine_contract()


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux flock")
def test_busy_workspace_reports_actionable_error(tmp_path):
    pytest.importorskip("fcntl")
    from hypershell.runner.managed import ManagedRunner

    runner = object.__new__(ManagedRunner)
    runner.base = tmp_path
    with runner.locked():
        with pytest.raises(RunnerError, match="exit its TUI"):
            with runner.locked():
                pytest.fail("a competing operation acquired the workspace")


def test_engine_identity_accepts_engine_from_a_different_checkout():
    sock = "/var/lib/hypershell-managed/u1/engine.sock"
    # Engine launched from the pinned /opt runtime while the controller runs
    # from a development tree (the hybrid "old bundle + new controller" case).
    for engine_path in (
        b"/opt/hypershell-demo/hypershell/runner/engine.py",
        b"/home/demo/hs-dev/hypershell/runner/engine.py",
    ):
        command = [b"/usr/bin/python", engine_path, b"--listen", b"unix://" + sock.encode()]
        assert engine_command_matches(command, sock)
    # A jiuwenswarm-box server token is also accepted.
    assert engine_command_matches([b"jiuwenbox-server", sock.encode()], sock)


def test_engine_identity_rejects_wrong_socket_or_script():
    sock = "/var/lib/hypershell-managed/u1/engine.sock"
    wrong_socket = [
        b"python",
        b"/opt/hypershell-demo/hypershell/runner/engine.py",
        b"--listen",
        b"unix:///var/lib/hypershell-managed/u2/engine.sock",
    ]
    assert not engine_command_matches(wrong_socket, sock)
    other_script = [
        b"python",
        b"/opt/hypershell-demo/hypershell/runner/terminal.py",
        b"--listen",
        b"unix://" + sock.encode(),
    ]
    assert not engine_command_matches(other_script, sock)
