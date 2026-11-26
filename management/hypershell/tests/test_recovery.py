"""Fail-closed recovery, durable state backups and PID-reuse regressions."""

from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
import sys

import pytest

from hypershell.cli import main
from hypershell.runner.client import RunnerError
from hypershell.runner.managed import ManagedRunner
from hypershell.runner import recovery

CURRENT = "11111111-1111-4111-8111-111111111111"
PREVIOUS = "22222222-2222-4222-8222-222222222222"


@pytest.fixture
def folder():
    path = Path(__file__).resolve().parents[1] / ".test-tmp" / ("recovery-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


@pytest.fixture
def runner(folder, monkeypatch):
    value = object.__new__(ManagedRunner)
    value.base, value.user_id = folder, "u1"
    value.locked = nullcontext
    monkeypatch.setattr("hypershell.runner.managed.host_network_locked", nullcontext)
    monkeypatch.setattr("hypershell.runner.managed.assert_no_residuals", lambda *args: None)
    monkeypatch.setattr(recovery, "boot_id", lambda: CURRENT)
    if sys.platform != "linux":
        monkeypatch.setattr("hypershell.runner.managed.sync_directory", lambda path: None)
    monkeypatch.setattr("hypershell.runner.managed.os.getuid", lambda: 0, raising=False)
    monkeypatch.setattr(value, "_engine_alive", Mock(return_value=False))
    value.save(
        {
            "user_id": "u1",
            "phase": "RUNNING",
            "boot_id": PREVIOUS,
            "sandbox_id": "old-id",
            "engine_pid": 123,
            "app_job_id": "job",
        }
    )
    return value


def test_lost_status_is_read_only_and_does_not_query_stale_socket(runner):
    original = (runner.base / "instance.json").read_bytes()
    result = runner.status()
    assert result["phase"] == "LOST"
    assert result["recorded_phase"] == "RUNNING"
    assert (runner.base / "instance.json").read_bytes() == original


def test_engine_query_failure_is_error_not_running(runner, monkeypatch):
    monkeypatch.setattr(runner, "_engine_alive", Mock(return_value=True))

    def fail(*args, **kwargs):
        assert kwargs["timeout"] == 3
        raise RunnerError("transport failure")

    runner.client = SimpleNamespace(call=fail)
    assert runner.status()["phase"] == "ERROR"


def test_recovery_preserves_backup_and_other_users_and_is_idempotent(runner):
    original = (runner.base / "instance.json").read_bytes()
    other = runner.base / "other-user.json"
    other.write_text("other user remains unchanged")
    result = runner.recover()
    assert result["phase"] == "STOPPED" and result["recovered"]
    assert (runner.base / result["recovery"]["backup"]).read_bytes() == original
    assert other.read_text() == "other user remains unchanged"
    assert not runner.recover()["recovered"]
    assert len(list(runner.base.glob("recovery-*.json"))) == 1
    events = [json.loads(line)["event"] for line in (runner.base / "audit.jsonl").read_text().splitlines()]
    assert events == ["RECOVERY_PREPARED", "RECOVERY_COMPLETED"]


def test_same_boot_recovery_refuses_even_when_engine_pid_is_gone(runner):
    state = runner.read_state()
    state["boot_id"] = CURRENT
    runner.save(state)
    with pytest.raises(RunnerError, match="same-boot"):
        runner.recover()
    with pytest.raises(RunnerError, match="same-boot"):
        runner.recover(legacy_after_reboot=True)
    assert runner.read_state()["phase"] == "RUNNING"


def test_residuals_or_live_engine_never_clear_state(runner, monkeypatch):
    engine_alive = Mock(return_value=True)
    monkeypatch.setattr(runner, "_engine_alive", engine_alive)
    with pytest.raises(RunnerError, match="alive"):
        runner.recover()
    engine_alive.return_value = False

    def fail(*args):
        raise RunnerError("namespace remains")

    monkeypatch.setattr("hypershell.runner.managed.assert_no_residuals", fail)
    with pytest.raises(RunnerError, match="namespace remains"):
        runner.recover()
    assert runner.read_state()["phase"] == "RUNNING"
    assert not list(runner.base.glob("recovery-*.json"))


def test_interruption_before_state_commit_can_be_retried(runner, monkeypatch):
    original_save = runner.save

    def fail(*args):
        raise OSError("interrupted state write")

    monkeypatch.setattr(runner, "save", fail)
    with pytest.raises(OSError):
        runner.recover()
    assert runner.read_state()["phase"] == "RUNNING"
    assert len(list(runner.base.glob("recovery-*.json"))) == 1
    monkeypatch.setattr(runner, "save", original_save)
    assert runner.recover()["phase"] == "STOPPED"


def test_backup_failure_never_commits_stopped_state(runner, monkeypatch):
    def fail(*args, **kwargs):
        raise OSError("backup storage unavailable")

    monkeypatch.setattr("hypershell.runner.managed.durable_write", fail)
    with pytest.raises(OSError, match="backup storage"):
        runner.recover()
    assert runner.read_state()["phase"] == "RUNNING"


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux flock and AF_UNIX")
def test_recovery_uses_workspace_lock_and_removes_only_stale_socket(runner):
    import socket

    runner.locked = ManagedRunner.locked.__get__(runner)
    with runner.locked():
        with pytest.raises(RunnerError, match="workspace is busy"):
            runner.recover()
    endpoint = runner.base / "engine.sock"
    # Linux Unix socket paths must fit sockaddr_un, so use the short VM temp path.
    endpoint = Path("/tmp") / ("hs-test-" + uuid4().hex + ".sock")
    peer = socket.socket(socket.AF_UNIX)
    try:
        peer.bind(str(endpoint))
        peer.close()
        endpoint.rename(runner.base / "engine.sock")
        assert runner.recover()["recovered"]
        assert not (runner.base / "engine.sock").exists()
    finally:
        peer.close()
        endpoint.unlink(missing_ok=True)


def test_legacy_requires_confirmation_and_unchanged_preboot_state(monkeypatch):
    monkeypatch.setattr(recovery, "boot_id", lambda: CURRENT)
    original = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda path, *a, **kw: (
            "btime 100\n" if str(path).replace("\\", "/") == "/proc/stat" else original(path, *a, **kw)
        ),
    )
    old = SimpleNamespace(stat=lambda: SimpleNamespace(st_mtime=98, st_ctime=99))
    with pytest.raises(RunnerError, match="legacy state"):
        recovery.reboot_evidence({}, old)
    assert recovery.reboot_evidence({}, old, legacy_after_reboot=True)["boot_time"] == 100
    recent = SimpleNamespace(stat=lambda: SimpleNamespace(st_mtime=98, st_ctime=101))
    with pytest.raises(RunnerError, match="changed during this boot"):
        recovery.reboot_evidence({}, recent, legacy_after_reboot=True)


@pytest.mark.parametrize("residual", ["namespace", "interface", "cgroup", "process", "socket", "fake_socket"])
def test_each_residual_blocks_recovery(folder, residual):
    proc, netns, cgroup, interfaces = [folder / name for name in ("proc", "netns", "cgroup", "net")]
    for path in (proc / "net", netns, cgroup, interfaces):
        path.mkdir(parents=True, exist_ok=True)
    (proc / "net/unix").write_text("header\n")
    base = folder / "workspace"
    base.mkdir()
    sid = "old-id"
    if residual == "namespace":
        (netns / ("jbx-" + sid)).touch()
    elif residual == "interface":
        (interfaces / ("jwbH" + hashlib.sha256(sid.encode()).hexdigest()[:8])).mkdir()
    elif residual == "cgroup":
        (cgroup / "jiuwenbox" / sid).mkdir(parents=True)
    elif residual == "process":
        (proc / "456").mkdir()
        (proc / "456/cmdline").write_bytes(b"python\0--listen\0" + str(base / "engine.sock").encode())
    elif residual == "socket":
        (proc / "net/unix").write_text("header\n000: 2 0 10000 1 01 123 " + str(base / "engine.sock") + "\n")
    else:
        (base / "engine.sock").touch()
    with pytest.raises(RunnerError, match="recovery refused"):
        recovery.assert_no_residuals(
            base, {"sandbox_id": sid}, proc=proc, netns=netns, cgroup=cgroup, interfaces=interfaces
        )


def test_engine_identity_checks_boot_and_process_start_before_command(runner, monkeypatch):
    monkeypatch.delattr(runner, "_engine_alive")
    monkeypatch.setattr("hypershell.runner.managed.boot_id", lambda: CURRENT)
    monkeypatch.setattr("hypershell.runner.managed.process_start_ticks", lambda pid: 99)
    state = runner.read_state()
    read_command = Mock(side_effect=AssertionError("process identity must be checked before reading argv"))
    monkeypatch.setattr(Path, "read_bytes", read_command)
    assert runner.status()["reason"] == "ENGINE_IDENTITY_MISSING"
    runner.save({**state, "boot_id": CURRENT, "engine_start_ticks": 98})
    assert runner.status()["reason"] == "ENGINE_IDENTITY_MISSING"
    read_command.assert_not_called()


def test_proc_stat_parses_parentheses_in_process_name(monkeypatch):
    monkeypatch.setattr(
        Path, "read_text", lambda path: "123 (a ) tricky name) " + " ".join(["S"] + ["0"] * 18 + ["987"])
    )
    assert recovery.process_start_ticks(123) == 987


def test_status_cli_reports_unhealthy_exit(monkeypatch, capsys):
    monkeypatch.setattr("hypershell.runner.managed.require_admin", lambda: None)
    monkeypatch.setattr("hypershell.runner.managed.trusted", lambda path: path)
    monkeypatch.setattr("hypershell.config.AdminConfig.load", lambda path: None)
    monkeypatch.setattr(
        "hypershell.runner.managed.ManagedRunner", lambda *a: SimpleNamespace(status=lambda: {"phase": "LOST"})
    )
    assert main(["status"]) == 1
    assert json.loads(capsys.readouterr().out)["ok"] is False
