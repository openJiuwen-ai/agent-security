"""Session-lease contracts for the P1 web/TUI session model.

These tests exercise the registry, liveness/TTL reclamation and termination
logic without a sandbox, a real PTY, or root. Linux-only primitives (fsync of a
directory, /proc boot/start ticks, signals) are stubbed so the suite also runs
on a developer workstation.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
import signal
import time
from unittest.mock import Mock
import uuid

import pytest

from hypershell.runner import managed
from hypershell.runner.client import RunnerError
from hypershell.runner.managed import ManagedRunner


@pytest.fixture
def session_env(tmp_path, monkeypatch):
    base = tmp_path / "u1"
    base.mkdir()
    state = {"boot": "boot-1", "ticks": {os.getpid(): 1}}

    def fake_ticks(pid):
        ticks = state["ticks"].get(pid)
        if ticks is None:
            raise FileNotFoundError(pid)
        return ticks

    monkeypatch.setattr(managed, "sync_directory", lambda path: None)
    monkeypatch.setattr(managed, "boot_id", lambda: state["boot"])
    monkeypatch.setattr(managed, "process_start_ticks", fake_ticks)

    runner = object.__new__(ManagedRunner)
    runner.base = base
    runner.user_id = "u1"
    runner.audit = Mock()
    return runner, state


def _write_session(runner, *, pid=5000, kind="web", started=None, last_seen=None, boot="boot-1", ticks=1):
    sessions = runner.base / "sessions"
    sessions.mkdir(mode=0o700, exist_ok=True)
    session_id = uuid.uuid4().hex
    now = time.time()
    record = {
        "id": session_id,
        "kind": kind,
        "pid": pid,
        "user_id": "u1",
        "started": now - 10 if started is None else started,
        "last_seen": now if last_seen is None else last_seen,
        "boot_id": boot,
        "start_ticks": ticks,
    }
    (sessions / (session_id + ".json")).write_text(json.dumps(record))
    return session_id


def test_session_lease_registers_and_removes_record(session_env):
    runner, _ = session_env
    sessions = runner.base / "sessions"
    with runner.session_lease("web") as session_id:
        files = list(sessions.glob("*.json"))
        assert len(files) == 1
        record = json.loads(files[0].read_text())
        assert record["id"] == session_id
        assert record["kind"] == "web"
        assert record["pid"] == os.getpid()
        assert record["start_ticks"] == 1
        assert [s["id"] for s in runner.list_sessions()] == [session_id]
    assert list(sessions.glob("*.json")) == []
    assert runner.list_sessions() == []


def test_session_lease_rejects_unknown_kind(session_env):
    runner, _ = session_env
    with pytest.raises(RunnerError):
        with runner.session_lease("chat"):
            pass


def test_list_sessions_reclaims_dead_pid(session_env):
    runner, state = session_env
    state["ticks"].pop(5000, None)  # pid 5000 is not alive
    session_id = _write_session(runner, pid=5000)
    assert runner.list_sessions() == []
    assert not (runner.base / "sessions" / (session_id + ".json")).exists()


def test_list_sessions_reclaims_expired_heartbeat(session_env):
    runner, state = session_env
    state["ticks"][5000] = 1  # alive, but heartbeat is stale
    session_id = _write_session(runner, pid=5000, last_seen=time.time() - (managed.SESSION_TTL_SECONDS + 10))
    assert runner.list_sessions() == []
    assert not (runner.base / "sessions" / (session_id + ".json")).exists()


def test_list_sessions_reclaims_previous_boot(session_env):
    runner, state = session_env
    state["ticks"][5000] = 1
    session_id = _write_session(runner, pid=5000, boot="previous-boot")
    assert runner.list_sessions() == []
    assert not (runner.base / "sessions" / (session_id + ".json")).exists()


def test_list_sessions_returns_live_session(session_env):
    runner, state = session_env
    state["ticks"][5000] = 7
    session_id = _write_session(runner, pid=5000, ticks=7, kind="tui")
    live = runner.list_sessions()
    assert len(live) == 1
    assert live[0]["id"] == session_id
    assert live[0]["kind"] == "tui"
    assert live[0]["pid"] == 5000


def test_terminate_session_signals_pid_and_drops_lease(session_env, monkeypatch):
    runner, state = session_env
    state["ticks"][5000] = 1
    session_id = _write_session(runner, pid=5000)
    killed = []

    def fake_kill(pid, sig):
        killed.append((pid, sig))
        state["ticks"].pop(pid, None)  # simulate the process exiting

    monkeypatch.setattr(managed.os, "kill", fake_kill)
    result = runner.terminate_session(session_id)
    assert result == {"session_id": session_id, "terminated": True}
    assert killed and killed[0] == (5000, signal.SIGTERM)
    assert not (runner.base / "sessions" / (session_id + ".json")).exists()


def test_terminate_session_rejects_bad_id(session_env):
    runner, _ = session_env
    for bad in ("", "short", "z" * 32, None, 123):
        with pytest.raises(RunnerError):
            runner.terminate_session(bad)


def test_terminate_session_missing_record_raises(session_env):
    runner, _ = session_env
    with pytest.raises(RunnerError):
        runner.terminate_session("c" * 32)


def test_revoke_sessions_terminates_all_live(session_env, monkeypatch):
    runner, state = session_env
    state["ticks"][5000] = 1
    state["ticks"][5001] = 1
    first = _write_session(runner, pid=5000)
    second = _write_session(runner, pid=5001, kind="tui")

    def fake_kill(pid, sig):
        state["ticks"].pop(pid, None)

    monkeypatch.setattr(managed.os, "kill", fake_kill)
    assert sorted(runner.revoke_sessions()) == sorted([first, second])
    assert runner.list_sessions() == []


def test_stop_revokes_sessions_before_stopping(session_env, monkeypatch):
    runner, _ = session_env
    events = []

    @contextmanager
    def fake_locked():
        yield

    monkeypatch.setattr(runner, "locked", fake_locked)
    monkeypatch.setattr(runner, "revoke_sessions", lambda: events.append("revoke") or ["x"])
    monkeypatch.setattr(runner, "read_state", lambda: {"phase": "RUNNING", "user_id": "u1"})
    monkeypatch.setattr(runner, "_stop", lambda state: events.append("stop"))
    runner.stop()
    assert events == ["revoke", "stop"]


def test_recover_revokes_sessions_even_when_stopped(session_env, monkeypatch):
    runner, _ = session_env
    events = []

    @contextmanager
    def fake_locked():
        yield

    monkeypatch.setattr(runner, "locked", fake_locked)
    monkeypatch.setattr(runner, "revoke_sessions", lambda: events.append("revoke") or [])
    monkeypatch.setattr(runner, "read_state", lambda: {"phase": "STOPPED", "user_id": "u1"})
    result = runner.recover()
    assert events == ["revoke"]
    assert result["recovered"] is False
