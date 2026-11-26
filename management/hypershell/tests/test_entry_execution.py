"""Entry probes must traverse the same execution paths as real chat and TUI.

These tests verify routing and fail-closed behavior, not kernel isolation.
The latter requires the live Linux probe and its recorded evidence.
"""

from contextlib import contextmanager
from pathlib import PurePosixPath
import sys
from types import SimpleNamespace

import pytest

from hypershell.runner.client import RunnerError
import hypershell.runner.managed as managed


@pytest.fixture
def entry_site(monkeypatch):
    runner = object.__new__(managed.ManagedRunner)
    runner.bin = PurePosixPath("/runtime/bin")
    runner.user_id = "u1"
    runner.config = SimpleNamespace(users={"u1": SimpleNamespace(run_as_user="hs-u1", run_as_group="hs-u1")})
    site = SimpleNamespace(
        runner=runner,
        locked=False,
        calls=[],
        events=[],
        state={"phase": "RUNNING", "sandbox_id": "sandbox-u1", "observed_sandbox": {"pid": 100}},
    )

    @contextmanager
    def locked():
        assert not site.locked, "execution must not recursively acquire its workspace lock"
        site.locked = True
        try:
            yield
        finally:
            site.locked = False

    def status():
        assert site.locked
        return site.state

    def execute(sid, command, **kwargs):
        assert site.locked
        site.calls.append((sid, command, kwargs))
        return {"exit_code": 0, "stdout": "probe-output", "stderr": ""}

    def audit(event, **details):
        if event in {"CHAT_COMPLETED", "TUI_ATTACH_REQUESTED"}:
            assert site.locked, "attach/chat audit must refer to the locked instance"
        site.events.append((event, details))

    @contextmanager
    def session_lease(kind):
        # Lease registry/liveness is covered by test_sessions.py; here we only
        # verify that the PTY itself runs under a lease, not the op lock.
        yield "session-id"

    runner.locked, runner.status, runner.audit = locked, status, audit
    runner.session_lease = session_lease
    runner.client = SimpleNamespace(execute=execute)
    monkeypatch.setattr(managed, "require_admin", lambda: None)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=2001)))
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda name: SimpleNamespace(gr_gid=2001)))
    return site


def test_chat_and_probe_use_the_same_locked_backend_execution(entry_site):
    site = entry_site
    assert site.runner.chat("hello", "session-u1")["stdout"] == "probe-output"
    sid, command, options = site.calls[0]
    assert sid == "sandbox-u1"
    assert command == [
        "/runtime/bin/jiuwenswarm",
        "chat",
        "--gateway-url",
        "ws://127.0.0.1:19001/tui",
        "--session",
        "session-u1",
        "--json",
        "--timeout",
        "90",
        "hello",
    ]
    assert options == {"timeout": 110, "workdir": "/workspace"}
    assert site.events == [("CHAT_COMPLETED", {"sandbox_id": sid, "exit_code": 0})]
    probe = ["/runtime/bin/python", "-c", "print('probe')"]
    assert site.runner.run_probe("chat", probe, timeout=12)["exit_code"] == 0
    assert site.calls[1] == (sid, probe, {"timeout": 12, "workdir": "/workspace"})
    assert len(site.events) == 1  # Fixed probes are not reported as user chats.


def test_exec_in_workspace_preserves_workdir_and_timeout(entry_site):
    entry_site.runner.exec_in_workspace(["true"], timeout=7, workdir="/data")
    assert entry_site.calls == [("sandbox-u1", ["true"], {"timeout": 7, "workdir": "/data"})]


def test_tui_and_probe_share_policy_bound_pty_execution(entry_site, monkeypatch):
    site = entry_site
    launches = []

    def terminal(runner, state, command, **kwargs):
        assert runner is site.runner and state is site.state
        launches.append((command, kwargs, site.locked))
        return {"exit_code": 0, "stdout": "measured", "stderr": ""}

    monkeypatch.setattr(managed, "run_terminal_session", terminal)
    assert site.runner.tui() == 0
    probe = ["/runtime/bin/python", "-c", "print('probe')"]
    assert site.runner.run_probe("tui", probe, timeout=8) == {
        "exit_code": 0,
        "stdout": "measured",
        "stderr": "",
    }
    normal, normal_options, normal_locked = launches[0]
    measured, measured_options, measured_locked = launches[1]
    assert normal == ["/runtime/bin/jiuwenswarm-tui", "--url", "ws://127.0.0.1:19001/tui"]
    assert measured == probe
    assert normal_options == {"capture": False}
    assert measured_options == {"capture": True, "timeout": 8}
    assert normal_locked is False  # a TUI session holds a lease, not the op lock
    assert measured_locked is True  # a fixed probe still holds the op lock
    assert site.events == [
        ("TUI_ATTACH_REQUESTED", {"sandbox_id": "sandbox-u1"}),
        ("TUI_EXITED", {"sandbox_id": "sandbox-u1", "exit_code": 0}),
    ]


@pytest.mark.parametrize("entry", ["chat", "tui"])
@pytest.mark.parametrize("phase", ["STOPPED", "LOST", "ERROR"])
def test_probe_refuses_non_running_workspace_without_fallback(entry_site, entry, phase, monkeypatch):
    entry_site.state["phase"] = phase
    monkeypatch.setattr(managed.subprocess, "run", lambda *a, **k: pytest.fail("host execution attempted"))
    with pytest.raises(RunnerError, match="no host fallback"):
        entry_site.runner.run_probe(entry, ["python", "-c", "print('probe')"])
    assert entry_site.calls == []
    assert not entry_site.locked


def test_legacy_host_tui_execution_path_is_removed(entry_site):
    assert not hasattr(entry_site.runner, "_tui_command")


def test_probe_requires_administrator_before_selecting_entry(entry_site, monkeypatch):
    def rejected():
        raise RunnerError("administrator required")

    monkeypatch.setattr(managed, "require_admin", rejected)
    with pytest.raises(RunnerError, match="administrator required"):
        entry_site.runner.run_probe("chat", ["true"])
    assert entry_site.calls == []


def test_unknown_probe_entry_does_not_execute(entry_site):
    with pytest.raises(RunnerError, match="unknown execution entry"):
        entry_site.runner.run_probe("host", ["true"])
    assert entry_site.calls == []


@pytest.mark.parametrize("production", [False, True])
def test_tui_transport_failure_never_falls_back_to_host(entry_site, monkeypatch, production):
    def fail(*args, **kwargs):
        raise RunnerError("policy-bound terminal failed")

    monkeypatch.setattr(managed, "run_terminal_session", fail)
    monkeypatch.setattr(managed.subprocess, "call", lambda *a, **k: pytest.fail("host fallback"))
    with pytest.raises(RunnerError, match="policy-bound terminal failed"):
        if production:
            entry_site.runner.tui()
        else:
            entry_site.runner.run_probe("tui", ["true"], timeout=1)
    assert not entry_site.locked
