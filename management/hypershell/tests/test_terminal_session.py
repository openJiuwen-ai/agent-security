"""A TUI workload must be a backend job; the host only relays terminal bytes."""

import hashlib
import json
from pathlib import PurePosixPath
from types import SimpleNamespace
import os
import sys

import pytest

from hypershell.runner.client import RunnerError
from hypershell.runner import terminal_session as terminal


@pytest.fixture
def site(monkeypatch):
    site = SimpleNamespace(calls=[], audits=[], launches=[], running=False, ready=True)
    runner = SimpleNamespace(
        bin=PurePosixPath("/runtime/bin"),
        user_id="u1",
        config=SimpleNamespace(users={"u1": SimpleNamespace(run_as_user="hs-u1", run_as_group="hs-u1")}),
    )

    def record_audit(event, **details):
        site.audits.append((event, details))

    runner.audit = record_audit

    def call(method, path, body=None, **options):
        site.calls.append((method, path, body))
        if path.endswith("/exec_background"):
            site.token = body["stdin"].rstrip("\n")
            site.job = body["job_id"]
            return {"started": True, "job_id": site.job}
        if path.endswith("/exec"):
            ready = {
                "version": 1,
                "port": 12345,
                "token_digest": hashlib.sha256(site.token.encode("ascii")).hexdigest(),
            }
            if not site.ready:
                ready["token_digest"] = "wrong"
            return {"exit_code": 0, "stdout": json.dumps(ready)}
        if method == "GET":
            return {"running": site.running}
        if path.endswith("/kill"):
            site.running = False
            return {"killed": True}
        raise AssertionError("unexpected API call")

    runner.client = SimpleNamespace(call=call)
    site.runner = runner
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=2001)))
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=2001)))

    def captured(argv, **options):
        credential = os.read(options["pass_fds"][0], 65).decode("ascii")
        assert credential == site.token
        assert site.token not in repr(argv)
        site.launches.append((argv, options))
        return SimpleNamespace(returncode=0, stdout="measured", stderr="")

    monkeypatch.setattr(terminal.subprocess, "run", captured)
    return site


def test_terminal_starts_backend_workload_and_drops_host_relay_identity(site, monkeypatch):
    monkeypatch.setenv("PRIVATE_SECRET", "must-not-inherit")
    result = terminal.run_terminal_session(
        site.runner, {"sandbox_id": "sandbox-u1"}, ["/runtime/bin/jiuwenswarm-tui"], capture=True, timeout=10
    )
    assert result == {"exit_code": 0, "stdout": "measured", "stderr": ""}
    method, path, start = site.calls[0]
    assert method == "POST" and path.endswith("/sandbox-u1/exec_background")
    assert start["command"][:4] == ["/runtime/bin/python", "-I", "-S", "-c"]
    assert site.token not in repr(start["command"])
    assert start["stdin"] == site.token + "\n"
    assert start["workdir"] == "/workspace"
    argv, options = site.launches[0]
    assert argv[:11] == [
        "/usr/sbin/ip",
        "netns",
        "exec",
        "jbx-sandbox-u1",
        "setpriv",
        "--reuid",
        "2001",
        "--regid",
        "2001",
        "--clear-groups",
        "--no-new-privs",
    ]
    assert "/runtime/bin/jiuwenswarm-tui" not in argv
    assert "PRIVATE_SECRET" not in options["env"]
    assert options["stdin"] == terminal.subprocess.DEVNULL


def test_interactive_terminal_is_required_before_creating_background_job(site, monkeypatch):
    monkeypatch.setattr(terminal.os, "isatty", lambda _: False)
    with pytest.raises(RunnerError, match="requires a terminal"):
        terminal.run_terminal_session(site.runner, {"sandbox_id": "s"}, ["/bin/true"], capture=False)
    assert site.calls == []


def test_invalid_ready_record_never_launches_host_relay(site):
    site.ready = False
    with pytest.raises(RunnerError, match="not authenticated"):
        terminal.run_terminal_session(site.runner, {"sandbox_id": "s"}, ["/bin/true"], capture=True)
    assert site.launches == []


def test_running_broker_gets_only_its_own_term_request(site):
    site.running = True
    terminal.run_terminal_session(site.runner, {"sandbox_id": "s"}, ["/bin/true"], capture=True)
    killed = [(path, body) for method, path, body in site.calls if path.endswith("/kill")]
    assert killed == [(f"/api/v1/sandboxes/s/background/{site.job}/kill", {"signal": 15})]


def test_unknown_broker_status_is_cleanup_error(site, monkeypatch):
    original = site.runner.client.call

    def status(method, path, body=None, **options):
        if method == "GET":
            return {}
        return original(method, path, body, **options)

    site.runner.client.call = status
    with pytest.raises(RunnerError, match="cleanup could not be confirmed"):
        terminal.run_terminal_session(site.runner, {"sandbox_id": "s"}, ["/bin/true"], capture=True)
    assert site.audits[0][0] == "TUI_CLEANUP_REQUIRED"


@pytest.mark.parametrize("uid,gid", [(0, 2001), (2001, 0)])
def test_relay_refuses_root_workload_alias(site, monkeypatch, uid, gid):
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace(getpwnam=lambda _: SimpleNamespace(pw_uid=uid)))
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace(getgrnam=lambda _: SimpleNamespace(gr_gid=gid)))
    with pytest.raises(RunnerError, match="non-root"):
        terminal.run_terminal_session(site.runner, {"sandbox_id": "s"}, ["/bin/true"], capture=True)
    assert site.launches == []


@pytest.mark.parametrize("sid", ["../s", "s;command", "", None])
def test_namespace_name_cannot_escape_selected_sandbox(site, sid):
    with pytest.raises(RunnerError, match="invalid sandbox identity"):
        terminal.run_terminal_session(site.runner, {"sandbox_id": sid}, ["/bin/true"], capture=True)
    assert site.calls == []
    assert site.launches == []
