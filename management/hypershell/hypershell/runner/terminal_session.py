"""Orchestrate a policy-bound PTY job and a fixed unprivileged host relay."""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import re
import secrets
import subprocess
import sys
import time
import uuid

from .client import RunnerError
from .terminal_broker import build_broker_command
from .terminal_relay import build_relay_command

_READ_READY = r"""
import json,os,stat,sys
try:
 fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
 with os.fdopen(fd,'rb') as f:
  info=os.fstat(f.fileno())
  if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or info.st_nlink!=1 or info.st_mode&0o077:
   raise ValueError('unsafe readiness record')
  data=f.read(4097)
  if len(data)>4096:raise ValueError('oversized readiness record')
  print(json.dumps(json.loads(data) if data else None))
except FileNotFoundError:
 print('null')
"""


def _terminal_environment():
    term = os.environ.get("TERM", "xterm-256color")
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", term):
        term = "xterm-256color"
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "TERM": term}


def _relay_argv(runner, sid, port, descriptor, capture, timeout):
    import pwd
    import grp

    profile = runner.config.users[runner.user_id]
    uid = pwd.getpwnam(profile.run_as_user).pw_uid
    gid = grp.getgrnam(profile.run_as_group).gr_gid
    if uid <= 0 or gid <= 0:
        raise RunnerError("terminal relay requires a non-root workload identity")
    return [
        "/usr/sbin/ip",
        "netns",
        "exec",
        "jbx-" + sid,
        "setpriv",
        "--reuid",
        str(uid),
        "--regid",
        str(gid),
        "--clear-groups",
        "--no-new-privs",
        *build_relay_command(sys.executable, port=port, token_fd=descriptor, capture=capture, timeout_seconds=timeout),
    ]


def _finish_job(runner, endpoint):
    """TERM lets the broker kill/reap its PTY group before it exits.

    Never equate killing only the broker with terminating all descendants.
    A broker which cannot confirm normal shutdown is an explicit cleanup error.
    """
    state = runner.client.call("GET", endpoint, timeout=4)
    if not isinstance(state.get("running"), bool):
        raise RunnerError("terminal broker status is unavailable")
    if state["running"] is False:
        return
    runner.client.call("POST", f"{endpoint}/kill", {"signal": 15}, timeout=4)
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        state = runner.client.call("GET", endpoint, timeout=4)
        if not isinstance(state.get("running"), bool):
            raise RunnerError("terminal broker status is unavailable")
        if state["running"] is False:
            return
        time.sleep(0.1)
    raise RunnerError("terminal broker cleanup was not confirmed; inspect workspace before retrying")


def run_terminal_session(runner, state, command, *, capture, timeout=7200):
    """Called with the workspace lock held, for both production and probes."""
    if not capture and (not os.isatty(0) or not os.isatty(1)):
        raise RunnerError("interactive TUI requires a terminal; no host fallback")
    if type(timeout) is not int or not 1 <= timeout <= 86400:
        raise RunnerError("invalid terminal session timeout")
    sid = state.get("sandbox_id")
    if not isinstance(sid, str) or not re.fullmatch(r"[A-Za-z0-9-]{1,64}", sid):
        raise RunnerError("invalid sandbox identity for terminal relay")
    session = uuid.uuid4().hex
    # JiuwenBox limits custom IDs; preserve the full 128 random bits within
    # its 32-character lowercase identifier contract.
    job_id = session
    ready_path = posixpath.join("/home/agent", f".hs-terminal-{session}.json")
    token = secrets.token_hex(32)
    environment = _terminal_environment()
    try:
        columns, rows = os.get_terminal_size(0)
    except OSError:
        columns, rows = 80, 24
    spec = {
        "token": token,
        "command": list(command),
        "ready_path": ready_path,
        "rows": max(1, min(rows, 500)),
        "columns": max(1, min(columns, 1000)),
        "timeout_seconds": min(86400, timeout + 15),
        "idle_timeout_seconds": min(300, timeout + 10),
    }
    broker = build_broker_command(runner.bin / "python", spec)
    endpoint = f"/api/v1/sandboxes/{sid}/background/{job_id}"
    submitted = False
    credential_fd = None
    try:
        submitted = True
        started = runner.client.call(
            "POST",
            f"/api/v1/sandboxes/{sid}/exec_background",
            {
                "job_id": job_id,
                "command": broker,
                "workdir": "/workspace",
                "env": {"TERM": environment["TERM"]},
                "stdin": token + "\n",
            },
            timeout=15,
        )
        if started.get("job_id") != job_id or started.get("started", True) is not True:
            raise RunnerError("policy-bound terminal broker did not start")
        deadline = time.monotonic() + 10
        ready = None
        while time.monotonic() < deadline:
            result = runner.client.call(
                "POST",
                f"/api/v1/sandboxes/{sid}/exec",
                {
                    "command": [str(runner.bin / "python"), "-I", "-S", "-c", _READ_READY, ready_path],
                    "workdir": "/workspace",
                    "timeout_seconds": 2,
                },
                timeout=4,
            )
            if result.get("exit_code") != 0:
                raise RunnerError("terminal readiness probe failed")
            try:
                ready = json.loads(result["stdout"])
            except (KeyError, TypeError, ValueError) as exc:
                raise RunnerError("invalid terminal readiness response") from exc
            if ready is not None:
                break
            if runner.client.call("GET", endpoint, timeout=4).get("running") is not True:
                raise RunnerError("terminal broker exited before readiness")
            time.sleep(0.05)
        if not isinstance(ready, dict) or ready.get("version") != 1:
            raise RunnerError("terminal broker readiness was not authenticated")
        port = ready.get("port")
        token_digest = hashlib.sha256(token.encode("ascii")).hexdigest()
        if type(port) is not int or not 1 <= port <= 65535 or ready.get("token_digest") != token_digest:
            raise RunnerError("terminal broker readiness was not authenticated")
        credential_fd, writer = os.pipe()
        try:
            os.write(writer, token.encode("ascii"))
        finally:
            os.close(writer)
        argv = _relay_argv(runner, sid, port, credential_fd, capture, timeout)
        # The token is only in the backend stdin and this inherited pipe. It is
        # absent from job argv, environment, ready files and audit records.
        if capture:
            completed = subprocess.run(
                argv,
                env=environment,
                pass_fds=(credential_fd,),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout + 8,
            )
            return {"exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
        return {"exit_code": subprocess.call(argv, env=environment, pass_fds=(credential_fd,))}
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RunnerError("policy-bound terminal transport failed; no host fallback") from exc
    finally:
        if credential_fd is not None:
            os.close(credential_fd)
        if submitted:
            try:
                _finish_job(runner, endpoint)
            except Exception as exc:
                runner.audit("TUI_CLEANUP_REQUIRED", job_id=job_id)
                raise RunnerError("terminal cleanup could not be confirmed; inspect the workspace") from exc
