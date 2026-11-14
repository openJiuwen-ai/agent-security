# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Real shell children: file decisions, immutable execution and venv arguments."""

import asyncio
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tool_permission import runtime_policy

PermissionEngine = runtime_policy.engine.PermissionEngine
DLL = guard_binary_directory() / "jiuwen_runtime_guard.dll"
pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file(), reason="Windows DLL required"
)


async def _run_shell(guard, command, shell, cwd):
    plan, use_shell, _ = runtime_policy.shell.resolve_execution_plan(
        command, runtime_policy.shell.ShellType(shell)
    )
    assert not use_shell and isinstance(plan, list)
    process = await guard.launch(
        asyncio.create_subprocess_exec,
        *plan,
        cwd=str(cwd),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
    return subprocess.CompletedProcess(
        plan,
        process.returncode,
        stdout.decode("utf-8", errors="backslashreplace"),
        stderr.decode("utf-8", errors="backslashreplace"),
    )


@pytest.mark.asyncio
async def test_concurrent_file_checks_wait_for_pipe_without_waiving_denies(tmp_path, monkeypatch):
    allowed, denied = tmp_path / "allowed.txt", tmp_path / "denied.txt"
    allowed.write_text("PUBLIC", encoding="utf-8")
    denied.write_text("PRIVATE", encoding="utf-8")
    script = tmp_path / "parallel_reads.py"
    script.write_text(
        "from concurrent.futures import ThreadPoolExecutor\n"
        "from pathlib import Path\nimport sys, threading\n"
        "allowed, denied = map(Path, sys.argv[1:])\n"
        "barrier = threading.Barrier(32)\n"
        "def worker(_):\n"
        "    barrier.wait()\n"
        "    for _ in range(8):\n"
        "        assert allowed.read_text() == 'PUBLIC'\n"
        "    try:\n"
        "        denied.read_text()\n"
        "    except PermissionError:\n"
        "        return True\n"
        "    raise AssertionError('Explicit deny was bypassed')\n"
        "with ThreadPoolExecutor(max_workers=32) as pool:\n"
        "    assert all(pool.map(worker, range(32)))\n"
        "print('CONCURRENT_OK')\n",
        encoding="utf-8",
    )
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{"path": str(denied), "read": "deny"}],
            },
        },
        workspace_root=tmp_path,
    )

    async def unexpected(card):
        raise AssertionError(card)

    async with WindowsGuardExecution(
        session_id="concurrent",
        tool_call_id="file-checks",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        source_tool="bash",
    ) as guard:
        decisions = _record_runtime_denials(monkeypatch, guard)
        process = await guard.launch(
            asyncio.create_subprocess_exec,
            sys.executable,
            str(script),
            str(allowed),
            str(denied),
            cwd=str(tmp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 20)
    assert process.returncode == 0 and b"CONCURRENT_OK" in stdout, (stdout, stderr)
    assert not stderr
    assert len(decisions) == 32
    assert all(
        subject["kind"] == "file" and (str(denied), "read") in subject["accesses"]
        for subject, _ in decisions
    ), decisions
    assert denied.read_text() == "PRIVATE"


def _python_script_command(shell, python, script, *arguments):
    """Quote literal argv and preserve the Python child's exit code in either shell."""
    if shell == "powershell":

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        # Literal operands isolate runtime checks from dynamic-shell checks.
        return (
            f"& {quote(python)} {quote(script)} "
            + " ".join(quote(argument) for argument in arguments)
            + "; exit $LASTEXITCODE"
        )
    return shlex.join(
        [
            Path(python).as_posix(),
            script.as_posix(),
            *(
                argument.as_posix() if isinstance(argument, Path) else argument
                for argument in arguments
            ),
        ]
    )


def _record_runtime_denials(monkeypatch, guard):
    """Observe the real decision, without replacing policy or native hooks."""
    denials = []
    evaluate = getattr(guard, "_evaluate_resource")

    async def record(engine, subject):
        result = await evaluate(engine, subject)
        if result.is_denied:
            denials.append((subject, result))
        return result

    monkeypatch.setattr(guard, "_evaluate_resource", record)
    return denials


@pytest.mark.asyncio
@pytest.mark.parametrize("shell", ["powershell", "bash"])
@pytest.mark.parametrize("directory", ["skills", "config"])
@pytest.mark.parametrize("action", ["read", "write"])
@pytest.mark.parametrize("decision", ["allow", "deny"])
async def test_real_child_data_path_uses_file_policy(
    tmp_path, monkeypatch, shell, directory, action, decision
):

    data = tmp_path / directory
    data.mkdir()
    # Directory names alone do not make data immutable. Keep the executable
    # separate so an exec rejection cannot impersonate a read/write denial.
    script, target = tmp_path / "script.py", data / "data.txt"
    target.write_text("ORIGINAL", encoding="utf-8")
    script.write_text(
        "from pathlib import Path\nimport sys\np=Path(sys.argv[1])\n"
        + "print('CHILD_STARTED', flush=True)\ntry:\n"
        + ("    print(p.read_text())\n" if action == "read" else "    p.write_text('UPDATED')\n")
        + "except PermissionError:\n    print('FILE_DENIED', flush=True)\n    sys.exit(23)\n"
        + "print('CHILD_OK')\n",
        encoding="utf-8",
    )
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {shell: "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{"path": str(target), action: decision}],
            },
        },
        workspace_root=tmp_path,
    )
    expected = decision == "allow"
    file_policy = engine.check_file_accesses([(target, action)])
    assert file_policy.permission.value == decision
    assert engine.check_file_accesses([(script, "exec")]).is_allowed

    async def unexpected(event):
        raise AssertionError(f"No approval expected: {event}")

    command = _python_script_command(shell, sys.executable, script, target)
    async with WindowsGuardExecution(
        session_id="control",
        tool_call_id="child",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        root_command_approved=True,
        source_tool=shell,
        source_shell=shell,
    ) as guard:
        denials = _record_runtime_denials(monkeypatch, guard)
        result = await _run_shell(guard, command, shell, tmp_path)
    assert "CHILD_STARTED" in result.stdout, (result, denials)
    assert result.returncode == (0 if expected else 23), result
    assert ("CHILD_OK" in result.stdout) is expected, result
    assert ("FILE_DENIED" in result.stdout) is (not expected), result
    assert not result.stderr, result
    if expected:
        assert not denials, denials
        if action == "read":
            assert "ORIGINAL" in result.stdout, result
    else:
        assert any(
            subject["kind"] == "file"
            and any(
                Path(path) == target and access == action for path, access in subject["accesses"]
            )
            and denied.matched_rule == file_policy.matched_rule
            for subject, denied in denials
        ), denials
    assert target.read_text() == ("UPDATED" if action == "write" and expected else "ORIGINAL")


@pytest.mark.asyncio
@pytest.mark.parametrize("shell", ["powershell", "bash"])
@pytest.mark.parametrize("directory", ["skills", "config"])
@pytest.mark.parametrize("protected", [False, True])
async def test_real_immutable_directory_script_execution(
    tmp_path, monkeypatch, shell, directory, protected
):

    control = tmp_path / directory
    control.mkdir()
    script = (control if protected else tmp_path) / "script.py"
    marker = tmp_path / "started.txt"
    script.write_text(
        "from pathlib import Path\nimport sys\n"
        "Path(sys.argv[1]).write_text('STARTED')\nprint('CHILD_STARTED')\n",
        encoding="utf-8",
    )
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {shell: "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        },
        workspace_root=tmp_path,
        immutable_control_roots=[control],
    )

    async def unexpected(event):
        raise AssertionError(f"No approval expected: {event}")

    command = _python_script_command(shell, sys.executable, script, marker)
    async with WindowsGuardExecution(
        session_id="immutable",
        tool_call_id="script",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        root_command_approved=True,
        source_tool=shell,
        source_shell=shell,
    ) as guard:
        denials = _record_runtime_denials(monkeypatch, guard)
        result = await _run_shell(guard, command, shell, tmp_path)
    if protected:
        # Shells report startup rejection differently. Require the actual rule
        # and protected script identity, rather than accepting any failed launch.
        assert result.returncode != 0, result
        assert not marker.exists() and "CHILD_STARTED" not in result.stdout, result
        assert any(
            subject["kind"] == "program"
            and denied.matched_rule == "immutable_control_plane"
            and any(Path(reported) == script for reported in (denied.external_paths or []))
            for subject, denied in denials
        ), denials
    else:
        assert result.returncode == 0, result
        assert marker.read_text() == "STARTED" and "CHILD_STARTED" in result.stdout, result
        assert not result.stderr and not denials, (result, denials)


@pytest.mark.asyncio
@pytest.mark.parametrize("shell", ["powershell", "bash"])
async def test_real_managed_python_skill_args_are_preserved(tmp_path, shell):
    import venv

    venv.create(tmp_path / "managed", with_pip=False)
    python = tmp_path / "managed/Scripts/python.exe"
    skills = tmp_path / "skills"
    skills.mkdir()
    script = skills / "session_state.py"
    script.write_text(
        "import json, sys\nprint('SKILL_STATE=' + json.dumps({'args': sys.argv[1:], "
        "'executable': sys.executable, 'prefix': sys.prefix}))\n",
        encoding="utf-8",
    )
    # This test verifies the venv launcher and arguments, independently of the
    # immutable execution boundary tested above.
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {shell: "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        },
        workspace_root=tmp_path,
    )

    async def unexpected(event):
        raise AssertionError(f"No approval expected: {event}")

    command = _python_script_command(shell, python, script, "init")
    async with WindowsGuardExecution(
        session_id="managed",
        tool_call_id="skill",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        root_command_approved=True,
        source_tool=shell,
        source_shell=shell,
    ) as guard:
        result = await _run_shell(guard, command, shell, tmp_path)
    assert result.returncode == 0, result
    assert not result.stderr, result
    states = [
        json.loads(line.removeprefix("SKILL_STATE="))
        for line in result.stdout.splitlines()
        if line.startswith("SKILL_STATE=")
    ]
    assert len(states) == 1, result
    assert states[0]["args"] == ["init"], states
    assert Path(states[0]["executable"]).resolve() == python.resolve(), states
    assert Path(states[0]["prefix"]).resolve() == (tmp_path / "managed").resolve(), states
