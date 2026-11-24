"""Long subprocess arguments preserve policy; in-process exec preserves file guards."""

import asyncio
import sys
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tests.intercepts.dll_guard.test_dll_guard_resources import DLL, policy
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file(), reason="Windows DLL required"
)

PYTHON = getattr(sys, "_base_executable", sys.executable)


@pytest.mark.asyncio
@pytest.mark.parametrize("letter,length", [("x", 9000), ("中", 28000)])
@pytest.mark.parametrize("approved", [False, True])
async def test_long_subprocess_arguments_reach_approval_intact(tmp_path, letter, length, approved):
    payload = letter * length
    engine = policy(tmp_path, tools={"bash": "ask"})
    registry, cards = RuntimeApprovalRequests(), []

    async def emit(card):
        resource = card["resource"]
        assert resource["kind"] == "program"
        assert resource["argv"][-1] == payload
        assert Path(resource["cwd"]) == tmp_path
        cards.append(card)
        registry.resolve(
            "long-args", card["request_id"], PermissionConfirmResponse(approved=approved)
        )

    child = "import sys; print('LONG_ARG_OK:' + str(len(sys.argv[1])))"
    code = (
        f"import subprocess,sys; payload={letter!r}*{length}; "
        f"r=subprocess.run([sys.executable,'-c',{child!r},payload],capture_output=True); "
        "sys.stdout.buffer.write(r.stdout); sys.stderr.buffer.write(r.stderr); sys.exit(r.returncode)"
    )
    async with WindowsGuardExecution(
        session_id="long-args",
        tool_call_id="child",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        root_command_approved=True,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            PYTHON,
            "-c",
            code,
            cwd=str(tmp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(process.communicate(), 20)
    assert len(cards) == 1
    assert (process.returncode == 0) is approved, (out, err)
    assert (f"LONG_ARG_OK:{length}".encode() in out) is approved
    if not approved:
        assert b"PermissionError" in err and b"WinError 5" in err


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["read", "write"])
@pytest.mark.parametrize("allowed", [False, True])
async def test_in_process_exec_keeps_actual_file_policy(tmp_path, action, allowed):
    target, script = tmp_path / "target.txt", tmp_path / "script.py"
    target.write_text("ORIGINAL", encoding="utf-8")
    operation = (
        f"Path({str(target)!r}).read_text(encoding='utf-8')"
        if action == "read"
        else f"Path({str(target)!r}).write_text('UPDATED',encoding='utf-8')"
    )
    script.write_text(
        "from pathlib import Path\n" + operation + "\nprint('EXEC_OK')\n", encoding="utf-8"
    )
    engine = policy(tmp_path, paths=[{"path": str(target), action: "allow" if allowed else "deny"}])

    async def unexpected(card):
        raise AssertionError(f"Explicit ALLOW/DENY must not ask: {card}")

    code = (
        f"from pathlib import Path; p=Path({str(script)!r}); "
        "exec(compile(p.read_text(encoding='utf-8'),str(p),'exec'),"
        "{'__name__':'__main__','__file__':str(p)})"
    )
    async with WindowsGuardExecution(
        session_id="exec-files",
        tool_call_id="exec",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        root_command_approved=True,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            PYTHON,
            "-c",
            code,
            cwd=str(tmp_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(process.communicate(), 20)
    assert (process.returncode == 0) is allowed, (out, err)
    assert (b"EXEC_OK" in out) is allowed
    assert target.read_text(encoding="utf-8") == (
        "UPDATED" if allowed and action == "write" else "ORIGINAL"
    )
    if not allowed:
        assert b"PermissionError" in err
