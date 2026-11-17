"""Run explicitly with pytest after building agent-security-dll with -BuildTestClient."""

import asyncio
import platform
import os
import struct
import subprocess
import sys

import pytest

from agent_shield import ProcessGuard
from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.bridge import RuntimeApprovalRequests, WindowsGuardExecution


pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or struct.calcsize("P") != 8
    or platform.machine().lower() not in {"amd64", "x86_64"},
    reason="Requires a Windows x64 host and 64-bit Python",
)


@pytest.fixture
def case(tmp_path):
    allowed, denied = tmp_path / "allowed.txt", tmp_path / "denied.txt"
    events = []

    class Host:
        @staticmethod
        def policy_snapshot():
            return {
                "config": {"enabled": False, "package_builtin_rules": False},
                "revision": 1,
                "workspace_root": str(tmp_path),
                "ruleset": {"spec": "agent-pdp/v1"},
                "unmatched": "allow",
                "tasks": {"task": {"subject_id": "acceptance", "user_rules": [
                    {"id": "probe." + action, "object": "file", "ops": ["write"],
                     "pattern": [str(path)], "action": action}
                    for action, path in (("allow", allowed), ("deny", denied))
                ]}},
            }

        async def confirm(self, request):
            return {"action": "allow_once"}

        @staticmethod
        def audit(event):
            events.append(event)

    return Host(), allowed, denied, events


@pytest.mark.asyncio
@pytest.mark.parametrize("bits,child,parent_bits", [
    (64, False, 64), (64, True, 64), (32, False, 64), (32, True, 64),
    (32, True, 32), (64, True, 32),
], ids=["x64-root", "x64-child", "wow64-root", "wow64-child", "x86-to-x86", "x86-to-x64"])
async def test_process_file_policy(bits, child, parent_bits, tmp_path, case):
    probe = guard_binary_directory() / ("probe.exe" if bits == 64 else "probe_x86.exe")
    if not probe.is_file():
        raise AssertionError(f"Build -BuildTestClient first. Missing {probe}")
    host, allowed, denied, events = case
    argv = [str(probe), "check-file-policy", str(allowed), str(denied)]
    if child and parent_bits == 32:
        parent = os.path.join(os.environ["SystemRoot"], "SysWOW64", "cmd.exe")
        argv = [parent, "/d", "/s", "/c", subprocess.list2cmdline(argv)]
    elif child:
        parent = "import subprocess, sys; sys.exit(subprocess.run(sys.argv[1:]).returncode)"
        argv = [sys.executable, "-I", "-c", parent, *argv]
    async with ProcessGuard(session_id="architecture", host=host) as guard:
        process = await guard.spawn(
            argv, task_id="task", tool_call_id="probe", tool_name="bash", cwd=tmp_path,
            stdio={"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE},
            timeout_s=30,
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), 35)
        if process.returncode != 0:
            raise AssertionError((process.returncode, stdout, stderr))
    assert_file_decisions(case, bits, child, process.pid, process.execution_id, stdout)


def assert_file_decisions(case, bits, child, root_pid, execution_id, stdout):
    _, allowed, denied, events = case
    actual_bits, pid, created = map(int, stdout.split())
    if actual_bits != bits or pid <= 0:
        raise AssertionError((actual_bits, bits, pid))
    if (pid != root_pid) != child:
        raise AssertionError((pid, root_pid, child))
    if not allowed.is_file() or denied.exists():
        raise AssertionError((allowed, denied))
    decisions = set()
    for event in events:
        selected = event.get("kind") == "policy_decision" and event.get("resource_kind") == "file"
        same_process = event.get("pid") == pid and event.get("process_instance_id") == f"{pid}:{created}"
        same_call = (
            event.get("task_id") == "task"
            and event.get("tool_call_id") == "probe"
            and event.get("execution_id") == execution_id
        )
        if selected and same_process and same_call:
            decisions.add((event.get("matched_rule"), event.get("action")))
    expected = {("probe.allow", "allow"), ("probe.deny", "deny")}
    if not expected <= decisions:
        raise AssertionError(decisions)


@pytest.mark.asyncio
async def test_x86_session_client_file_policy(case, tmp_path):
    """Isolate protocol and policy enforcement from deployment into an external process."""
    host, allowed, denied, _ = case
    directory = guard_binary_directory()
    guard = ProcessGuard(session_id="architecture", host=host)
    async with WindowsGuardExecution(
        session_id=guard.session_id, tool_call_id="probe", task_id="task", source_tool="bash",
        dll=directory / "x64" / "agent_security_guard.dll", engine=getattr(guard, "_policy"),
        emit=None, approvals=RuntimeApprovalRequests(), audit=host.audit,
    ) as session:
        process = await asyncio.create_subprocess_exec(
            directory / "session_client_x86.exe", allowed, denied, cwd=tmp_path,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            session.job.attach(process.pid)
            stdout, stderr = await asyncio.wait_for(process.communicate(session.bootstrap), 20)
            if process.returncode != 0:
                raise AssertionError((process.returncode, stdout, stderr))
            assert_file_decisions(case, 32, False, process.pid, session.context.execution_id, stdout)
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,broker,success", [
    ("recover", False, True), ("recover", True, False), ("permanent", False, True),
])
async def test_wow64_delete_uses_shared_disposition(tmp_path, case, mode, broker, success):
    host, target, _, events = case
    target.write_bytes(b"recoverable")
    probe = guard_binary_directory() / "probe_x86.exe"
    env = dict(os.environ)
    env["JIUWENBOX_SOFT_DELETE_ARCHIVE"] = str(tmp_path / "archive")
    if broker:
        env.update(JIUWENBOX_SOFT_DELETE="1", JIUWENBOX_SOFT_DELETE_RECYCLE_PORT="0")
    async with ProcessGuard(session_id="architecture", host=host, delete_mode=mode) as guard:
        process = await guard.spawn(
            [probe, "delete", target], task_id="task", tool_call_id="probe", tool_name="bash",
            env=env, timeout_s=20,
        )
        exit_code = await process.wait()
        if (exit_code == 0) != success:
            raise AssertionError(exit_code)
    if target.exists() == success:
        raise AssertionError(target)
    results = [event for event in events if event.get("kind") == "result"]
    if len(results) != 1:
        raise AssertionError(results)
    expected_status = "success" if success else "failed"
    if results[0].get("status") != expected_status:
        raise AssertionError(results[0])
    if mode == "permanent" and results[0].get("disposition") != "permanent":
        raise AssertionError(results[0])
