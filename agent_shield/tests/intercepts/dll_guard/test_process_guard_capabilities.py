"""Real public-entry coverage for the retired launcher API families."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from unittest.mock import AsyncMock

import pytest

from agent_shield import ProcessGuard
from agent_shield.intercepts.native_call._binary_location import guard_binary_directory

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "probe_x86.exe").is_file(),
    reason="Requires the foundation Windows build with both test probes",
)


class Host:
    def __init__(self, root, rules):
        self.root, self.rules, self.events = root, rules, []

    def policy_snapshot(self):
        snapshot = {
            "revision": 1,
            "workspace_root": str(self.root),
            "config": {"enabled": False, "package_builtin_rules": False},
            "ruleset": {"spec": "agent-pdp/v1"},
            "unmatched": "allow",
            "tasks": {"task": {"subject_id": "user", "user_rules": self.rules}},
        }
        if self.rules is None:
            snapshot.pop("ruleset")
            snapshot.pop("tasks")
        return snapshot

    async def confirm(self, request):
        raise AssertionError(f"Unexpected approval {request}")

    def audit(self, event):
        self.events.append(event)


async def execute(host, argv, mode="permanent"):
    async with ProcessGuard(session_id="capabilities", host=host, delete_mode=mode) as guard:
        process = await guard.spawn(
            argv,
            task_id="task",
            tool_call_id="call",
            tool_name="bash",
            timeout_s=20,
            stdio={"stdout": asyncio.subprocess.PIPE, "stderr": asyncio.subprocess.PIPE},
        )
        out, err = await process.communicate()
        return process.returncode, process.pid, out, err


@pytest.mark.asyncio
async def test_task_ask_reuses_only_the_current_calls_app_receipt(tmp_path):
    probe = guard_binary_directory() / "probe.exe"
    target, other, blocked = (tmp_path / name for name in ("target", "other", "blocked"))
    for path in (target, other, blocked):
        path.write_bytes(b"original")
    host = Host(tmp_path, [
        {"id": "receipt.ask", "object": "file", "ops": ["read", "write"],
         "pattern": [str(target), str(other)], "action": "ask"},
        {"id": "receipt.deny", "object": "file", "ops": ["read"], "pattern": [str(blocked)], "action": "deny"},
    ])
    host.confirm = AsyncMock(return_value={"action": "deny"})
    cases = [
        ("read", target, target, 0, 0),
        ("read", target, None, 5, 1),  # Next call in the same session.
        ("write", target, target, 5, 1),
        ("read", other, target, 5, 1),
        ("read", blocked, blocked, 5, 0),
    ]
    async with ProcessGuard(session_id="s", host=host) as guard:
        for index, (operation, path, approved_path, status, prompts) in enumerate(cases):
            call = str(index)
            receipt = None if approved_path is None else {
                "session_id": "s", "task_id": "task", "tool_call_id": call, "tool_name": "bash", "revision": 1,
                "operation": {"kind": "file", "accesses": [(str(approved_path), "read")]},
                "confirmation": {"approved": True, "authorization_mode": "allow"},
            }
            host.confirm.reset_mock()
            proc = await guard.spawn([probe, operation, path], task_id="task", tool_call_id=call,
                                     tool_name="bash", approval_receipt=receipt, timeout_s=15)
            assert await proc.wait() == status
            assert host.confirm.await_count == prompts
            assert any(e["kind"] == "policy_settled" and e["tool_call_id"] == call
                       and e["matched_rule"] == ("receipt.deny" if path == blocked else "receipt.ask")
                       and e["action"] == ("allow" if status == 0 else "deny") for e in host.events)
    assert target.read_bytes() == b"original"


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("action", ["allow", "deny"])
@pytest.mark.parametrize(
    "operation",
    [
        "read",
        "attributes",
        "enumerate",
        "set-attributes",
        "write",
        "mkdir",
        "copy",
        "move",
        "replace",
        "hardlink",
        "symlink",
        "rename-replace",
    ],
)
async def test_file_operations_apply_task_rule_before_side_effect(
    tmp_path, bits, action, operation
):
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    source, target = tmp_path / "source", tmp_path / "target"
    source.write_bytes(b"source")
    if operation in {"read", "attributes", "set-attributes", "replace", "rename-replace"}:
        target.write_bytes(b"original")
    if operation == "enumerate":
        target.mkdir()
        (target / "entry").write_bytes(b"entry")
    arguments = [operation, str(target)]
    if operation == "enumerate":
        arguments[-1] += "/*"
    if operation in {"copy", "move", "replace", "hardlink", "symlink", "rename-replace"}:
        arguments = [operation, str(source), str(target)]
    rule_target = source if operation == "symlink" else target
    host = Host(
        tmp_path,
        [
            {
                "id": "migration.file",
                "object": "file",
                "action": action,
                "ops": ["delete"] if operation == "rename-replace" else ["read", "write", "delete"],
                "pattern": [str(rule_target), str(rule_target) + "/**"],
            }
        ],
    )
    code, pid, out, err = await execute(host, [str(probe), *arguments])
    if operation == "symlink":
        assert any(
            e.get("operation", {}).get("operation") == {"kind": "symlink", "resources": [
                {"role": "source", "path": str(source)}, {"role": "target", "path": str(target)},
            ]} and e.get("action") == action and e.get("matched_rule") == "migration.file"
            for e in host.events
        )
    assert code == (0 if action == "allow" else 5), (operation, code, out, err)
    assert any(
        event.get("kind") == "policy_decision"
        and event.get("pid") == pid
        and event.get("matched_rule") == "migration.file"
        and event.get("action") == action
        for event in host.events
    )
    identities = [
        event["process"] for event in host.events if event.get("kind") == "policy_decision"
    ]
    assert identities and all(identity["user_sid"].startswith("S-1-") for identity in identities)
    assert all(identity["process_instance_id"].startswith(f"{pid}:") for identity in identities)
    if action == "deny":
        assert source.read_bytes() == b"source"
        if operation in {"read", "attributes", "set-attributes", "replace", "rename-replace"}:
            assert target.read_bytes() == b"original"
        elif operation != "enumerate":
            assert not target.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("action", ["allow", "deny"])
async def test_shell_execute_has_actual_child_rule_and_tool_cause(tmp_path, bits, action):
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    child, target = tmp_path / "child.exe", tmp_path / "child-write"
    shutil.copyfile(probe, child)
    host = Host(
        tmp_path,
        [
            {
                "id": "migration.program",
                "object": "command",
                "action": action,
                "match": "child.exe *",
            }
        ],
    )
    code, root_pid, out, err = await execute(
        host,
        [str(probe), "shell", str(child), f'write "{target}"'],
    )
    assert code == (0 if action == "allow" else 5), (code, out, err)
    assert target.exists() == (action == "allow")
    decisions = [e for e in host.events if e.get("kind") == "policy_decision"]
    assert any(
        e.get("matched_rule") == "migration.program" and e["action"] == action for e in decisions
    )
    if action == "allow":
        assert any(
            e.get("pid") != root_pid
            and e.get("resource_kind") == "file"
            and e.get("tool_call_id") == "call"
            for e in decisions
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
async def test_shell_execute_rejects_delegated_verb(tmp_path, bits):
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    cmd = os.path.join(os.environ["SystemRoot"], "System32", "cmd.exe")
    code, _, _, _ = await execute(
        Host(tmp_path, None), [str(probe), "shell", cmd, "/c exit 0", "runas"]
    )
    assert code == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["token-exec", "as-user"])
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("action", ["allow", "deny"])
async def test_current_user_token_launch_stays_in_same_task(tmp_path, bits, api, action):
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    child, target = tmp_path / "child.exe", tmp_path / "written"
    shutil.copyfile(probe, child)
    command = subprocess.list2cmdline([str(child), "write", str(target)])
    baseline = await asyncio.to_thread(
        subprocess.run,
        [str(probe), api, str(child), command],
        capture_output=True,
        timeout=15,
        check=False,
    )
    system_api = "CreateProcessWithTokenW" if api == "token-exec" else "CreateProcessAsUserW"
    privilege_error = f"stage={system_api} error=1314".encode()
    if baseline.returncode == 77 and privilege_error in baseline.stderr:
        pytest.skip(f"Unguarded {system_api} returned ERROR_PRIVILEGE_NOT_HELD (1314)")
    assert baseline.returncode == 0 and target.is_file(), baseline
    target.unlink()
    host = Host(
        tmp_path,
        [
            {
                "id": "migration.token",
                "object": "command",
                "action": action,
                "match": "child.exe *",
            }
        ],
    )
    code, root_pid, out, err = await execute(host, [str(probe), api, str(child), command])
    (tmp_path / "guard-audit.jsonl").write_text(
        "".join(json.dumps(event, ensure_ascii=False, default=str) + "\n" for event in host.events),
        encoding="utf-8",
    )
    assert code == (0 if action == "allow" else 5), (code, out, err)
    assert target.exists() == (action == "allow")
    assert any(
        e.get("matched_rule") == "migration.token" and e["action"] == action for e in host.events
    )
    if action == "allow":
        children = [
            e
            for e in host.events
            if e.get("kind") == "policy_decision" and e.get("pid") != root_pid
        ]
        assert children
        assert all(e["process"]["parent_pid"] == root_pid for e in children)
        assert all(e["process_instance_id"].startswith(f'{e["pid"]}:') for e in children)


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("action", ["allow", "deny"])
async def test_network_rule_and_actual_loopback_connection(tmp_path, bits, action):
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    accepted = asyncio.Event()

    async def receive(reader, writer):
        accepted.set()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(receive, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        host = Host(
            tmp_path,
            [
                {
                    "id": "migration.network",
                    "object": "domain",
                    "ops": ["connect"],
                    "action": action,
                    "cidrs": ["127.0.0.1/32"],
                }
            ],
        )
        code, pid, out, err = await execute(
            host, [str(probe), "connect", "-", "127.0.0.1", str(port)]
        )
        # The probe uses 4 for a completed TCP connection and 5 for policy denial.
        assert code == (4 if action == "allow" else 5), (code, out, err)
        assert any(
            e.get("matched_rule") == "migration.network" and e.get("pid") == pid
            for e in host.events
        )
        if action == "allow":
            await asyncio.wait_for(accepted.wait(), 2)
        else:
            assert not accepted.is_set()
    finally:
        server.close()
        await server.wait_closed()
