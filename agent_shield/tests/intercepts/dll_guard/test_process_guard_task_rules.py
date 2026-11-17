"""Task policy parity at the decision boundary and through a real protected process."""

import json
import os
import sys
from pathlib import Path

import pytest

from agent_shield import ProcessGuard
from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.errors import GuardError
from agent_shield.intercepts.native_call.dll_guard.task_rules import TaskRules
from agent_shield.tool_permission.runtime.engine import PermissionEngine


def snapshot(root, *, user_rules=()):
    return {
        "config": {"enabled": False, "package_builtin_rules": False},
        "revision": 1,
        "workspace_root": str(root),
        "ruleset": {"spec": "agent-pdp/v1"},
        "unmatched": "allow",
        "tasks": {"task": {"subject_id": "alice", "user_rules": list(user_rules)}},
    }


def test_existing_native_rule_decisions_and_winner_ids():
    directory = Path(__file__).parent
    cases = json.loads((directory / "operation_cases.json").read_text(encoding="utf-8"))
    baseline = {}
    results = (directory / "operation_results.jsonl").read_text(encoding="utf-8")
    for line in results.splitlines():
        row = json.loads(line)
        baseline[row["id"]] = row
    assert len(cases) == len(baseline) == 100
    policy = snapshot("C:/Users/me/proj")
    policy["unmatched"] = "none"
    policy["tasks"]["task"].update(
        user_intent={"text": "read the project file"},
        host_capabilities={"hitl": False, "auto_intent": True},
    )
    rules = TaskRules(policy, "session")
    for case in cases:
        body = case
        actual = rules.check_operation(body["operation"], "task", body["cause"])
        expected = baseline.get(case["id"])
        if expected is None:
            raise KeyError(case["id"])
        # The runtime denies unsettled decisions when the host disables approval.
        action = "deny" if expected["action"] in ("ask", "undetermined") else expected["action"]
        assert (actual.permission.value, actual.matched_rule) == (
            action, expected["winner_rule_id"]
        ), case["id"]


@pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "probe.exe").is_file(),
    reason="Requires the Windows Guard build with test probes",
)
@pytest.mark.asyncio
async def test_public_spawn_runs_wow64_root(tmp_path):
    target = Path(os.environ["SystemRoot"]) / "SysWOW64" / "cmd.exe"
    if not target.is_file():
        pytest.skip("WOW64 system executable unavailable")

    class Host:
        @staticmethod
        def policy_snapshot():
            return snapshot(tmp_path)

        @staticmethod
        def audit(event):
            pass

    async with ProcessGuard(session_id="architecture", host=Host()) as guard:
        process = await guard.spawn(
            [target, "/d", "/c", "exit 0"], task_id="task", tool_call_id="call", tool_name="bash",
        )
        assert await process.wait() == 0


def test_task_grant_is_subject_bound_and_revision_scoped(tmp_path):
    target = str(tmp_path / "one.txt")
    rule = {
        "id": "ask.read",
        "object": "file",
        "pattern": [target],
        "ops": ["read"],
        "action": "ask",
    }
    policy = snapshot(tmp_path, user_rules=[rule])
    policy["tasks"]["second"] = {"subject_id": "bob", "user_rules": [rule]}
    rules = TaskRules(policy, "session")
    subject = {"kind": "file", "accesses": [(target, "read")]}
    decision = rules.check(subject, "task", "call", "bash")
    assert decision.needs_approval and decision.grants
    rules.remember("task", decision.grants)
    assert rules.check(subject, "task", "call", "bash").is_allowed
    assert rules.check(subject, "second", "call", "bash").needs_approval
    assert TaskRules(policy, "session").check(subject, "task", "call", "bash").needs_approval
    with pytest.raises(GuardError, match="unknown_task"):
        rules.check(subject, "unknown", "call", "bash")


@pytest.mark.asyncio
async def test_explicit_task_allow_retains_rule_id_for_audit(tmp_path):
    path = str(tmp_path / "allowed.txt")
    rule = {"id": "allow.read", "object": "file", "pattern": [path], "ops": ["read"], "action": "allow"}
    policy = snapshot(tmp_path, user_rules=[rule])
    engine = PermissionEngine(policy["config"], workspace_root=str(tmp_path))
    engine.task_rules = TaskRules(policy, "session")
    decision = await engine.evaluate_operation(
        {"kind": "file", "accesses": [(path, "read")]}, {}, task=("task", "call", "bash")
    )
    assert decision.is_allowed and decision.matched_rule == "allow.read"


@pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "probe.exe").is_file(),
    reason="Requires the Windows Guard build with test probes",
)
@pytest.mark.asyncio
async def test_spawn_denies_backup_before_replacing_either_file(tmp_path):
    source, target, backup = [
        tmp_path / name for name in ("source.txt", "target.txt", "backup.txt")
    ]
    source.write_bytes(b"replacement")
    target.write_bytes(b"original")
    events = []

    class Host:
        @staticmethod
        def policy_snapshot():
            return snapshot(
                tmp_path,
                user_rules=[
                    {
                        "id": "deny.backup",
                        "object": "file",
                        "action": "deny",
                        "ops": ["write"],
                        "pattern": [str(backup)],
                    }
                ],
            )

        async def confirm(self, request):
            return {"action": "allow_once"}

        @staticmethod
        def audit(event):
            events.append(event)

    async with ProcessGuard(session_id="s", host=Host()) as guard:
        proc = await guard.spawn(
            [guard_binary_directory() / "probe.exe", "replace", source, target, backup],
            task_id="task",
            tool_call_id="call",
            tool_name="bash",
            timeout_s=20,
        )
        assert await proc.wait() == 5
    assert any(e.get("matched_rule") == "deny.backup" and e["action"] == "deny" for e in events)
    assert source.read_bytes() == b"replacement" and target.read_bytes() == b"original"
    assert not backup.exists()


@pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "probe.exe").is_file(),
    reason="Requires the Windows Guard build with test probes",
)
@pytest.mark.asyncio
async def test_spawn_applies_device_rule_to_named_pipe(tmp_path):
    import _winapi
    from uuid import uuid4

    name = os.path.join(r"\\.\pipe", "guard-test-" + uuid4().hex)
    listener = _winapi.CreateNamedPipe(name, _winapi.PIPE_ACCESS_DUPLEX, 0, 1, 512, 512, 0, 0)
    events = []

    class Host:
        @staticmethod
        def policy_snapshot():
            policy = snapshot(tmp_path)
            policy["tasks"]["task"]["host_capabilities"] = {"hitl": False}
            return policy

        @staticmethod
        def audit(event):
            events.append(event)

    try:
        async with ProcessGuard(session_id="s", host=Host()) as guard:
            proc = await guard.spawn(
                [guard_binary_directory() / "probe.exe", "open", "read", name],
                task_id="task",
                tool_call_id="call",
                tool_name="bash",
                timeout_s=20,
            )
            assert await proc.wait() == 5
    finally:
        _winapi.CloseHandle(listener)
    assert any(e.get("matched_rule") == "fs.device" and e["action"] == "deny" for e in events)


@pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "probe.exe").is_file(),
    reason="Requires the Windows Guard build with test probes",
)
@pytest.mark.asyncio
async def test_spawn_applies_domain_rule_before_opening_internet_handle(tmp_path):
    events = []

    class Host:
        @staticmethod
        def policy_snapshot():
            policy = snapshot(tmp_path)
            policy["ruleset"]["rules"] = [
                {
                    "id": "corp.peer",
                    "object": "domain",
                    "action": "deny",
                    "hosts": ["private.invalid"],
                    "ops": ["connect"],
                }
            ]
            return policy

        async def confirm(self, request):
            return {"action": "allow_once"}

        @staticmethod
        def audit(event):
            events.append(event)

    async with ProcessGuard(session_id="s", host=Host()) as guard:
        proc = await guard.spawn(
            [guard_binary_directory() / "probe.exe", "connect", "private.invalid", "-", "443"],
            task_id="task",
            tool_call_id="call",
            tool_name="bash",
            timeout_s=20,
        )
        assert await proc.wait() == 5
    assert any(
        e.get("matched_rule") == "corp.peer" and e["resource_kind"] == "connection" for e in events
    )
