"""Execution-scoped approval lifecycle and policy changes during a live wait."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.intercepts.native_call.dll_guard.context import RuntimeGuardContext
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["deny", "cancel", "host_revision", "membership"])
async def test_host_wait_cannot_resume_after_policy_or_execution_changes(tmp_path, change):
    from agent_shield.tool_permission.runtime.models import (
        PermissionLevel,
        PermissionResult,
    )

    config = {"enabled": True, "package_builtin_rules": False, "defer_unmatched": True}
    engine = PermissionEngine(config, workspace_root=tmp_path)
    entered, release = asyncio.Event(), asyncio.Event()
    revision, member = "v1", True

    async def host(_subject, _local):
        entered.set()
        await release.wait()
        return PermissionResult(PermissionLevel.ALLOW)

    obj = WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=tmp_path / "guard.dll",
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=AsyncMock(),
        program_decision=host,
        policy_revision=lambda: revision,
    )
    obj.job = SimpleNamespace(contains=lambda _pid: member, close=lambda: None)
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "program.exe"),
        "argv": [],
        "cwd": str(tmp_path),
    }
    task = asyncio.create_task(obj.check_resource(123, subject))
    await entered.wait()
    if change == "deny":
        engine.update_config({**config, "tools": {"bash": "deny"}})
    elif change == "cancel":
        obj.context.finish()
    elif change == "host_revision":
        revision = "v2"
    else:
        member = False
    release.set()
    assert not await task
    obj.emit.assert_not_awaited()
    await obj.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("final_decision", ["allow", "deny", "stricter_ask"])
async def test_program_rechecks_host_after_runtime_confirmation(tmp_path, final_decision):
    from agent_shield.tool_permission.runtime.models import (
        PermissionLevel,
        PermissionResult,
    )

    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "defer_unmatched": True,
            "defaults": {"*": "allow"},
        },
        workspace_root=tmp_path,
    )
    registry = RuntimeApprovalRequests()
    decision, calls = "ask", []

    async def host(subject, local):
        assert local.is_undetermined
        calls.append(subject)
        if decision == "stricter_ask":
            return PermissionResult(PermissionLevel.ASK, "del_guard:batch_delete")
        return PermissionResult(PermissionLevel(decision))

    async def emit(event):
        nonlocal decision
        decision = final_decision
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=True))

    execution = WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=tmp_path / "guard.dll",
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        program_decision=host,
    )
    execution.job = SimpleNamespace(contains=lambda pid: pid == 123, close=lambda: None)
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "which.exe"),
        "argv": ["bash"],
        "cwd": str(tmp_path),
    }
    assert await execution.check_resource(123, subject) is (final_decision == "allow")
    assert calls == [subject, subject]
    await execution.close()


@pytest.mark.asyncio
async def test_pending_identity_duplicate_and_late_answer():
    registry = RuntimeApprovalRequests()
    context = RuntimeGuardContext("s", "call", "v1")
    seen = []

    async def emit(event):
        seen.append(event)

    task = asyncio.create_task(registry.request(context, {}, emit, 1))
    await asyncio.sleep(0)
    request_id = seen[0]["request_id"]
    answer = PermissionConfirmResponse(approved=True)
    assert not registry.resolve("other", request_id, answer)
    assert registry.resolve("s", request_id, answer)
    assert not registry.resolve("s", request_id, answer)
    assert await task is answer
    assert not registry.resolve("s", request_id, answer)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_pending_timeout_and_cancel_cleanup(cancel):
    registry = RuntimeApprovalRequests()
    context = RuntimeGuardContext("s", "call", "v1")
    seen = []

    async def emit(event):
        seen.append(event)
        await asyncio.Event().wait()  # The deadline also covers blocked output.

    task = asyncio.create_task(registry.request(context, {}, emit, 0.02))
    await asyncio.sleep(0)
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
        await task
    assert not registry.resolve(
        "s", seen[0]["request_id"], PermissionConfirmResponse(approved=True)
    )


@pytest.mark.asyncio
async def test_queued_card_gets_its_own_response_deadline():
    registry = RuntimeApprovalRequests()
    cards = asyncio.Queue()
    first = RuntimeGuardContext("s", "first", "v1")
    second = RuntimeGuardContext("s", "second", "v1")
    answer = PermissionConfirmResponse(approved=True)
    async with asyncio.TaskGroup() as group:
        first_task = group.create_task(registry.request(first, {}, cards.put, 5))
        first_card = await asyncio.wait_for(cards.get(), 1)
        second_task = group.create_task(registry.request(second, {}, cards.put, 0.1))
        await asyncio.sleep(0.2)
        assert cards.empty()
        assert registry.resolve("s", first_card["request_id"], answer)
        second_card = await asyncio.wait_for(cards.get(), 1)
        assert second_card["tool_call_id"] == "second"
        assert registry.resolve("s", second_card["request_id"], answer)
    assert first_task.result() is answer and second_task.result() is answer


@pytest.mark.asyncio
async def test_disconnect_cancels_displayed_and_queued_cards():
    registry = RuntimeApprovalRequests()
    contexts = [RuntimeGuardContext("s", str(index), "v1") for index in range(2)]
    cards = []

    async def emit(event):
        cards.append(event)

    tasks = [
        asyncio.create_task(registry.request(ctx, {}, emit, 5, channel="desktop"))
        for ctx in contexts
    ]
    await asyncio.sleep(0)
    assert len(cards) == 1
    registry.cancel_channel("web")
    assert not tasks[0].done()
    registry.cancel_channel("desktop")
    results = await asyncio.gather(*tasks, return_exceptions=True)
    assert all(isinstance(result, asyncio.CancelledError) for result in results)
    assert len(cards) == 1


def make_execution(tmp_path, emit, registry, *, read="ask", write="ask"):
    target = tmp_path / "target.txt"
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "file_guard": {
                "enabled": True,
                "paths": [{"path": str(target), "read": read, "write": write, "exec": "deny"}],
            },
        },
        workspace_root=tmp_path / "workspace",
    )
    execution = WindowsGuardExecution(
        session_id="s",
        tool_call_id="call",
        dll=tmp_path / "guard.dll",
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
    )
    execution.job = SimpleNamespace(contains=lambda pid: pid == 123, close=lambda: None)
    return target, execution


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "artifact", ["jiuwen_runtime_guard.dll", "jiuwen_runtime_guard.manifest.json"]
)
async def test_native_artifacts_have_no_independent_write_policy(tmp_path, artifact):
    engine = PermissionEngine({"enabled": False})
    native = tmp_path / "package" / "native"
    execution = WindowsGuardExecution(
        session_id="s",
        tool_call_id="call",
        dll=native / "jiuwen_runtime_guard.dll",
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=AsyncMock(),
    )
    execution.job = SimpleNamespace(contains=lambda pid: pid == 123)
    resource = str(native / artifact)
    assert await execution.check_resource(123, {"kind": "file", "accesses": [(resource, "write")]})
    assert await execution.check_resource(123, {"kind": "file", "accesses": [(resource, "read")]})


@pytest.mark.asyncio
async def test_same_execution_deduplicates_and_denies_mixed_access(tmp_path):
    registry = RuntimeApprovalRequests()
    cards = []

    async def emit(event):
        cards.append(event)
        await asyncio.sleep(0)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=True))

    target, execution = make_execution(tmp_path, emit, registry, write="deny")
    assert not await execution.check_access(999, str(target), 1)
    assert not await execution.check_access(123, str(target), 3)  # read ASK + write DENY
    assert cards == []
    assert (
        await asyncio.gather(*(execution.check_access(123, str(target), 1) for _ in range(3)))
        == [True] * 3
    )
    assert len(cards) == 1
    assert await execution.check_access(123, str(target), 1)
    assert len(cards) == 1
    await execution.close()
    assert not await execution.check_access(123, str(target), 1)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["policy", "cancel", "scope", "session", "permanent"])
async def test_approval_cannot_outlive_policy_or_expand_scope(tmp_path, change):
    registry = RuntimeApprovalRequests()

    async def emit(event):
        if change == "policy":
            execution.engine().update_config(
                {
                    "enabled": True,
                    "file_guard": {
                        "enabled": True,
                        "paths": [{"path": str(target), "read": "deny"}],
                    },
                }
            )
        if change == "cancel":
            execution.context.finish()
        registry.resolve(
            "s",
            event["request_id"],
            PermissionConfirmResponse(
                approved=True,
                auto_confirm=change in {"session", "permanent"},
                persist_allow=change == "permanent",
                authorization_scope="directory" if change == "scope" else "exact",
            ),
        )

    target, execution = make_execution(tmp_path, emit, registry)
    assert not await execution.check_access(123, str(target), 1)
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_raw_approval_event_resumes_original_check(tmp_path, approved):
    registry = RuntimeApprovalRequests()

    async def emit(event):
        assert event == {
            "request_id": event["request_id"],
            "execution_id": execution.context.execution_id,
            "session_id": "s",
            "tool_call_id": "call",
            "resource": {
                "kind": "file",
                "accesses": [(str(target), "read")],
                "can_remember": False,
            },
            "matched_rule": expected.matched_rule,
            "reason": expected.reason,
        }
        assert registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved))

    target, execution = make_execution(tmp_path, emit, registry)
    expected = execution.engine().check_file_accesses([(target, "read")])
    assert await execution.check_access(123, str(target), 1) is approved
    await execution.close()
