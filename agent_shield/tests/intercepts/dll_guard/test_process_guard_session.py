"""Public launch API, per-execution ownership and session-scoped approvals."""

import asyncio
import importlib.util
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from agent_shield import ProcessGuard
from agent_shield.intercepts.native_call import dll_guard
from agent_shield.intercepts.native_call.dll_guard import process_guard as sdk
from agent_shield.intercepts.native_call.dll_guard.context import RuntimeGuardContext
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse


def test_runtime_launch_api_is_retired():
    assert not hasattr(dll_guard, "RuntimeGuardManager")
    assert not hasattr(dll_guard, "create_process")


def test_native_startup_and_json_protocol_entry_points_are_retired():
    from agent_shield.intercepts import native_call

    for name in (
        "wrap",
        "preflight",
        "ProcessBinding",
        "settle_native_record",
        "native_record_to_event",
    ):
        assert not hasattr(native_call, name)
    for name in ("launch", "decide_pipe", "session", "record"):
        assert importlib.util.find_spec(f"agent_shield.intercepts.native_call.{name}") is None


@pytest.mark.asyncio
async def test_same_session_id_in_two_guards_does_not_share_pending_approval():
    first = ProcessGuard(session_id="s", host=Mock())
    second = ProcessGuard(session_id="s", host=Mock())
    context = RuntimeGuardContext("s", "call", "revision")
    events = asyncio.Queue()
    pending = asyncio.create_task(first.approvals.request(context, {}, events.put, 1, channel="c"))
    event = await asyncio.wait_for(events.get(), 1)
    answer = PermissionConfirmResponse(approved=True)
    second.cancel_pending(channel="c")
    assert not second.approvals.resolve("s", event["request_id"], answer)
    assert first.approvals.resolve("s", event["request_id"], answer)
    assert await pending is answer


@pytest.mark.asyncio
async def test_concurrent_spawns_own_independent_trees_until_session_exit(monkeypatch):
    def execution(identity):
        context = SimpleNamespace(active=True, execution_id=identity)

        async def close(**kwargs):
            context.active = False

        return Mock(
            context=context,
            job=Mock(active_processes=Mock(return_value=1)),
            __aenter__=AsyncMock(),
            close=AsyncMock(side_effect=close),
            launch=AsyncMock(),
        )

    first, second = execution("first"), execution("second")
    factory = Mock(side_effect=[first, second])
    monkeypatch.setattr(sdk, "WindowsGuardExecution", factory)
    monkeypatch.setattr(sdk, "validate_guard_platform", lambda: "guard.dll")
    host = Mock(policy_snapshot=Mock(return_value={"config": {}, "revision": 1}))
    guard = ProcessGuard(session_id="session", host=host)
    args = {"task_id": "task", "tool_call_id": "call", "tool_name": "bash"}
    async with guard:
        a, b = await asyncio.gather(guard.spawn(["a"], **args), guard.spawn(["b"], **args))
        assert {a.execution_id, b.execution_id} == {"first", "second"}
        assert first.context.active and second.context.active
        await a.cancel()
        assert not first.context.active and second.context.active
    assert not second.context.active
    with pytest.raises(sdk.GuardError, match="session_closed"):
        await guard.spawn(["c"], **args)


@pytest.mark.asyncio
async def test_session_cleanup_releases_other_trees_and_can_retry_after_error():
    guard = ProcessGuard(session_id="s", host=Mock())
    failed = Mock(close=AsyncMock(side_effect=[OSError("busy"), None]))
    other = Mock(close=AsyncMock())
    guard.active_executions.update([failed, other])
    with pytest.raises(ExceptionGroup, match="session cleanup failed"):
        await guard.__aexit__(None, None, None)
    assert guard.active_executions == {failed}
    with pytest.raises(sdk.GuardError, match="session_already_open"):
        await guard.__aenter__()
    await guard.__aexit__(None, None, None)
    assert not guard.active_executions
    other.close.assert_awaited_once()
