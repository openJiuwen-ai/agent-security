"""Ownership at actual invocation, lazy concurrent launch and background lifetime."""

import asyncio
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import AsyncMock, Mock

import pytest

from agent_shield.intercepts.native_call.dll_guard import (
    PermissionConfirmResponse,
    RuntimeGuardManager,
    create_process,
)
from agent_shield.intercepts.native_call.dll_guard.context import RuntimeGuardContext


def assembled_manager(tmp_path, config):
    """Host callback fixture for session and background-process ownership."""
    import json

    from agent_shield.tool_permission.runtime.engine import PermissionEngine
    from agent_shield.tool_permission.runtime.models import (
        PermissionLevel,
        PermissionResult,
    )

    def engine():
        return PermissionEngine(
            {**config["permissions"], "defer_unmatched": True}, workspace_root=tmp_path
        )

    async def program(subject, result, **kwargs):
        return PermissionResult(
            PermissionLevel.ASK
            if config["security"]["fail_closed"]["enabled"]
            else PermissionLevel.ALLOW
        )

    owner = RuntimeGuardManager(
        session_id="runtime-session",
        dll=tmp_path / "guard.dll",
        engine=engine,
        program_decision=program,
        revision=lambda: json.dumps(config, sort_keys=True),
    )
    return owner, SimpleNamespace(runtime_engine=lambda _session: engine())


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_closed,expected", [(False, "allow"), (True, "ask")])
async def test_program_uses_host_fallback(tmp_path, fail_closed, expected):
    from agent_shield.tool_permission.runtime.models import (
        PermissionLevel,
        PermissionResult,
    )

    config = {
        "permissions": {
            "enabled": True,
            "package_builtin_rules": False,
            "defaults": {"*": "allow"},
        },
        "security": {"fail_closed": {"enabled": fail_closed}},
    }
    owner, rail = assembled_manager(tmp_path, config)
    engine = rail.runtime_engine("runtime-session")
    result = await engine.check_permission("bash", {"command": "which bash"})
    assert result.is_undetermined
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "which.exe"),
        "argv": ["bash"],
        "cwd": str(tmp_path),
    }
    decision = await owner.program_decision(
        subject,
        PermissionResult(PermissionLevel.UNDETERMINED),
        session=SimpleNamespace(get_session_id=lambda: "runtime-session"),
        tool_call_id="tool",
        execution_id="exec",
    )
    assert decision.permission.value == expected


@pytest.mark.asyncio
async def test_program_host_policy_change_invalidates_execution_grants(tmp_path):
    from agent_shield.intercepts.native_call.dll_guard.policy import resource_grant

    config = {
        "permissions": {"enabled": True, "package_builtin_rules": False},
        "security": {"fail_closed": {"enabled": True}},
    }
    owner, _rail = assembled_manager(tmp_path, config)
    first = owner.revision()
    context = RuntimeGuardContext("s", "c", first)
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "program.exe"),
        "argv": [],
        "cwd": str(tmp_path),
    }
    grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
    context.remember("dll_runtime_program", grant, policy_version=first)
    assert context.matches(subject, execution_id=context.execution_id, policy_version=first)
    config["security"]["fail_closed"]["enabled"] = False
    assert owner.revision() != first
    context.update_policy_version(owner.revision())
    assert not context.matches(
        subject, execution_id=context.execution_id, policy_version=owner.revision()
    )


class Execution:
    instances: ClassVar[list] = []

    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.context = SimpleNamespace(active=True, execution_id="execution")
        self.source_shell = "bash"
        self.seed_approved_operation = Mock()
        self.alive = 1
        self.job = SimpleNamespace(active_processes=lambda: self.alive)
        self.closed = 0
        self.instances.append(self)

    async def __aenter__(self):
        await asyncio.sleep(0)
        return self

    async def launch(self, factory, *args, **kwargs):
        return await factory(*args, **kwargs)

    async def close(self):
        if self.context.active:
            self.closed += 1
            self.context.active = False
            self.alive = 0


def manager(tmp_path, **kwargs):
    return RuntimeGuardManager(
        session_id="s",
        engine=lambda: None,
        dll=tmp_path / "guard.dll",
        enabled=lambda: True,
        execution_factory=Execution,
        **kwargs,
    )


@pytest.mark.asyncio
async def test_managers_with_same_ids_have_isolated_pending_approvals(tmp_path):
    first, second = manager(tmp_path), manager(tmp_path)
    context = RuntimeGuardContext("s", "call", "v1")
    events = asyncio.Queue()
    pending = asyncio.create_task(first.approvals.request(context, {}, events.put, 1, channel="c"))
    event = await asyncio.wait_for(events.get(), 1)
    answer = PermissionConfirmResponse(approved=True)
    second.approvals.cancel_channel("c")
    assert not second.approvals.resolve("s", event["request_id"], answer)
    assert first.approvals.resolve("s", event["request_id"], answer)
    assert await pending is answer


@pytest.mark.asyncio
async def test_lazy_concurrent_launch_and_background_ownership(tmp_path):
    emit, notify = AsyncMock(), AsyncMock()
    receipt = {"operation": {"kind": "url", "url": "https://example.test/"}}
    take = Mock(return_value=receipt)
    decide, persist, revision = AsyncMock(), Mock(return_value=True), Mock(return_value=17)
    owner = manager(
        tmp_path,
        emit=emit,
        notify=notify,
        take_approval=take,
        program_decision=decide,
        persist=persist,
        revision=revision,
    )
    async with owner.tool_execution(
        tool_name="bash", inputs={}, session=None, tool_call_id="call", channel="connection"
    ):
        assert not owner.active
        factory = AsyncMock(return_value="process")
        assert (
            await asyncio.gather(create_process(factory), create_process(factory))
            == ["process"] * 2
        )
        assert len(owner.active) == 1
        execution = next(iter(owner.active))
        assert execution.kwargs["emit"] is emit
        assert execution.kwargs["notify"] is notify
        assert execution.kwargs["approvals"] is owner.approvals
        assert execution.kwargs["channel"] == "connection"
        take.assert_called_once_with("call", "bash", {})
        execution.seed_approved_operation.assert_called_once_with(receipt)
        assert execution.kwargs["persist"] is persist
        assert execution.kwargs["policy_revision"]() == 17
        subject = {"kind": "program", "exe": "app.exe", "argv": [], "cwd": str(tmp_path)}
        result = Mock()
        assert await execution.kwargs["program_decision"](subject, result) is decide.return_value
        decide.assert_awaited_once_with(
            {**subject, "source_tool": "bash", "source_shell": "bash"},
            result,
            session=None,
            tool_call_id="call",
            execution_id="execution",
        )
    assert owner.active[execution] is None and not execution.closed
    execution.alive = 0
    await asyncio.gather(*owner.watchers)
    assert execution.closed == 1 and not owner.active


@pytest.mark.asyncio
async def test_stop_cancels_foreground_and_allows_next_call(tmp_path):
    owner = manager(tmp_path)
    started = asyncio.Event()

    async def run():
        async with owner.tool_execution(
            tool_name="code", inputs={}, session=None, tool_call_id="call"
        ):
            await create_process(AsyncMock())
            started.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(run())
    await started.wait()
    execution = next(iter(owner.active))
    await owner.close()
    assert task.cancelled() and execution.closed == 1 and not owner.active
    async with owner.tool_execution(tool_name="code", inputs={}, session=None, tool_call_id="next"):
        pass
    await owner.close(permanent=True)
    with pytest.raises(RuntimeError):
        async with owner.tool_execution(
            tool_name="code", inputs={}, session=None, tool_call_id="later"
        ):
            pass


@pytest.mark.asyncio
async def test_disabled_preserves_original_subprocess_arguments(tmp_path):
    owner = manager(tmp_path)

    def disabled():
        return False

    owner.enabled = disabled
    factory = AsyncMock(return_value="original")
    async with owner.tool_execution(tool_name="bash", inputs={}, session=None, tool_call_id=None):
        assert await create_process(factory, "command", cwd="workspace") == "original"
    factory.assert_awaited_once_with("command", cwd="workspace")
    assert not owner.active


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_skip_other_jobs_and_can_retry(tmp_path):
    owner = manager(tmp_path)
    failed, other = Execution(), Execution()
    failed.close = AsyncMock(side_effect=OSError("locked staging file"))
    owner.active.update({failed: None, other: None})
    with pytest.raises(ExceptionGroup, match="cleanup failed"):
        await owner.close()
    assert other.closed == 1 and owner.active == {failed: None} and owner.closing
    failed.close = AsyncMock()
    await owner.close()
    assert not owner.active and not owner.closing
