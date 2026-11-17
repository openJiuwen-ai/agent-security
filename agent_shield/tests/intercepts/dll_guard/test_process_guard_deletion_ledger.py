"""Deletion reservations are shared across executions and settled only once."""

from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tool_permission.runtime.engine import PermissionEngine


@pytest.mark.asyncio
@pytest.mark.parametrize("threshold", [0, 1])
async def test_task_reservations_results_unknown_and_duplicate_settlement(tmp_path, threshold):
    engine = PermissionEngine({"enabled": False, "soft_delete": {"batch_delete_threshold": threshold}})
    ledger = {"success": 0, "reserved": 0}
    events = []

    def execution():
        obj = WindowsGuardExecution(
            session_id="s",
            tool_call_id="c",
            task_id="task",
            dll=tmp_path / "guard.dll",
            engine=lambda: engine,
            emit=None,
            approvals=RuntimeApprovalRequests(),
            delete_ledger=ledger,
            audit=events.append,
        )
        obj.job = SimpleNamespace(contains=lambda pid: pid == 17, close=lambda: None)
        obj.check_resource = AsyncMock(return_value=True)
        return obj

    first, second = execution(), execution()
    one, two, three = [str(uuid4()) for _ in range(3)]
    path = str(tmp_path / "target")
    assert await first.check_delete(17, one, path)
    assert not first.check_resource.call_args.args[1].get("bulk")
    assert ledger == {"success": 0, "reserved": 1}
    assert await first.check_delete(17, one, path, recheck=True)
    assert first.check_resource.await_count == 1
    assert not await first.check_delete(99, one, path, recheck=True)
    assert not await first.check_delete(17, one, path)
    engine.config["tools"] = {"bash": "allow"}
    assert await first.check_delete(17, one, path, recheck=True)
    assert first.check_resource.await_count == 2
    assert first.check_resource.call_args.kwargs["operation_id"] == one
    assert ledger == {"success": 0, "reserved": 1}
    assert first.report_operation_stage(17, one, "1,0,0")
    assert first.report_operation_stage(17, one, "1,0,0")
    assert not first.report_operation_stage(99, one, "1,0,0")
    assert len([e for e in events if e["kind"] == "operation_result"]) == 1
    assert await second.check_delete(17, two, path)
    assert second.check_resource.call_args.args[1].get("bulk", False) is (threshold == 1)
    assert not second.finish_delete(99, two, "1,0")
    assert second.finish_delete(17, two, "0,5")
    assert ledger == {"success": 0, "reserved": 1}
    assert first.finish_delete(17, one, "1,0")
    assert not first.finish_delete(17, one, "1,0")
    assert ledger == {"success": 1, "reserved": 0}
    assert await second.check_delete(17, three, path)
    assert second.check_resource.call_args.args[1].get("bulk", False) is (threshold == 1)
    if threshold == 1:
        engine.config["soft_delete"]["batch_delete_threshold"] = 0
        assert await second.check_delete(17, three, path, recheck=True)
        assert not second.check_resource.call_args.args[1].get("bulk")
    assert second.finish_delete(17, three, "-1,5")
    assert ledger == {"success": 1, "reserved": 1}
    assert not second.finish_delete(17, three, "1,0")
    unfinished = str(uuid4())
    assert await first.check_delete(17, unfinished, path)
    await first.close()
    await second.close()
    assert ledger == {"success": 1, "reserved": 0}
    assert [e["status"] for e in events if e["kind"] == "result"] == [
        "failed",
        "success",
        "unknown",
        "unknown",
    ]
    assert len([e for e in events if e["kind"] == "result" and e["operation_ids"] == [unfinished]]) == 1


@pytest.mark.asyncio
async def test_denied_delete_releases_its_task_reservation(tmp_path):
    ledger = {"success": 0, "reserved": 0}
    obj = WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=tmp_path / "guard.dll",
        engine=lambda: PermissionEngine({"enabled": False}),
        emit=None,
        approvals=RuntimeApprovalRequests(),
        delete_ledger=ledger,
    )
    obj.job = SimpleNamespace(contains=lambda pid: True, close=lambda: None)
    obj.check_resource = AsyncMock(return_value=False)
    assert not await obj.check_delete(17, str(uuid4()), str(tmp_path / "target"))
    assert ledger == {"success": 0, "reserved": 0}
    await obj.close()
