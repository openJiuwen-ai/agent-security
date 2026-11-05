# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""批量删除审批：软删除开启且数量达到阈值时返回 ASK。"""

from __future__ import annotations

from pathlib import Path

from agent_shield.tool_permission.delguard.deletion_guard import DeletionGuard
from agent_shield.tool_permission.models import PermissionLevel


def test_disabled_soft_delete_does_not_vote(tmp_path: Path) -> None:
    guard = DeletionGuard(
        permission_config={"soft_delete": {"enabled": False, "batch_delete_threshold": 1}},
        workspace_root=str(tmp_path),
    )
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    assert guard.evaluate("bash", {"command": "rm a.txt"}) is None


def test_threshold_asks_with_del_guard_rule(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    (tmp_path / "b.txt").write_text("b", encoding="utf-8")
    guard = DeletionGuard(
        permission_config={
            "soft_delete": {"enabled": True, "batch_delete_threshold": 2},
        },
        workspace_root=str(tmp_path),
    )
    result = guard.evaluate("bash", {"command": "rm a.txt b.txt"})
    assert result is not None
    assert result.permission == PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"
    assert result.reason is not None
    assert "2" in result.reason


def test_below_threshold_returns_none(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    guard = DeletionGuard(
        permission_config={
            "soft_delete": {"enabled": True, "batch_delete_threshold": 100},
        },
        workspace_root=str(tmp_path),
    )
    assert guard.evaluate("bash", {"command": "rm a.txt"}) is None


def test_zero_threshold_disables_counting(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a", encoding="utf-8")
    guard = DeletionGuard(
        permission_config={
            "soft_delete": {"enabled": True, "batch_delete_threshold": 0},
        },
        workspace_root=str(tmp_path),
    )
    assert guard.evaluate("bash", {"command": "rm a.txt"}) is None
