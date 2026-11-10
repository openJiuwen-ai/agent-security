# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""批量删除审批：软删除开启且数量达到阈值时返回 ASK。"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_shield.tool_permission.delguard.del_count import count_deletion_targets
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


@pytest.mark.parametrize("shell_type", ["auto", "powershell"])
def test_quoted_powershell_delete_list_counts_each_file(tmp_path, shell_type):
    targets = [tmp_path / "a.txt", tmp_path / "b.txt", tmp_path / "c.txt"]
    for target in targets:
        target.write_text("data", encoding="utf-8")
    command = "Remove-Item " + ",".join(f"'{target.as_posix()}'" for target in targets)
    count, paths = count_deletion_targets(command, shell_type, str(tmp_path))
    assert count == 3
    assert {Path(path).resolve() for path in paths} == set(targets)
    guard = DeletionGuard(permission_config={
        "soft_delete": {"enabled": True, "batch_delete_threshold": 3},
    }, workspace_root=str(tmp_path))
    result = guard.evaluate("powershell", {"command": command})
    assert result is not None
    assert result.permission is PermissionLevel.ASK
    assert result.reason == "本次操作将删除 3 个文件，达到阈值 3，需要确认"


def test_quoted_comma_in_delete_filename_is_one_target(tmp_path):
    target = tmp_path / "a,b.txt"
    target.write_text("data", encoding="utf-8")
    count, paths = count_deletion_targets(
        f"Remove-Item '{target.as_posix()}'", "powershell", str(tmp_path),
    )
    assert count == 1
    assert [Path(path).resolve() for path in paths] == [target]
