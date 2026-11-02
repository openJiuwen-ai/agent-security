# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel
from agent_shield.tool_permission.hostguard.safety import _loose_parse_worktree_target


def _run(awaitable):
    return asyncio.run(awaitable)


def test_host_guard_blocks_jiuwenswarm_kill() -> None:
    engine = PermissionEngine({
        "host_guard": {"enabled": True},
        "runtime": {"workspace_root": str(Path.cwd())},
        "tools": {"bash": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _run(engine.check_permission("bash", {"command": "pkill -f jiuwenswarm"}))
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "host_guard:safety"


def test_host_guard_blocks_mcp_exec_kill_without_worktree() -> None:
    engine = PermissionEngine({
        "host_guard": {"enabled": True},
        "runtime": {"workspace_root": str(Path.cwd())},
        "tools": {"mcp_exec_command": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _run(engine.check_permission("mcp_exec_command", {"command": "pkill -f jiuwenswarm"}))
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "host_guard:safety"


def test_develop_profile_python_name_kill() -> None:
    engine = PermissionEngine({
        "host_guard": {
                "enabled": True,
                "python_name_kill": True,
            },
        "runtime": {"workspace_root": str(Path.cwd())},
        "tools": {"bash": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _run(engine.check_permission("bash", {"command": "taskkill /IM python.exe /F"}))
    assert result.permission is PermissionLevel.DENY


def _engine(
    host_guard: dict,
    root: Path | None = None,
    runtime: dict | None = None,
) -> PermissionEngine:
    merged = {"workspace_root": str(root or Path.cwd())}
    if runtime:
        merged.update(runtime)
    return PermissionEngine({
        "host_guard": host_guard,
        "runtime": merged,
        "tools": {"bash": "allow", "powershell": "allow", "mcp_exec_command": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })


def _self_parent_guard() -> dict:
    """dev-stable: image-name kills, self/parent pid, no segment rules."""

    return {
        "enabled": True,
        "shell_mismatch": False,
        "python_name_kill": False,
        "process_image_kill": True,
        "segment_guard": False,
        "join_continuations": False,
        "pid_kill": "self_parent",
        "worktree_parser": "loose",
    }


def test_process_image_kill_blocks_node_and_keeps_im_reason() -> None:
    engine = _engine(_self_parent_guard())
    node = _run(engine.check_permission("bash", {"command": "taskkill /IM node.exe /F"}))
    assert node.permission is PermissionLevel.DENY
    assert node.matched_rule == "host_guard:safety"
    assert node.reason == "blocked pattern: taskkill /im targeting agent/host runtime"
    python_name = _run(engine.check_permission("powershell", {"command": "Stop-Process -Name python"}))
    assert python_name.permission is PermissionLevel.DENY
    assert python_name.reason == (
        "blocked pattern: Stop-Process -Name targeting agent/host runtime"
    )


def test_process_image_kill_stays_off_for_node_and_unnamed_pipeline() -> None:
    engine = _engine({"enabled": True, "shell_mismatch": False, "python_name_kill": True})
    node = _run(engine.check_permission("bash", {"command": "taskkill /IM node.exe /F"}))
    assert node.matched_rule != "host_guard:safety"
    unnamed = _run(engine.check_permission("powershell", {"command": "Get-Process | Stop-Process"}))
    assert unnamed.matched_rule != "host_guard:safety"
    python_im = _run(engine.check_permission("bash", {"command": "taskkill /IM python.exe /F"}))
    assert python_im.permission is PermissionLevel.DENY
    assert "host python interpreter" in (python_im.reason or "")


def test_self_parent_blocks_current_pid_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getpid", lambda: 4242,
    )
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getppid", lambda: 1,
    )
    engine = _engine(_self_parent_guard())
    blocked = _run(engine.check_permission("bash", {"command": "taskkill /PID 4242 /F"}))
    assert blocked.permission is PermissionLevel.DENY
    assert blocked.matched_rule == "host_guard:safety"
    assert blocked.reason == "blocked pattern: taskkill targeting current agent/host process"
    other = _run(engine.check_permission("bash", {"command": "taskkill /PID 99999 /F"}))
    assert other.matched_rule != "host_guard:safety"
    spelled = _run(engine.check_permission("bash", {"command": "kill -9 4242"}))
    assert spelled.matched_rule != "host_guard:safety"


def test_pid_kill_off_allows_current_pid(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getpid", lambda: 4242,
    )
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getppid", lambda: 1,
    )
    engine = _engine({"enabled": True, "shell_mismatch": False, "pid_kill": "off"})
    result = _run(engine.check_permission("bash", {"command": "taskkill /PID 4242 /F"}))
    assert result.matched_rule != "host_guard:safety"


def test_backend_pid_kill_uses_the_wider_set(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety._backend_pids",
        lambda: {4242, 7777},
    )
    engine = _engine({
        "enabled": True,
        "shell_mismatch": False,
        "pid_kill": "backend",
    })
    blocked = _run(engine.check_permission("bash", {"command": "kill 7777"}))
    assert blocked.permission is PermissionLevel.DENY
    assert blocked.reason is not None
    assert "7777" in blocked.reason
    assert "JiuwenSwarm backend" in blocked.reason
    other = _run(engine.check_permission("bash", {"command": "kill 1"}))
    assert other.matched_rule != "host_guard:safety"

    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getpid", lambda: 4242,
    )
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.safety.os.getppid", lambda: 1,
    )
    narrow = _engine(_self_parent_guard())
    missed = _run(narrow.check_permission("bash", {"command": "kill 7777"}))
    assert missed.matched_rule != "host_guard:safety"


def test_callers_keep_shell_mismatch_and_product_kills() -> None:
    stable = _engine(_self_parent_guard())
    kill_claw = _run(stable.check_permission("bash", {"command": "kill jiuwenclaw"}))
    assert kill_claw.matched_rule != "host_guard:safety"
    plain_python = _run(stable.check_permission("bash", {"command": "kill python"}))
    assert plain_python.matched_rule != "host_guard:safety"
    mismatch = _run(stable.check_permission("bash", {"command": "Get-ChildItem"}))
    assert mismatch.matched_rule != "host_guard:shell_mismatch"
    destructive = _run(stable.check_permission("bash", {"command": "rm -rf /tmp/example"}))
    assert destructive.matched_rule != "host_guard:safety"

    xiaoyi = _engine({"enabled": True})
    blocked = _run(xiaoyi.check_permission("bash", {"command": "Get-ChildItem"}))
    assert blocked.matched_rule == "host_guard:shell_mismatch"


def test_dev_stable_does_not_join_continuations() -> None:
    engine = _engine(_self_parent_guard())
    split = _run(engine.check_permission("bash", {"command": "pkill \\\n-f jiuwenswarm"}))
    assert split.matched_rule != "host_guard:safety"
    quoted = _run(engine.check_permission("bash", {"command": 'echo "kill jiuwenclaw"'}))
    assert quoted.matched_rule != "host_guard:safety"


def test_default_host_guard_still_blocks_kill_jiuwenclaw() -> None:
    engine = PermissionEngine({
        "host_guard": {"enabled": True},
        "runtime": {"workspace_root": str(Path.cwd())},
        "tools": {"bash": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _run(engine.check_permission("bash", {"command": "kill jiuwenclaw"}))
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "host_guard:safety"


def test_dev_stable_worktree_uses_the_loose_parser() -> None:
    with tempfile.TemporaryDirectory() as project:
        engine = _engine(_self_parent_guard(), Path(project))
        echoed = _run(engine.check_permission(
            "bash", {"command": "echo worktree add ../outside-worktree"},
        ))
        assert echoed.permission is PermissionLevel.DENY
        assert "Do NOT use `../`" in (echoed.reason or "")
        blocked = _run(engine.check_permission(
            "bash", {"command": "git worktree add ../outside-worktree"},
        ))
        assert blocked.permission is PermissionLevel.DENY
        assert blocked.matched_rule == "host_guard:safety"
        assert "refused path outside the project" in (blocked.reason or "")
        unparsed = _run(engine.check_permission(
            "bash", {"command": "git worktree add"},
        ))
        assert unparsed.matched_rule != "host_guard:safety"
        inside = _run(engine.check_permission(
            "bash", {"command": "git worktree add .worktrees/feature -b feature HEAD"},
        ))
        assert inside.matched_rule != "host_guard:safety"
        mcp = _run(engine.check_permission(
            "mcp_exec_command", {"command": "git worktree add ../outside-worktree"},
        ))
        assert mcp.matched_rule != "host_guard:safety"
        assert _loose_parse_worktree_target(
            "git worktree add ..\\..\\outside",
        ) == "..\\..\\outside"
        if os.name == "nt":
            windows_parent = _run(engine.check_permission(
                "bash", {"command": "git worktree add ..\\..\\outside"},
            ))
            assert windows_parent.permission is PermissionLevel.DENY
            assert "refused path outside the project" in (windows_parent.reason or "")


def test_default_worktree_stays_strict() -> None:
    with tempfile.TemporaryDirectory() as project:
        engine = _engine(
            {"enabled": True, "shell_mismatch": False},
            Path(project),
        )
        echoed = _run(engine.check_permission(
            "bash", {"command": "echo worktree add ../outside-worktree"},
        ))
        assert echoed.matched_rule != "host_guard:safety"
        unparsed = _run(engine.check_permission(
            "bash", {"command": "git worktree add"},
        ))
        assert unparsed.reason == "worktree add could not be parsed; refused"


def test_self_parent_uses_caller_protected_pids() -> None:
    engine = PermissionEngine({
        "host_guard": {
            "enabled": True,
            "shell_mismatch": False,
            "pid_kill": "self_parent",
            "worktree_guard": False,
        },
        "runtime": {"protected_pids": ["30472"]},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    injected = engine.evaluate_component("host_guard", "bash", {"command": "echo $(date)"})
    assert injected is None
    blocked = engine.evaluate_component(
        "host_guard", "bash", {"command": "Stop-Process -Id 30472 -Force"},
    )
    assert blocked is not None
    assert blocked.permission is PermissionLevel.DENY
    assert blocked.matched_rule == "host_guard:safety"
    assert blocked.reason == (
        "blocked pattern: Stop-Process targeting current agent/host process"
    )
    other = engine.evaluate_component(
        "host_guard", "bash", {"command": "Stop-Process -Id 1 -Force"},
    )
    assert other is None


def test_removed_pid_switches_are_rejected() -> None:
    engine = _engine({"enabled": True})
    with pytest.raises(ValueError, match="whole_line_regex"):
        engine.update_config({
            "host_guard": {"enabled": True, "whole_line_regex": True},
            "package_builtin_rules": False,
            "shell_allowlist": None,
        })
    with pytest.raises(ValueError, match="backend_pid_kill"):
        engine.update_config({
            "host_guard": {"enabled": True, "backend_pid_kill": True},
            "package_builtin_rules": False,
            "shell_allowlist": None,
        })
    with pytest.raises(ValueError, match="pid_kill"):
        engine.update_config({
            "host_guard": {"enabled": True, "pid_kill": "parents"},
            "package_builtin_rules": False,
            "shell_allowlist": None,
        })
    with pytest.raises(ValueError, match="worktree_parser"):
        engine.update_config({
            "host_guard": {"enabled": True, "worktree_parser": "fuzzy"},
            "package_builtin_rules": False,
            "shell_allowlist": None,
        })
    assert engine.config["host_guard"]["enabled"] is True


def test_host_guard_reads_cmd_when_command_is_absent() -> None:
    engine = PermissionEngine({
        "host_guard": {"enabled": True},
        "tools": {"bash": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _run(engine.check_permission("bash", {"cmd": "pkill -f jiuwenswarm"}))
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "host_guard:safety"
