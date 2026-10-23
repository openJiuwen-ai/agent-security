from __future__ import annotations

import asyncio
from pathlib import Path

from agent_shield.tool_permission import PermissionEngine, PermissionLevel


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
