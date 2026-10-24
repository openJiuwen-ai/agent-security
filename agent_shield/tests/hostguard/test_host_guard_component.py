# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
import tempfile
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


def _dev_stable_engine(root: Path | None = None) -> PermissionEngine:
    runtime = {"workspace_root": str(root or Path.cwd())}
    return PermissionEngine({
        "host_guard": {"enabled": True, "dev_stable": True, "python_name_kill": True},
        "runtime": runtime,
        "tools": {"bash": "allow", "powershell": "allow", "mcp_exec_command": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })


def test_dev_stable_blocks_node_and_python_name_kills() -> None:
    engine = _dev_stable_engine()
    node = _run(engine.check_permission("bash", {"command": "taskkill /IM node.exe /F"}))
    assert node.permission is PermissionLevel.DENY
    assert node.matched_rule == "host_guard:dev_stable"
    python_name = _run(engine.check_permission("powershell", {"command": "Stop-Process -Name python"}))
    assert python_name.permission is PermissionLevel.DENY
    assert "Stop-Process -Name" in (python_name.reason or "")


def test_dev_stable_blocks_current_pid_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.dev_stable.os.getpid", lambda: 4242,
    )
    monkeypatch.setattr(
        "agent_shield.tool_permission.hostguard.dev_stable.os.getppid", lambda: 1,
    )
    engine = _dev_stable_engine()
    blocked = _run(engine.check_permission("bash", {"command": "taskkill /PID 4242 /F"}))
    assert blocked.permission is PermissionLevel.DENY
    assert blocked.matched_rule == "host_guard:dev_stable"
    other = _run(engine.check_permission("bash", {"command": "taskkill /PID 99999 /F"}))
    assert other.matched_rule != "host_guard:dev_stable"


def test_dev_stable_skips_later_branch_checks() -> None:
    engine = _dev_stable_engine()
    kill_other_name = _run(engine.check_permission("bash", {"command": "kill jiuwenclaw"}))
    assert kill_other_name.matched_rule != "host_guard:dev_stable"
    mismatch = _run(engine.check_permission("bash", {"command": "Get-ChildItem"}))
    assert mismatch.matched_rule != "host_guard:shell_mismatch"
    destructive = _run(engine.check_permission("bash", {"command": "rm -rf /tmp/example"}))
    assert destructive.matched_rule != "host_guard:dev_stable"


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


def test_dev_stable_worktree_uses_loose_parser() -> None:
    with tempfile.TemporaryDirectory() as project:
        engine = _dev_stable_engine(Path(project))
        blocked = _run(engine.check_permission(
            "bash", {"command": "echo worktree add ../outside-worktree"},
        ))
        assert blocked.permission is PermissionLevel.DENY
        assert blocked.matched_rule == "host_guard:dev_stable"
        assert "refused path outside the project" in (blocked.reason or "")
        inside = _run(engine.check_permission(
            "bash", {"command": "git worktree add .worktrees/feature -b feature HEAD"},
        ))
        assert inside.matched_rule != "host_guard:dev_stable"
        mcp = _run(engine.check_permission(
            "mcp_exec_command", {"command": "git worktree add ../outside-worktree"},
        ))
        assert mcp.matched_rule != "host_guard:dev_stable"


def test_evaluate_component_uses_dev_stable_host_only() -> None:
    engine = PermissionEngine({
        "host_guard": {
            "enabled": True,
            "dev_stable": True,
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
    assert blocked.matched_rule == "host_guard:dev_stable"
    other = engine.evaluate_component(
        "host_guard", "bash", {"command": "Stop-Process -Id 1 -Force"},
    )
    assert other is None


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
