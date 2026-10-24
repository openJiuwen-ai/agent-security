# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from agent_shield.tool_permission import PermissionEngine, PermissionLevel
from agent_shield.tool_permission.fileguard.file_guard import build_file_guard_checker


def _run(awaitable):
    return asyncio.run(awaitable)


def test_file_guard_denies_outside_workspace() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        engine = PermissionEngine({
            "file_guard": {
                    "enabled": True,
                    "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
                    "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
                },
            "runtime": {"workspace_root": workspace},
            "package_builtin_rules": False,
            "tools": {"read_file": "allow"},
        })
        outside = str(Path(workspace).parent / "outside-secret.txt")
        result = _run(engine.check_permission("read_file", {"path": outside}))
        assert result.permission is PermissionLevel.DENY
        assert result.matched_rule is not None
        assert "file_guard" in result.matched_rule


def _path_engine(workspace: str, file_guard: dict, tools: dict | None = None) -> PermissionEngine:
    return PermissionEngine({
        "file_guard": file_guard,
        "runtime": {"workspace_root": workspace},
        "package_builtin_rules": False,
        "tools": tools or {"write_file": "allow", "glob": "allow", "powershell": "allow"},
    })


def test_dev_stable_keeps_explicit_read_deny_from_forcing_write_deny() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        secret = Path(workspace) / "secret"
        secret.mkdir()
        target = str(secret / "note.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "ask", "write": "ask", "exec": "ask"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{
                "path": str(secret),
                "read": "deny",
                "write": "allow",
                "exec": "allow",
            }],
        }
        stable = build_file_guard_checker(
            {"file_guard": {**common, "dev_stable": True}},
            workspace_root=Path(workspace),
        )
        assert stable is not None
        assert stable.evaluate("write_file", {"path": target}) is None
        current = build_file_guard_checker(
            {"file_guard": common},
            workspace_root=Path(workspace),
        )
        assert current is not None
        denied = current.evaluate("write_file", {"path": target})
        assert denied is not None
        assert denied.permission is PermissionLevel.DENY


def test_dev_stable_missing_axis_stays_ask() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        secret = Path(workspace) / "secret"
        secret.mkdir()
        target = str(secret / "note.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{"path": str(secret), "read": "allow"}],
        }
        stable = _path_engine(workspace, {**common, "dev_stable": True})
        asked = _run(stable.check_permission("write_file", {"path": target}))
        assert asked.permission is PermissionLevel.ASK
        current = _path_engine(workspace, common)
        denied = _run(current.check_permission("write_file", {"path": target}))
        assert denied.permission is PermissionLevel.DENY


def test_dev_stable_glob_uses_pattern_as_path() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        outside = str(Path(workspace).parent / "outside-glob.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
        }
        stable = _path_engine(workspace, {**common, "dev_stable": True})
        judged = _run(stable.check_permission("glob", {"pattern": outside, "path": workspace}))
        assert judged.permission is PermissionLevel.DENY
        assert judged.matched_rule != "file_guard:glob_pattern"
        current = _path_engine(workspace, common)
        rejected = _run(current.check_permission("glob", {"pattern": outside, "path": workspace}))
        assert rejected.matched_rule == "file_guard:glob_pattern"


def test_evaluate_component_reaches_dev_stable_file_guard() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        secret = Path(workspace) / "secret"
        secret.mkdir()
        target = str(secret / "note.txt")
        engine = PermissionEngine({
            "file_guard": {
                "enabled": True,
                "dev_stable": True,
                "defaults": {"read": "ask", "write": "ask", "exec": "ask"},
                "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{
                    "path": str(secret),
                    "read": "deny",
                    "write": "allow",
                    "exec": "allow",
                }],
            },
            "runtime": {"workspace_root": workspace, "trusted_dirs": []},
            "package_builtin_rules": False,
        })
        assert engine.component_active("file_guard") is True
        result = engine.evaluate_component("file_guard", "write_file", {"path": target})
        assert result is None


def test_dev_stable_powershell_is_not_a_path_shell() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        outside = str(Path(workspace).parent / "outside-ps.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
        }
        command = f"type {outside}"
        stable = _path_engine(workspace, {**common, "dev_stable": True})
        skipped = _run(stable.check_permission("powershell", {"command": command}))
        assert skipped.permission is PermissionLevel.ALLOW
        current = _path_engine(workspace, common)
        denied = _run(current.check_permission("powershell", {"command": command}))
        assert denied.permission is PermissionLevel.DENY
