# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from agent_shield.tool_permission import PermissionLevel
from agent_shield.tool_permission.engine import PermissionEngine
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


def test_read_deny_only_keeps_explicit_read_deny_from_forcing_write_deny() -> None:
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
            {"file_guard": {**common, "read_deny_only": True}},
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


def test_read_deny_only_missing_axis_stays_ask() -> None:
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
        stable = _path_engine(workspace, {**common, "read_deny_only": True})
        asked = _run(stable.check_permission("write_file", {"path": target}))
        assert asked.permission is PermissionLevel.ASK
        current = _path_engine(workspace, common)
        denied = _run(current.check_permission("write_file", {"path": target}))
        assert denied.permission is PermissionLevel.DENY


def test_read_deny_only_glob_uses_pattern_as_path() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        outside = str(Path(workspace).parent / "outside-glob.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
        }
        stable = _path_engine(workspace, {**common, "read_deny_only": True})
        judged = _run(stable.check_permission("glob", {"pattern": outside, "path": workspace}))
        assert judged.permission is PermissionLevel.DENY
        assert judged.matched_rule != "file_guard:glob_pattern"
        current = _path_engine(workspace, common)
        rejected = _run(current.check_permission("glob", {"pattern": outside, "path": workspace}))
        assert rejected.matched_rule == "file_guard:glob_pattern"


def test_evaluate_component_reaches_read_deny_only_file_guard() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        secret = Path(workspace) / "secret"
        secret.mkdir()
        target = str(secret / "note.txt")
        engine = PermissionEngine({
            "file_guard": {
                "enabled": True,
                "read_deny_only": True,
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


def test_read_deny_only_powershell_is_not_a_path_shell() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        outside = str(Path(workspace).parent / "outside-ps.txt")
        common = {
            "enabled": True,
            "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
        }
        command = f"type {outside}"
        stable = _path_engine(workspace, {**common, "read_deny_only": True})
        skipped = _run(stable.check_permission("powershell", {"command": command}))
        assert skipped.permission is PermissionLevel.ALLOW
        current = _path_engine(workspace, common)
        denied = _run(current.check_permission("powershell", {"command": command}))
        assert denied.permission is PermissionLevel.DENY


def test_dev_null_redirect_write_is_allowed_by_builtin_path() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        engine = PermissionEngine({
            "package_builtin_rules": False,
            "shell_allowlist": None,
            "tools": {"bash": "allow"},
            "runtime": {"workspace_root": workspace},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "ask", "exec": "ask"},
                "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        })
        allowed = _run(engine.check_permission(
            "bash", {"command": "cat ./a 2>/dev/null", "shell_type": "bash"},
        ))
        assert allowed.permission is PermissionLevel.ALLOW
        outside = (Path(workspace).parent / "outside.log").as_posix()
        asked = _run(engine.check_permission(
            "bash", {"command": f"echo hi > {outside}", "shell_type": "bash"},
        ))
        assert asked.permission is PermissionLevel.ASK


def test_dev_null_allow_survives_composed_source_order() -> None:
    """The /dev/null discard-sink allow must hold in composed (stacked) mode too.

    Regression: the builtin allow rules carry no ``source``, so
    ``_resolve_composed`` used to skip them and fall back to ``defaults``,
    turning ``2>/dev/null`` into an ASK even though plain mode allowed it.
    """
    permissions = {
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "ask", "exec": "ask"},
        },
        "composition": {"source_order": ["user", "cloud", "builtin"]},
    }
    checker = build_file_guard_checker(permissions)
    assert checker is not None
    assert checker.evaluate_accesses([(Path("/dev/null"), "write")]) is None
    # An ordinary path still falls through to the composed defaults (ask).
    other = checker.evaluate_accesses([(Path("/tmp/other.log"), "write")])
    assert other is not None and other.permission is PermissionLevel.ASK


def test_dev_null_allow_survives_composed_without_builtin_layer() -> None:
    """Even when ``source_order`` omits ``builtin`` the discard sink stays allowed."""
    permissions = {
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "ask", "exec": "ask"},
        },
        "composition": {"source_order": ["user", "cloud"]},
    }
    checker = build_file_guard_checker(permissions)
    assert checker is not None
    assert checker.evaluate_accesses([(Path("/dev/null"), "write")]) is None


def test_unscoped_deny_is_not_reversed_in_composed_mode() -> None:
    """A ``paths`` entry without ``layer`` keeps DENY in composed mode.

    Regression: the unscoped branch only collected ALLOW rules, so an explicit
    deny was dropped and the composed verdict fell through to the builtin
    /dev/null allow -- i.e. composed mode was more permissive than plain mode.
    """
    target = Path("/dev/null").resolve()
    base = {
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{"path": str(target), "read": "deny", "write": "deny", "exec": "deny"}],
        },
    }
    plain = build_file_guard_checker(base)
    assert plain is not None
    plain_result = plain.evaluate_accesses([(target, "write")])
    assert plain_result is not None
    assert plain_result.permission is PermissionLevel.DENY

    composed = build_file_guard_checker(
        dict(base, composition={"source_order": ["user", "cloud", "builtin"]}),
    )
    assert composed is not None
    composed_result = composed.evaluate_accesses([(target, "write")])
    assert composed_result is not None
    assert composed_result.permission is PermissionLevel.DENY


def test_unscoped_ask_is_not_reversed_in_composed_mode() -> None:
    """A ``paths`` entry without ``layer`` keeps ASK instead of becoming ALLOW."""
    target = Path("/dev/null").resolve()
    base = {
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{"path": str(target), "read": "ask", "write": "ask", "exec": "ask"}],
        },
    }
    plain = build_file_guard_checker(base)
    assert plain is not None
    plain_result = plain.evaluate_accesses([(target, "write")])
    assert plain_result is not None
    assert plain_result.permission is PermissionLevel.ASK

    composed = build_file_guard_checker(
        dict(base, composition={"source_order": ["user", "cloud", "builtin"]}),
    )
    assert composed is not None
    result = composed.evaluate_accesses([(target, "write")])
    assert result is not None
    assert result.permission is PermissionLevel.ASK
