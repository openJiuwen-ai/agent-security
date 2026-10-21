from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from jiuwen_security import PermissionEngine, PermissionLevel


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
