# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio

from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.models import PermissionLevel, PermissionResult, RiskLevel


def _check(config: dict, command: str):
    return asyncio.run(
        PermissionEngine(config).check_permission("bash", {"command": command})
    )


def test_disabled_by_default_does_not_mark_high_risk() -> None:
    result = _check({"tools": {"bash": "ask"}, "package_builtin_rules": False}, "rm -rf /tmp/x")
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.NONE


def test_enabled_marks_builtin_rm_rf_as_high() -> None:
    result = _check(
        {
            "tools": {"bash": "ask"},
            "package_builtin_rules": False,
            "high_risk_command": {"enabled": True},
        },
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_enabled_leaves_safe_command_as_none() -> None:
    result = _check(
        {
            "tools": {"bash": "ask"},
            "package_builtin_rules": False,
            "high_risk_command": {"enabled": True},
        },
        "ls",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.NONE


def test_custom_patterns_override_builtin() -> None:
    result = _check(
        {
            "tools": {"bash": "ask"},
            "package_builtin_rules": False,
            "high_risk_command": {
                "enabled": True,
                "patterns": [r"\bshutdown\b"],
            },
        },
        "rm -rf /tmp/x",
    )
    assert result.risk_level is RiskLevel.NONE

    hit = _check(
        {
            "tools": {"bash": "ask"},
            "package_builtin_rules": False,
            "high_risk_command": {
                "enabled": True,
                "patterns": [r"\bshutdown\b"],
            },
        },
        "shutdown -h now",
    )
    assert hit.risk_level is RiskLevel.HIGH


def test_merge_keeps_strongest_risk_level() -> None:
    result = PermissionEngine.merge_results(
        [
            PermissionResult(permission=PermissionLevel.ASK, risk_level=RiskLevel.NONE),
            PermissionResult(risk_level=RiskLevel.HIGH),
        ]
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_high_risk_does_not_change_allow_level() -> None:
    result = _check(
        {
            "tools": {"bash": "allow"},
            "package_builtin_rules": False,
            "high_risk_command": {"enabled": True},
        },
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ALLOW
    assert result.risk_level is RiskLevel.HIGH
