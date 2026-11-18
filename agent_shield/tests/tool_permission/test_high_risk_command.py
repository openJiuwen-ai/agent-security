# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.models import PermissionLevel, PermissionResult, RiskLevel


def _check(config: dict, command: str):
    return asyncio.run(
        PermissionEngine(config).check_permission("bash", {"command": command})
    )


_PATTERNS = [r"\brm\s+-[^\s]*[rf][^\s]*[rf]\b", r"\brm\s+.*--force\b"]


def _high_risk_on(**extra) -> dict:
    return {
        "package_builtin_rules": False,
        "high_risk_command": {
            "enabled": True,
            "patterns": list(_PATTERNS),
            **extra.get("high_risk_command", {}),
        },
        **{k: v for k, v in extra.items() if k != "high_risk_command"},
    }


def test_disabled_by_default_does_not_mark_high_risk() -> None:
    result = _check({"tools": {"bash": "ask"}, "package_builtin_rules": False}, "rm -rf /tmp/x")
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.NONE


def test_enabled_without_patterns_does_not_mark() -> None:
    result = _check(
        {
            "tools": {"bash": "ask"},
            "package_builtin_rules": False,
            "high_risk_command": {"enabled": True},
        },
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.NONE


def test_configured_pattern_marks_high() -> None:
    result = _check(
        {**_high_risk_on(), "tools": {"bash": "ask"}},
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_matching_is_case_insensitive() -> None:
    result = _check(
        {**_high_risk_on(), "tools": {"bash": "allow"}},
        "RM -RF /tmp/x",
    )
    # Case-insensitive pattern hit; allowlist may still DENY uppercase `RM`.
    assert result.risk_level is RiskLevel.HIGH


def test_enabled_leaves_safe_command_as_none() -> None:
    result = _check(
        {**_high_risk_on(), "tools": {"bash": "ask"}},
        "ls",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.NONE


def test_enabled_must_be_boolean() -> None:
    with pytest.raises(ValueError, match="high_risk_command.enabled must be a boolean"):
        PermissionEngine(
            {
                "package_builtin_rules": False,
                "high_risk_command": {"enabled": "true", "patterns": _PATTERNS},
            }
        )


def test_merge_keeps_strongest_risk_level() -> None:
    result = PermissionEngine.merge_results(
        [
            PermissionResult(permission=PermissionLevel.ALLOW, risk_level=RiskLevel.NONE),
            PermissionResult(permission=PermissionLevel.ASK, risk_level=RiskLevel.HIGH),
        ]
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_high_risk_hit_raises_allow_to_ask() -> None:
    result = _check(
        {**_high_risk_on(), "tools": {"bash": "allow"}},
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_master_off_without_always_on_skips_high_risk() -> None:
    result = _check(
        {
            "enabled": False,
            **_high_risk_on(),
        },
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ALLOW
    assert result.risk_level is RiskLevel.NONE


def test_master_off_with_always_on_hit_is_ask() -> None:
    result = _check(
        {
            "enabled": False,
            "always_on_components": ["high_risk_command"],
            **_high_risk_on(),
        },
        "rm -rf /tmp/x",
    )
    assert result.permission is PermissionLevel.ASK
    assert result.risk_level is RiskLevel.HIGH


def test_master_off_always_on_miss_is_allow() -> None:
    result = _check(
        {
            "enabled": False,
            "always_on_components": ["high_risk_command"],
            "tools": {"bash": "ask"},
            **_high_risk_on(),
        },
        "ls",
    )
    assert result.permission is PermissionLevel.ALLOW
    assert result.risk_level is RiskLevel.NONE
