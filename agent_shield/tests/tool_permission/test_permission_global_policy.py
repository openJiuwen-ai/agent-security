# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel
from agent_shield.tool_permission import (
    register_meta_tool,
    unregister_meta_tool,
)
from agent_shield.tool_permission.engine import PermissionEngine

_CONFIG = {
    "tools": {"bash": "allow"},
    "shell_allowlist": None,
    "rules": [{"id": "ask-ls", "tools": ["bash"], "pattern": "re:^ls", "action": "ask"}],
}


def _both(engine: PermissionEngine, tool: str, args: dict):
    checked = asyncio.run(engine.check_permission(tool, args))
    direct = asyncio.run(engine.evaluate_global_policy_directly(tool, args))
    return checked, direct


@pytest.mark.parametrize(
    "command",
    ["echo hi", "ls -la", "shutdown now", "echo `id`", "git reset --hard"],
)
def test_returns_the_same_decision_as_check_permission(command: str) -> None:
    checked, direct = _both(PermissionEngine(_CONFIG), "bash", {"command": command})

    assert direct == (checked.permission, checked.matched_rule)


def test_equivalence_holds_for_registered_forwarder_envelopes() -> None:
    """等价契约覆盖注册转发器：global policy 直查不得退化为仅外层判定。

    外层 ``invoke_tool`` 不在 tools 配置走 defaults 放行（issue #6499 的绕过
    形态）；若本入口不展开，宿主经它拿到的就是外层 ALLOW，等于在
    check_permission 之外漏开一条同型旁路（检视意见：等价关系单侧打破）。
    """
    register_meta_tool(
        "invoke_tool",
        lambda args: (
            (args["tool_name"], args["arguments"])
            if isinstance(args.get("tool_name"), str)
            and args.get("tool_name", "").strip()
            and isinstance(args.get("arguments"), dict)
            else None
        ),
    )
    try:
        engine = PermissionEngine(
            {
                "package_builtin_rules": False,
                "defaults": {"*": "allow"},
                "tools": {"create_terminal": "deny"},
            }
        )
        envelope = {
            "tool_name": "create_terminal",
            "arguments": {"command": 'iex "Get-Process"'},
        }

        checked, direct = _both(engine, "invoke_tool", envelope)

        assert checked.permission is PermissionLevel.DENY
        assert direct == (checked.permission, checked.matched_rule)
    finally:
        unregister_meta_tool("invoke_tool")


@pytest.mark.parametrize("enabled", (True, False))
def test_raw_query_keeps_allowlist_denial_even_with_allow_tool_baseline(enabled: bool) -> None:
    engine = PermissionEngine(
        {
            "enabled": enabled,
            "tools": {"bash": "allow"},
            "shell_allowlist": ["echo"],
        }
    )
    assert asyncio.run(
        engine.evaluate_global_policy_directly("bash", {"command": "git status"})
    ) == (PermissionLevel.DENY, "shell_allowlist:not_allowed")


def test_returns_a_level_and_rule_tuple() -> None:
    level, rule = asyncio.run(
        PermissionEngine(_CONFIG).evaluate_global_policy_directly("bash", {"command": "ls"})
    )

    assert level is PermissionLevel.ASK
    assert rule is not None and "ask-ls" in rule


def test_undetermined_is_passed_through() -> None:
    engine = PermissionEngine({"defaults": {"*": "undetermined"}, "shell_allowlist": None})

    level, _ = asyncio.run(engine.evaluate_global_policy_directly("bash", {"command": "pwd"}))

    assert level is PermissionLevel.UNDETERMINED


def test_follows_config_updates() -> None:
    engine = PermissionEngine(_CONFIG)
    engine.update_config({**_CONFIG, "rules": []})

    level, _ = asyncio.run(engine.evaluate_global_policy_directly("bash", {"command": "ls"}))

    assert level is PermissionLevel.ALLOW


def test_rejects_invalid_arguments_like_check_permission() -> None:
    engine = PermissionEngine(_CONFIG)

    with pytest.raises(ValueError):
        asyncio.run(engine.evaluate_global_policy_directly(" ", {}))
    with pytest.raises(TypeError):
        asyncio.run(engine.evaluate_global_policy_directly("bash", ["x"]))  # type: ignore[arg-type]


# --- the engine-level ``enabled`` switch ---------------------------------------------------

_DENY_ALL = {"tools": {"bash": "deny"}, "shell_allowlist": None}


def _check(engine: PermissionEngine, command: str = "ls"):
    return asyncio.run(engine.check_permission("bash", {"command": command}))


def _direct(engine: PermissionEngine, command: str = "ls"):
    return asyncio.run(engine.evaluate_global_policy_directly("bash", {"command": command}))


def test_enabled_defaults_to_on() -> None:
    assert _check(PermissionEngine(_DENY_ALL)).permission is PermissionLevel.DENY


def test_explicit_enabled_true_checks_normally() -> None:
    engine = PermissionEngine({**_DENY_ALL, "enabled": True})

    assert _check(engine).permission is PermissionLevel.DENY


def test_disabled_check_permission_allows_without_running_components() -> None:
    engine = PermissionEngine({**_DENY_ALL, "enabled": False})

    result = _check(engine, "shutdown now")

    assert result.permission is PermissionLevel.ALLOW
    assert result.reason == "Permission system is disabled"
    assert result.matched_rule is None
    assert result.warnings == []


def test_evaluate_global_policy_directly_ignores_the_switch() -> None:
    engine = PermissionEngine({**_DENY_ALL, "enabled": False})

    level, rule = _direct(engine)

    assert level is PermissionLevel.DENY
    assert rule == "tools.bash"


def test_switch_can_be_toggled_by_update_config() -> None:
    engine = PermissionEngine(_DENY_ALL)

    engine.update_config({**_DENY_ALL, "enabled": False})
    assert _check(engine).permission is PermissionLevel.ALLOW

    engine.update_config(_DENY_ALL)
    assert _check(engine).permission is PermissionLevel.DENY


@pytest.mark.parametrize("bad", ["false", "true", 0, 1, None, [], {}])
def test_non_boolean_enabled_is_rejected_and_keeps_old_config(bad: object) -> None:
    engine = PermissionEngine({**_DENY_ALL, "enabled": False})

    with pytest.raises(ValueError, match="enabled"):
        engine.update_config({**_DENY_ALL, "enabled": bad})

    assert engine.config["enabled"] is False
    assert _check(engine).permission is PermissionLevel.ALLOW


@pytest.mark.parametrize("bad", ["false", 0, None])
def test_non_boolean_enabled_is_rejected_at_construction(bad: object) -> None:
    with pytest.raises(ValueError, match="enabled"):
        PermissionEngine({"enabled": bad})


def test_disabled_engine_still_validates_arguments() -> None:
    engine = PermissionEngine({"enabled": False})

    with pytest.raises(ValueError):
        asyncio.run(engine.check_permission("", {}))
    with pytest.raises(TypeError):
        asyncio.run(engine.check_permission("bash", ["x"]))  # type: ignore[arg-type]
