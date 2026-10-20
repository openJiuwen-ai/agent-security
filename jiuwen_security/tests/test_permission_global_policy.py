from __future__ import annotations

import asyncio

import pytest

from jiuwen_security import PermissionEngine, PermissionLevel

_CONFIG = {
    "tools": {"bash": "allow"},
    "shell_allowlist": None,
    "rules": [{"id": "ask-ls", "tools": ["bash"], "pattern": "re:^ls", "action": "ask"}],
}


def _both(engine: PermissionEngine, tool: str, args: dict):
    checked = asyncio.run(engine.check_permission(tool, args))
    direct = asyncio.run(engine.evaluate_global_policy_directly(tool, args))
    return checked, direct


@pytest.mark.parametrize("command", ["ls -la", "shutdown now"])
def test_raw_query_keeps_tiered_policy_decisions(command: str) -> None:
    checked, direct = _both(PermissionEngine(_CONFIG), "bash", {"command": command})

    assert direct == (checked.permission, checked.matched_rule)


@pytest.mark.parametrize("command", ["echo hi", "git reset --hard"])
def test_raw_query_reports_the_tiered_rule_when_execution_check_has_none(command: str) -> None:
    checked, direct = _both(PermissionEngine(_CONFIG), "bash", {"command": command})

    assert checked.permission is PermissionLevel.ALLOW
    assert checked.matched_rule is None
    assert direct == (PermissionLevel.ALLOW, "tools.bash")


def test_raw_query_skips_injection_execution_check() -> None:
    checked, direct = _both(PermissionEngine(_CONFIG), "bash", {"command": "echo `id`"})

    assert checked.permission is PermissionLevel.DENY
    assert checked.matched_rule == "backtick-command-substitution"
    assert direct[0] is PermissionLevel.ASK
    assert direct[1] is not None
    assert "backtick-command-substitution" not in direct[1]


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
