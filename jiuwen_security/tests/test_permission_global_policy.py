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


@pytest.mark.parametrize(
    "command",
    ["echo hi", "ls -la", "shutdown now", "echo `id`", "git reset --hard"],
)
def test_returns_the_same_decision_as_check_permission(command: str) -> None:
    checked, direct = _both(PermissionEngine(_CONFIG), "bash", {"command": command})

    assert direct == (checked.permission, checked.matched_rule)


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
