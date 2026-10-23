from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.component import PermissionComponent
from agent_shield.tool_permission.routing import RouteInterest, SecurityTarget

_BASE = {"tools": {"bash": "allow"}, "package_builtin_rules": False, "shell_allowlist": None}


def _check(engine: PermissionEngine, command: str) -> PermissionResult:
    return asyncio.run(engine.check_permission("bash", {"command": command}))


def _level(engine: PermissionEngine, command: str) -> PermissionLevel | None:
    return _check(engine, command).permission


# --- updates take effect and are whole-config replacements --------------------------------


def test_update_tool_baseline_takes_effect_immediately() -> None:
    engine = PermissionEngine(_BASE)
    assert _level(engine, "ls") is PermissionLevel.ALLOW

    engine.update_config({**_BASE, "tools": {"bash": "deny"}})

    assert _level(engine, "ls") is PermissionLevel.DENY


def test_update_defaults_takes_effect_and_removal_restores_the_default() -> None:
    engine = PermissionEngine({"package_builtin_rules": False})
    engine.update_config({"package_builtin_rules": False, "defaults": {"*": "undetermined"}})
    assert _level(engine, "ls") is PermissionLevel.UNDETERMINED

    engine.update_config({"package_builtin_rules": False})

    assert _level(engine, "ls") is not PermissionLevel.UNDETERMINED


def test_update_rules_takes_effect_and_removal_restores_baseline() -> None:
    rule = {"id": "no-ls", "tools": ["bash"], "pattern": "re:^ls", "action": "deny"}
    engine = PermissionEngine(_BASE)

    engine.update_config({**_BASE, "rules": [rule]})
    assert _level(engine, "ls") is PermissionLevel.DENY

    engine.update_config(_BASE)
    assert _level(engine, "ls") is PermissionLevel.ALLOW


def test_update_approval_overrides_takes_effect_and_removal_restores() -> None:
    rule = {"id": "no-ls", "tools": ["bash"], "pattern": "re:^ls", "action": "deny"}
    approval = {"id": "ok", "tools": ["bash"], "pattern": "re:^ls", "action": "allow"}
    engine = PermissionEngine({**_BASE, "rules": [rule]})
    assert _level(engine, "ls") is PermissionLevel.DENY

    engine.update_config({**_BASE, "rules": [rule], "approval_overrides": [approval]})
    assert _level(engine, "ls") is PermissionLevel.ALLOW

    engine.update_config({**_BASE, "rules": [rule]})
    assert _level(engine, "ls") is PermissionLevel.DENY


def test_update_guard_actions_takes_effect_and_removal_restores_ask(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_shield.tool_permission.toolguard import shell_ast

    monkeypatch.setattr(shell_ast, "_get_tree_sitter_bash_parser", lambda: None)
    engine = PermissionEngine(_BASE)
    assert _level(engine, "echo hi > f.txt") is PermissionLevel.ASK

    engine.update_config(
        {**_BASE, "guard_actions": {"parse_unavailable": "allow"}}
    )
    assert _level(engine, "echo hi > f.txt") is PermissionLevel.ALLOW

    engine.update_config(_BASE)
    assert _level(engine, "echo hi > f.txt") is PermissionLevel.ASK


def test_update_package_builtin_rules_switch() -> None:
    engine = PermissionEngine(_BASE)
    assert _level(engine, "shutdown now") is PermissionLevel.ALLOW

    engine.update_config({**_BASE, "package_builtin_rules": True})

    assert _level(engine, "shutdown now") is PermissionLevel.DENY


def test_update_with_already_processed_config_is_idempotent() -> None:
    engine = PermissionEngine({"tools": {"bash": "allow"}, "shell_allowlist": None})
    before = _check(engine, "shutdown now")

    engine.update_config(engine.config)
    engine.update_config(engine.config)

    after = _check(engine, "shutdown now")
    assert (after.permission, after.matched_rule) == (before.permission, before.matched_rule)


def test_update_config_rejects_non_mapping_and_keeps_state() -> None:
    engine = PermissionEngine(_BASE)

    with pytest.raises(TypeError):
        engine.update_config(["not", "a", "mapping"])  # type: ignore[arg-type]

    assert _level(engine, "ls") is PermissionLevel.ALLOW
    assert dict(engine.config) == _BASE


# --- failed update leaves the old state untouched (build new, then swap) ------------------


class _Stub:
    interests: tuple[RouteInterest, ...] | None = (RouteInterest(SecurityTarget.ALL),)

    def __init__(self, level: PermissionLevel) -> None:
        self.level = level
        self.configured: Mapping[str, Any] | None = None

    def configure(self, config: Mapping[str, Any]) -> None:
        if config.get("boom") == self.level.value:
            raise ValueError("bad config")
        self.configured = config

    async def evaluate(self, tool_name, tool_args, *, route=None):
        return PermissionResult(permission=self.level, matched_rule=self.level.value)


class _FreshEngine(PermissionEngine):
    """Builds a brand-new component set on every (re)configuration."""

    built: list[tuple[_Stub, ...]]

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        if not hasattr(self, "built"):
            self.built = []
        stubs = (_Stub(PermissionLevel.ALLOW), _Stub(PermissionLevel.ASK))
        self.built.append(stubs)
        return stubs


def test_update_builds_new_components_and_swaps_them_in() -> None:
    engine = _FreshEngine({"v": 1})
    old = engine.built[-1]

    engine.update_config({"v": 2})

    new = engine.built[-1]
    assert new is not old
    assert all(component.configured == {"v": 2} for component in new)
    assert engine._components is new


def test_failed_update_keeps_old_components_config_and_decisions() -> None:
    engine = _FreshEngine({"v": 1})
    old = engine.built[-1]
    old_snapshot = [c.configured for c in old]

    # The second (ASK) component fails after the first one was already configured.
    with pytest.raises(ValueError, match="bad config"):
        engine.update_config({"v": 2, "boom": "ask"})

    assert engine._components is old
    assert dict(engine.config) == {"v": 1}
    assert [c.configured for c in old] == old_snapshot
    assert _level(engine, "ls") is PermissionLevel.ASK


def test_failed_update_on_real_engine_keeps_old_decisions() -> None:
    engine = PermissionEngine(_BASE)

    with pytest.raises(TypeError):
        engine.update_config({**_BASE, "tools": {"bash": "deny"}, "shell_allowlist": 123})

    assert dict(engine.config) == _BASE
    assert _level(engine, "ls") is PermissionLevel.ALLOW


def test_engine_still_updatable_after_a_failed_update() -> None:
    engine = _FreshEngine({"v": 1})
    with pytest.raises(ValueError):
        engine.update_config({"v": 2, "boom": "allow"})

    engine.update_config({"v": 3})

    assert dict(engine.config) == {"v": 3}


def test_invalid_construction_config_raises() -> None:
    with pytest.raises(ValueError):
        _FreshEngine({"boom": "allow"})


def test_in_flight_call_keeps_the_components_it_started_with() -> None:
    class Slow(_Stub):
        gate: asyncio.Event
        entered: asyncio.Event

        async def evaluate(self, tool_name, tool_args, *, route=None):
            self.entered.set()
            await self.gate.wait()
            return await super().evaluate(tool_name, tool_args, route=route)

    class SlowEngine(PermissionEngine):
        generation = 0

        def _build_components(self) -> tuple[PermissionComponent, ...]:
            SlowEngine.generation += 1
            if SlowEngine.generation == 1:
                return (Slow(PermissionLevel.DENY),)
            return (_Stub(PermissionLevel.ALLOW),)

    async def scenario() -> tuple[PermissionLevel | None, PermissionLevel | None]:
        engine = SlowEngine({})
        slow = engine._components[0]
        assert isinstance(slow, Slow)
        slow.gate, slow.entered = asyncio.Event(), asyncio.Event()

        in_flight = asyncio.create_task(engine.check_permission("bash", {"command": "ls"}))
        await slow.entered.wait()
        engine.update_config({"v": 2})
        after_swap = (await engine.check_permission("bash", {"command": "ls"})).permission
        slow.gate.set()
        before_swap = (await in_flight).permission
        return before_swap, after_swap

    SlowEngine.generation = 0
    assert asyncio.run(scenario()) == (PermissionLevel.DENY, PermissionLevel.ALLOW)


# --- no aliasing with the caller's dict ---------------------------------------------------


def test_mutating_the_callers_dict_after_update_has_no_effect() -> None:
    engine = PermissionEngine(_BASE)
    config = {**_BASE, "tools": {"bash": "allow"}}
    engine.update_config(config)

    config["tools"]["bash"] = "deny"

    assert engine.config["tools"]["bash"] == "allow"
    assert _level(engine, "ls") is PermissionLevel.ALLOW


def test_mutating_the_callers_dict_after_construction_has_no_effect() -> None:
    config = {**_BASE, "tools": {"bash": "allow"}}
    engine = PermissionEngine(config)

    config["tools"]["bash"] = "deny"

    assert engine.config["tools"]["bash"] == "allow"
    assert _level(engine, "ls") is PermissionLevel.ALLOW
