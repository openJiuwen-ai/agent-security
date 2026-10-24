# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from itertools import product

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.component import PermissionComponent
from agent_shield.tool_permission.routing import RouteInterest, SecurityTarget

_STRICTNESS_ORDER = [
    PermissionLevel.ALLOW,
    PermissionLevel.UNDETERMINED,
    PermissionLevel.ASK,
    PermissionLevel.DENY,
]


class _Stub:
    interests: tuple[RouteInterest, ...] | None = (RouteInterest(SecurityTarget.ALL),)

    def __init__(self, result: PermissionResult | None) -> None:
        self.result = result

    def configure(self, config: Mapping[str, object]) -> None:
        pass

    async def evaluate(self, tool_name, tool_args, *, route=None):
        return self.result


class _StubEngine(PermissionEngine):
    def __init__(self, *results: PermissionResult | None) -> None:
        self._stubs = tuple(_Stub(result) for result in results)
        super().__init__()

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        return self._stubs


def _merge(*results: PermissionResult | None) -> PermissionResult:
    engine = _StubEngine(*results)
    return asyncio.run(engine.check_permission("bash", {"command": "true"}))


def _check(config: dict, command: str, tool: str = "bash") -> PermissionResult:
    engine = PermissionEngine(config)
    return asyncio.run(engine.check_permission(tool, {"command": command}))


# --- R13: four levels and their strictness order -----------------------------------------


def test_permission_level_has_four_values() -> None:
    assert {level.value for level in PermissionLevel} == {
        "allow", "ask", "undetermined", "deny",
    }


@pytest.mark.parametrize(("first", "second"), list(product(_STRICTNESS_ORDER, repeat=2)))
def test_merge_returns_the_stricter_level(first: PermissionLevel, second: PermissionLevel) -> None:
    expected = max(first, second, key=_STRICTNESS_ORDER.index)
    result = _merge(PermissionResult(permission=first), PermissionResult(permission=second))
    assert result.permission is expected


def test_undetermined_is_returned_to_the_caller() -> None:
    result = _merge(PermissionResult(permission=PermissionLevel.UNDETERMINED, matched_rule="x"))
    assert result.permission is PermissionLevel.UNDETERMINED
    assert result.matched_rule == "x"


def test_undetermined_is_not_masked_by_allow_but_is_masked_by_ask_and_deny() -> None:
    undetermined = PermissionResult(permission=PermissionLevel.UNDETERMINED)
    assert _merge(PermissionResult(permission=PermissionLevel.ALLOW), undetermined).permission \
        is PermissionLevel.UNDETERMINED
    for stricter in (PermissionLevel.ASK, PermissionLevel.DENY):
        assert _merge(undetermined, PermissionResult(permission=stricter)).permission is stricter


def test_defaults_undetermined_reaches_the_caller_through_the_real_engine() -> None:
    result = _check({"defaults": {"*": "undetermined"}}, "ls -la")
    assert result.permission is PermissionLevel.UNDETERMINED
    assert result.matched_rule == "tiered_policy:defaults.*"


def test_tool_baseline_undetermined_reaches_the_caller() -> None:
    result = _check({"tools": {"bash": "undetermined"}}, "ls -la")
    assert result.permission is PermissionLevel.UNDETERMINED
    assert result.matched_rule == "tools.bash"


def test_rule_action_undetermined_reaches_the_caller() -> None:
    config = {
        "tools": {"bash": "allow"},
        "rules": [{"id": "r", "tools": ["bash"], "pattern": "re:^ls", "action": "undetermined"}],
    }
    assert _check(config, "ls -la").permission is PermissionLevel.UNDETERMINED


def test_undetermined_is_masked_by_ask_or_deny_subcommand_and_structure_floor() -> None:
    config = {"defaults": {"*": "undetermined"}}
    assert _check(config, "ls && sudo ls").permission is PermissionLevel.ASK
    assert _check(config, "ls && shutdown now").permission is PermissionLevel.DENY
    assert _check(config, "cat <<EOF").permission is PermissionLevel.ASK


# --- aggregation details ----------------------------------------------------------------


def test_equal_strictness_keeps_the_first_registered_components_rule() -> None:
    result = _merge(
        PermissionResult(permission=PermissionLevel.ASK, matched_rule="first"),
        PermissionResult(permission=PermissionLevel.ASK, matched_rule="second"),
    )
    assert result.matched_rule == "first"


def test_warnings_and_external_paths_from_all_components_are_kept() -> None:
    result = _merge(
        PermissionResult(permission=PermissionLevel.ALLOW, warnings=["w1"], external_paths=["/a"]),
        PermissionResult(permission=PermissionLevel.DENY, warnings=["w2"], external_paths=["/b"]),
    )
    assert result.permission is PermissionLevel.DENY
    assert result.warnings == ["w1", "w2"]
    assert result.external_paths == ["/a", "/b"]


def test_warning_only_result_does_not_change_the_level() -> None:
    result = _merge(
        PermissionResult(warnings=["hint"]),
        PermissionResult(permission=PermissionLevel.ALLOW),
    )
    assert result.permission is PermissionLevel.ALLOW
    assert result.warnings == ["hint"]


def test_warning_only_result_alone_never_allows() -> None:
    result = _merge(PermissionResult(warnings=["hint"]))
    assert result.permission is PermissionLevel.ASK
    assert result.warnings == ["hint"]


def test_components_returning_none_are_ignored() -> None:
    result = _merge(None, PermissionResult(permission=PermissionLevel.ALLOW), None)
    assert result.permission is PermissionLevel.ALLOW


def test_destructive_warning_rides_along_without_changing_the_level() -> None:
    config = {"tools": {"bash": "allow"}, "package_builtin_rules": False}
    with_warning = _check(config, "git reset --hard")
    without = _check(config, "ls")
    assert with_warning.warnings
    assert not without.warnings
    assert with_warning.permission is without.permission
