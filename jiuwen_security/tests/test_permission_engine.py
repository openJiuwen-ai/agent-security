from __future__ import annotations

import asyncio
from collections.abc import Mapping
from typing import Any

import pytest

from jiuwen_security import PermissionEngine, PermissionLevel, PermissionResult
from jiuwen_security.policy.component import PermissionComponent
from jiuwen_security.policy.routing import CommandDialect, RouteInterest, SecurityTarget


class ResultComponent:
    interests = None
    def __init__(self, result: PermissionResult) -> None:
        self.result = result
        self.configured: list[dict[str, object]] = []

    def configure(self, config: Mapping[str, object]) -> None:
        self.configured.append(dict(config))

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
    ) -> PermissionResult:
        return self.result


class RouteComponent(ResultComponent):
    interests = (RouteInterest(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL),)

    def __init__(self, result: PermissionResult) -> None:
        super().__init__(result)
        self.routes = []

    async def evaluate(self, tool_name, tool_args, route=None):
        self.routes.append(route)
        return self.result


class ComponentEngine(PermissionEngine):
    def __init__(self, component: ResultComponent, config=None) -> None:
        self.component = component
        super().__init__(config)

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        return (self.component,)


def test_engine_exports_and_safe_empty_default() -> None:
    engine = PermissionEngine()

    result = asyncio_run(engine.check_permission("bash", {}))

    assert result.permission is PermissionLevel.ASK


def asyncio_run(awaitable):
    return asyncio.run(awaitable)


def test_component_is_configured_on_init_and_refresh() -> None:
    component = ResultComponent(PermissionResult(permission=PermissionLevel.ALLOW))
    engine = ComponentEngine(component, {"version": 1})

    assert component.configured == [{"version": 1}]

    engine.update_config({"version": 2})

    assert component.configured == [{"version": 1}, {"version": 2}]


def test_component_results_are_aggregated() -> None:
    component = ResultComponent(
        PermissionResult(
            permission=PermissionLevel.DENY,
            matched_rule="test-rule",
            warnings=["warning"],
            external_paths=["/tmp/example"],
        )
    )
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("bash", {"command": "true"}))

    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "test-rule"
    assert result.warnings == ["warning"]
    assert result.external_paths == ["/tmp/example"]


def test_invalid_input_is_rejected() -> None:
    engine = PermissionEngine()

    with pytest.raises(ValueError):
        asyncio_run(engine.check_permission("", {}))
    with pytest.raises(TypeError):
        asyncio_run(engine.check_permission("bash", []))  # type: ignore[arg-type]


def test_route_aware_component_receives_matching_route() -> None:
    component = RouteComponent(PermissionResult(permission=PermissionLevel.DENY))
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("bash", {"command": "echo hi"}))

    assert result.permission is PermissionLevel.DENY
    assert component.routes[0].target is SecurityTarget.COMMAND
    assert component.routes[0].command_dialect is CommandDialect.POSIX_SHELL


def test_route_interest_skips_non_matching_component() -> None:
    component = RouteComponent(PermissionResult(permission=PermissionLevel.DENY))
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("read_file", {"path": "a.txt"}))

    assert result.permission is PermissionLevel.ASK
    assert component.routes == []
