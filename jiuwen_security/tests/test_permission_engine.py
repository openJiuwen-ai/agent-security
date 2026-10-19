from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from jiuwen_security import PermissionEngine, PermissionLevel, PermissionResult
from jiuwen_security.policy.component import PermissionComponent
from jiuwen_security.policy.routing import (
    CommandDialect,
    RouteContext,
    RouteInterest,
    SecurityTarget,
    resolve_route,
)


class ResultComponent:
    interests: tuple[RouteInterest, ...] | None = (RouteInterest(SecurityTarget.ALL),)

    def __init__(self, result: PermissionResult) -> None:
        self.result = result
        self.configured: list[dict[str, object]] = []

    def configure(self, config: Mapping[str, object]) -> None:
        self.configured.append(dict(config))

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult:
        return self.result


class RouteComponent(ResultComponent):
    interests = (RouteInterest(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL),)

    def __init__(self, result: PermissionResult) -> None:
        super().__init__(result)
        self.routes = []

    async def evaluate(self, tool_name, tool_args, *, route=None):
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


def test_all_route_interest_matches_every_resolved_route() -> None:
    component = RouteComponent(PermissionResult(permission=PermissionLevel.DENY))
    component.interests = (RouteInterest(SecurityTarget.ALL),)
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("read_file", {"path": "a.txt"}))

    assert result.permission is PermissionLevel.DENY
    assert component.routes[0].target is SecurityTarget.FILE


@pytest.mark.parametrize("tool", ["bash", "powershell", "cmd", "mcp_exec_command", "read_file", "fetch", "unknown"])
def test_all_subscription_matches_each_category(tool: str) -> None:
    route = resolve_route(tool, {})
    assert route.target is not SecurityTarget.ALL
    assert RouteInterest(SecurityTarget.ALL).matches(route)


@pytest.mark.parametrize("target", [SecurityTarget.FILE, SecurityTarget.NETWORK, SecurityTarget.OTHER, SecurityTarget.ALL])
def test_non_command_dialect_subscription_is_rejected(target: SecurityTarget) -> None:
    with pytest.raises(ValueError):
        RouteInterest(target, CommandDialect.POSIX_SHELL)


def test_unrecognized_subscription_values_are_rejected() -> None:
    with pytest.raises(TypeError):
        RouteInterest("missing")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        RouteInterest(SecurityTarget.COMMAND, "missing")  # type: ignore[arg-type]


def test_unknown_dialect_is_not_a_wildcard() -> None:
    posix = resolve_route("bash", {})
    unknown = resolve_route("mcp_exec_command", {})
    assert RouteInterest(SecurityTarget.COMMAND).matches(posix)
    assert not RouteInterest(SecurityTarget.COMMAND, CommandDialect.UNKNOWN).matches(posix)
    assert RouteInterest(SecurityTarget.COMMAND, CommandDialect.UNKNOWN).matches(unknown)
