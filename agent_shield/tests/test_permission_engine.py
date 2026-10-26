# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.component import PermissionComponent
from agent_shield.tool_permission.toolguard.injection import InjectionComponent
from agent_shield.tool_permission.routing import (
    CandidateKind,
    CommandDialect,
    RouteContext,
    resolve_route,
)


class ResultComponent:
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


@pytest.mark.parametrize(
    ("tool", "command", "rule"),
    [
        ("bash", "printf '%s' `whoami`", "backtick command substitution"),
        ("bash", "printf '%s' $(whoami)", "$() command substitution"),
        ("bash", "cat <(printf secret)", "process substitution <() or >()"),
        ("powershell", "Invoke-Expression $cmd", "Invoke-Expression"),
        ("powershell", "pwsh -EncodedCommand ZQBjAGgAbwA=", "nested encoded command"),
        ("powershell", "& ($command)", "dynamic call operator"),
        ("powershell", "[ScriptBlock]::Create($code)", "dynamic ScriptBlock creation"),
    ],
)
def test_r02_injection_is_denied(tool: str, command: str, rule: str) -> None:
    result = asyncio_run(PermissionEngine().check_permission(tool, {"command": command}))

    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == rule


@pytest.mark.parametrize(
    ("tool", "command", "blocked"),
    [
        # Patterns are the original ones: unclosed, multi-line and nested forms still block.
        ("bash", "echo $(", True),
        ("bash", "echo $((1+2))", True),
        ("bash", "echo $(\nrm -rf /\n)", True),
        ("bash", "echo `\nwhoami\n`", True),
        ("bash", "cat <(\nls\n)", True),
        ("bash", "echo '`ls`'", False),
        ("powershell", "Foo-iex", True),
        ("powershell", "pwsh -enc AAA", False),
        ("powershell", "pwsh -e AAA", False),
        ("powershell", "x&($y)", False),
        ("powershell", "a & ($y)", True),
        ("powershell", "(& $y)", True),
        ("powershell", "[ScriptBlock] :: Create('x')", False),
    ],
)
def test_injection_patterns_match_original_semantics(tool: str, command: str, blocked: bool) -> None:
    result = asyncio_run(
        InjectionComponent().evaluate(
            tool, {"command": command}, route=resolve_route(tool, {"command": command})
        )
    )

    assert (result.permission is PermissionLevel.DENY) is blocked


def test_injection_reason_keeps_original_wording() -> None:
    bash = asyncio_run(PermissionEngine().check_permission("bash", {"command": "echo $(id)"}))
    ps = asyncio_run(PermissionEngine().check_permission("powershell", {"command": "iex $x"}))

    assert bash.reason == "Shell injection detected: $() command substitution"
    assert ps.reason == "PowerShell injection detected: Invoke-Expression"


@pytest.mark.parametrize(
    ("tool", "command"),
    [("bash", "echo hello"), ("powershell", "echo hello")],
)
def test_r02_safe_commands_are_allowed(tool: str, command: str) -> None:
    result = asyncio_run(
        InjectionComponent().evaluate(
            tool, {"command": command}, route=resolve_route(tool, {})
        )
    )

    assert result.permission is PermissionLevel.ALLOW


def test_r02_does_not_apply_to_file_routes() -> None:
    result = asyncio_run(
        PermissionEngine().check_permission("read_file", {"path": "$(whoami)"})
    )

    assert result.permission is PermissionLevel.ASK


def test_r02_component_accepts_complete_config_without_changing_rules() -> None:
    component = InjectionComponent()
    component.configure({"injection": {"enabled": False}})

    result = asyncio_run(
        component.evaluate(
            "bash",
            {"command": "echo $(whoami)"},
            route=resolve_route("bash", {}),
        )
    )

    assert result.permission is PermissionLevel.DENY


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


def test_route_aware_component_receives_candidate_context() -> None:
    component = RouteComponent(PermissionResult(permission=PermissionLevel.DENY))
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("bash", {"command": "echo hi"}))

    assert result.permission is PermissionLevel.DENY
    assert component.routes[0].kind is CandidateKind.ORIGINAL
    assert component.routes[0].is_shell is True
    assert component.routes[0].command_dialect is CommandDialect.POSIX_SHELL


def test_every_component_is_invoked_for_non_shell_tools() -> None:
    component = RouteComponent(PermissionResult(permission=PermissionLevel.DENY))
    engine = ComponentEngine(component)

    result = asyncio_run(engine.check_permission("read_file", {"path": "a.txt"}))

    assert result.permission is PermissionLevel.DENY
    assert component.routes[0].kind is CandidateKind.ORIGINAL
    assert component.routes[0].is_shell is False


@pytest.mark.parametrize(
    "tool",
    ["bash", "powershell", "cmd", "mcp_exec_command", "read_file", "fetch", "unknown"],
)
def test_resolve_route_sets_shell_flag(tool: str) -> None:
    route = resolve_route(tool, {})
    assert route.kind is CandidateKind.ORIGINAL
    assert route.is_shell is (tool in {"bash", "powershell", "cmd", "mcp_exec_command"})
