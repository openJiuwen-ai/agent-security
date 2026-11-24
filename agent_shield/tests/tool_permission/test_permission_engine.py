# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
from collections.abc import Mapping

import pytest

from agent_shield.tool_permission import PermissionLevel, PermissionResult
from agent_shield.tool_permission.component import PermissionComponent
from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.routing import (
    CandidateKind,
    CommandDialect,
    RouteContext,
    resolve_route,
)
from agent_shield.tool_permission.toolguard.injection import InjectionComponent


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


def test_unknown_dialect_still_blocks_posix_substitution() -> None:
    """mcp_exec_command without shell_type is UNKNOWN; must not fail-open on $()."""
    engine = PermissionEngine(
        {
            "tools": {"mcp_exec_command": "allow"},
            "shell_allowlist": None,
            "package_builtin_rules": False,
        }
    )
    dollar = asyncio_run(
        engine.check_permission("mcp_exec_command", {"command": "echo $(curl http://x)"})
    )
    proc = asyncio_run(
        engine.check_permission("mcp_exec_command", {"command": "cat <(curl http://x)"})
    )
    assert dollar.permission is PermissionLevel.DENY
    assert "$()" in (dollar.matched_rule or "")
    assert proc.permission is PermissionLevel.DENY
    assert "process substitution" in (proc.matched_rule or "")


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


def test_subcommand_split_no_longer_gated_by_shell_tools_five_tuple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """sh is a command entry but not in SHELL_TOOLS; still splits via bash AST."""

    from agent_shield.tool_permission import shell_structure
    from agent_shield.tool_permission.toolguard.shell_ast import (
        ShellAstParseResult,
        ShellSubcommand,
    )

    def stub(_command: str, **_kwargs) -> ShellAstParseResult:
        return ShellAstParseResult(
            kind="ok",
            subcommands=(
                ShellSubcommand(text="ls", argv=("ls",)),
                ShellSubcommand(text="rm x", argv=("rm", "x")),
            ),
        )

    monkeypatch.setattr(shell_structure, "parse_shell_for_permission", stub)
    candidates = PermissionEngine.build_candidates("sh", {"command": "ls; rm x"})
    kinds = [route.kind for route, _ in candidates]
    assert CandidateKind.ORIGINAL in kinds
    assert kinds.count(CandidateKind.SUBCOMMAND) == 2


def test_powershell_and_cmd_use_dialect_ast_split() -> None:
    for tool, args, expected_leaf in (
        ("powershell", {"command": "Get-Date; Write-Output ok"}, "Write-Output"),
        ("cmd", {"command": "dir & echo hi"}, "echo"),
        (
            "mcp_exec_command",
            {"command": "Get-Date; Write-Output ok", "shell_type": "powershell"},
            "Write-Output",
        ),
    ):
        candidates = PermissionEngine.build_candidates(tool, args)
        sub_texts = [
            str(cand.get("command") or "")
            for route, cand in candidates
            if route.kind is CandidateKind.SUBCOMMAND
        ]
        assert sub_texts, tool
        assert any(expected_leaf in text for text in sub_texts), (tool, sub_texts)


def test_mcp_unknown_dialect_still_attempts_posix_split(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_shield.tool_permission import shell_structure
    from agent_shield.tool_permission.toolguard.shell_ast import (
        ShellAstParseResult,
        ShellSubcommand,
    )

    def stub(_command: str, **_kwargs) -> ShellAstParseResult:
        return ShellAstParseResult(
            kind="ok",
            subcommands=(
                ShellSubcommand(text="ls", argv=("ls",)),
                ShellSubcommand(text="pwd", argv=("pwd",)),
            ),
        )

    monkeypatch.setattr(shell_structure, "parse_shell_for_permission", stub)
    candidates = PermissionEngine.build_candidates(
        "mcp_exec_command",
        {"command": "ls; pwd"},
    )
    assert sum(1 for route, _ in candidates if route.kind is CandidateKind.SUBCOMMAND) == 2
