# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio

from agent_shield.tool_permission import PermissionEngine, PermissionLevel
from agent_shield.tool_permission.routing import CandidateKind, CommandDialect, RouteContext
from agent_shield.tool_permission.toolguard.command_allowlist import CommandAllowlistComponent


def run(awaitable):
    return asyncio.run(awaitable)


def _shell_route(dialect: CommandDialect = CommandDialect.POSIX_SHELL) -> RouteContext:
    return RouteContext(
        kind=CandidateKind.ORIGINAL, command_dialect=dialect, is_shell=True
    )


def test_default_allowlist_allows_known_prefix_and_denies_unknown_prefix() -> None:
    component = CommandAllowlistComponent()
    route = _shell_route()

    allowed = run(component.evaluate("bash", {"command": "echo hello"}, route=route))
    denied = run(component.evaluate("bash", {"command": "unknown hello"}, route=route))

    assert allowed is not None and allowed.permission is PermissionLevel.ALLOW
    assert denied is not None and denied.permission is PermissionLevel.DENY


def test_explicit_none_or_empty_list_disables_allowlist() -> None:
    route = _shell_route(CommandDialect.POWERSHELL)
    for value in (None, []):
        component = CommandAllowlistComponent()
        component.configure({"shell_allowlist": value})
        result = run(component.evaluate("powershell", {"command": "anything"}, route=route))
        assert result is not None and result.permission is PermissionLevel.ALLOW


def test_route_dispatch_ignores_non_command_routes() -> None:
    component = CommandAllowlistComponent()
    route = RouteContext(kind=CandidateKind.ORIGINAL, is_shell=False)

    assert run(component.evaluate("read_file", {}, route=route)) is None


def test_allowlist_skips_subcommand_candidates() -> None:
    component = CommandAllowlistComponent()
    route = RouteContext(
        kind=CandidateKind.SUBCOMMAND,
        command_dialect=CommandDialect.POSIX_SHELL,
        is_shell=True,
    )
    assert run(component.evaluate("bash", {"command": "unknown hello"}, route=route)) is None


def test_allowlist_still_judges_unwrapped_view() -> None:
    component = CommandAllowlistComponent()
    route = RouteContext(
        kind=CandidateKind.UNWRAPPED,
        command_dialect=CommandDialect.POSIX_SHELL,
        is_shell=True,
    )
    denied = run(component.evaluate("bash", {"command": "unknown hello"}, route=route))
    assert denied is not None and denied.permission is PermissionLevel.DENY


def test_engine_routes_command_allowlist_and_reconfigures_it() -> None:
    engine = PermissionEngine({"shell_allowlist": ["echo"]})

    denied = run(engine.check_permission("bash", {"command": "printf hello"}))
    assert denied.permission is PermissionLevel.DENY
    assert denied.matched_rule == "shell_allowlist:not_allowed"

    engine.update_config({"shell_allowlist": ["printf"]})
    allowed = run(engine.check_permission("bash", {"command": "printf hello"}))
    # The allowlist component allows its own check; the currently registered
    # tiered component still contributes its ASK fallback.
    assert allowed.permission is PermissionLevel.ASK
