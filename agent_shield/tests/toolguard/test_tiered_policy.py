from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel
from agent_shield.tool_permission.routing import CommandDialect, RouteContext, SecurityTarget
from agent_shield.tool_permission.toolguard.tiered import TieredPolicyComponent


_BASH_ROUTE = RouteContext(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL)


def test_rule_match_and_strictest_across_builtin_and_user() -> None:
    component = TieredPolicyComponent()
    component.configure(
        {
            "rules": [
                {"id": "builtin-ask", "layer": "builtin", "tools": ["bash"],
                 "match_type": "command", "pattern": "re:danger", "action": "ask"},
                {"id": "user-deny", "tools": ["bash"],
                 "match_type": "command", "pattern": "re:danger", "action": "deny"},
            ]
        }
    )

    result = asyncio.run(
        component.evaluate(
            "bash", {"command": "echo danger"},
            route=_BASH_ROUTE,
        )
    )

    assert result is not None
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule is not None
    # Matching object is identical, so the user's action replaces the
    # builtin action and the detector remains attributed to the builtin rule.
    assert "builtin:deny" in result.matched_rule
    assert "builtin-ask" in result.matched_rule
    assert "user-deny" not in result.matched_rule


def test_action_override_uses_tools_and_pattern_not_id() -> None:
    component = TieredPolicyComponent()
    component.configure(
        {
            "rules": [
                {"id": "builtin-id", "layer": "builtin", "tools": ["bash"],
                 "pattern": "re:danger", "action": "deny"},
                {"id": "different-id", "tools": ["bash"],
                 "pattern": "re:danger", "action": "allow"},
            ]
        }
    )

    result = asyncio.run(
        component.evaluate(
            "bash", {"command": "danger"},
            route=_BASH_ROUTE,
        )
    )

    assert result is not None
    assert result.permission is PermissionLevel.ALLOW
    assert result.matched_rule is not None
    assert "builtin-id" in result.matched_rule
    assert "different-id" not in result.matched_rule


def test_approval_override_precedes_non_deny_rule_and_baseline() -> None:
    component = TieredPolicyComponent()
    component.configure(
        {
            "tools": {"bash": "ask"},
            "rules": [{"id": "deny", "tools": ["bash"], "pattern": "re:danger", "action": "deny"}],
            "approval_overrides": [
                {"id": "approved", "tools": ["bash"], "pattern": "re:danger", "action": "allow"}
            ],
        }
    )

    result = asyncio.run(
        component.evaluate(
            "bash", {"command": "danger"},
            route=_BASH_ROUTE,
        )
    )

    assert result is not None
    assert result.permission is PermissionLevel.ALLOW
    assert result.matched_rule is not None
    assert "approval_overrides" in result.matched_rule


def test_tool_deny_cannot_be_overridden_by_approval() -> None:
    component = TieredPolicyComponent()
    component.configure(
        {
            "tools": {"bash": "deny"},
            "approval_overrides": [
                {"id": "approved", "tools": ["bash"], "pattern": "re:.*", "action": "allow"}
            ],
        }
    )

    result = asyncio.run(
        component.evaluate(
            "bash", {"command": "echo safe"},
            route=_BASH_ROUTE,
        )
    )

    assert result is not None
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "tools.bash"


def test_default_undetermined_and_engine_registration() -> None:
    engine = PermissionEngine({"defaults": {"*": "undetermined"}})

    result = asyncio.run(engine.check_permission("bash", {"command": "echo hello"}))

    assert result.permission is PermissionLevel.UNDETERMINED


def test_non_command_route_does_not_match_component() -> None:
    component = TieredPolicyComponent()
    component.configure({"defaults": {"*": "deny"}})
    route = RouteContext(SecurityTarget.FILE)

    result = asyncio.run(component.evaluate("read_file", {"path": "x"}, route=route))

    assert result is None


def test_update_config_replaces_prepared_policy() -> None:
    engine = PermissionEngine({"defaults": {"*": "allow"}})
    engine.update_config({"defaults": {"*": "deny"}})

    result = asyncio.run(engine.check_permission("bash", {"command": "echo hello"}))

    assert result.permission is PermissionLevel.DENY


def test_builtin_and_user_rules_for_different_patterns_take_strictest() -> None:
    component = TieredPolicyComponent()
    component.configure(
        {
            "rules": [
                {"id": "builtin-ask", "layer": "builtin", "tools": ["bash"],
                 "pattern": "re:danger", "action": "ask"},
                {"id": "user-allow", "tools": ["bash"],
                 "pattern": "re:echo", "action": "allow"},
            ]
        }
    )

    result = asyncio.run(
        component.evaluate("bash", {"command": "echo danger"}, route=_BASH_ROUTE)
    )

    assert result is not None
    assert result.permission is PermissionLevel.ASK
    assert result.matched_rule is not None
    assert "builtin-ask" in result.matched_rule
    assert "user-allow" not in result.matched_rule


@pytest.mark.parametrize("action", ["allow", "ask", "deny", "undetermined"])
def test_rule_actions_accept_all_permission_levels(action: str) -> None:
    component = TieredPolicyComponent()
    component.configure(
        {"rules": [{"id": "level", "tools": ["bash"], "pattern": "re:danger", "action": action}]}
    )

    result = asyncio.run(
        component.evaluate(
            "bash", {"command": "danger"},
            route=_BASH_ROUTE,
        )
    )

    assert result is not None
    assert result.permission is PermissionLevel(action)
