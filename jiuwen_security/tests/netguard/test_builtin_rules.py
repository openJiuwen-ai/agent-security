"""Package network rules are explicit, isolated and configurable."""

import asyncio

import pytest

from jiuwen_security import PermissionEngine, PermissionLevel
from jiuwen_security.policy.netguard import NetGuardComponent
from jiuwen_security.policy.netguard.builtin_rules import package_net_urls


def test_package_network_rules_are_the_four_migrated_defaults():
    expected = {
        "169.254.169.254": "deny",
        "metadata.google.internal": "deny",
        "localhost": "deny",
        "127.0.0.1": "deny",
    }
    rules = package_net_urls()
    assert rules == expected
    rules["localhost"] = "allow"
    rules["extra.example"] = "deny"
    assert package_net_urls() == expected


@pytest.mark.parametrize("host", tuple(package_net_urls()))
def test_each_package_rule_reaches_the_production_component(host):
    engine = PermissionEngine(
        {
            "tools": {"mcp_fetch_webpage": "allow"},
            "net_guard": {"enabled": True},
        }
    )
    result = asyncio.run(engine.check_permission("mcp_fetch_webpage", {"url": f"https://{host}/"}))
    assert result.permission is PermissionLevel.DENY
    assert result.matched_rule == "net_guard:url:" + host


def test_disabling_package_rules_does_not_disable_connection_address_checks():
    engine = PermissionEngine(
        {
            "package_builtin_rules": False,
            "tools": {"mcp_fetch_webpage": "allow"},
            "net_guard": {"enabled": True},
        }
    )
    args = {
        "url": "https://169.254.169.254/",
        "resolved_addresses": ["169.254.169.254"],
        "connect_address": "169.254.169.254",
    }
    assert (
        asyncio.run(engine.check_permission("mcp_fetch_webpage", args)).permission
        is PermissionLevel.ALLOW
    )
    assert (
        asyncio.run(engine.check_permission("network_connect", args)).permission
        is PermissionLevel.DENY
    )


@pytest.mark.parametrize("value", (False, " false ", "0", "NO", "off", None, True))
def test_component_owns_package_switch_parsing(value):
    config = {
        "package_builtin_rules": value,
        "tools": {"mcp_fetch_webpage": "allow"},
        "net_guard": {"enabled": True},
    }
    component = NetGuardComponent()
    component.configure(config)
    args = {"url": "https://localhost/"}
    result = asyncio.run(component.evaluate("mcp_fetch_webpage", args))
    expected = PermissionLevel.DENY if value is None or value is True else PermissionLevel.ALLOW
    assert result.permission is expected
    engine_result = asyncio.run(
        PermissionEngine(config).check_permission("mcp_fetch_webpage", args)
    )
    assert (engine_result.permission, engine_result.matched_rule) == (
        result.permission,
        result.matched_rule,
    )
