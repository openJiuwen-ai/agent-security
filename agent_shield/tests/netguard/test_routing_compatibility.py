# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Compatibility of older two-argument W3 component adapters.

This fixture deliberately has no subscriptions. Production registration is
covered separately without overriding the real engine's component set.
"""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionResult
from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.netguard.component import NetGuardComponent
from agent_shield.tool_permission.netguard.iptext import ipv4
from agent_shield.tool_permission.routing import is_network_tool

_FETCH_TOOLS = ("mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage")


class _ObservedNetGuard(NetGuardComponent):
    interests = None

    def __init__(self):
        super().__init__()
        self.calls = []
        self.results = []

    async def evaluate(self, tool_name, tool_args):
        self.calls.append((tool_name, tool_args))
        result = await super().evaluate(tool_name, tool_args)
        self.results.append(result)
        return result


class _Baseline:
    def __init__(self, permission):
        self.permission = permission

    def configure(self, config):
        pass

    async def evaluate(self, tool_name, tool_args):
        return PermissionResult(self.permission, "test:tool_baseline")


def _config(action="deny", *, enabled=True, default="allow"):
    return {
        "tools": {name: "allow" for name in _FETCH_TOOLS},
        "net_guard": {"enabled": enabled, "defaults": default, "urls": {"example.com": action}},
    }


def _mount(config, *, baseline=None):
    component = _ObservedNetGuard()

    class MountedEngine(PermissionEngine):
        def _build_components(self):
            return (component,) if baseline is None else (_Baseline(baseline), component)

    return MountedEngine(config), component


def _check(engine, tool, args):
    return asyncio.run(engine.check_permission(tool, args))


def test_raw_query_keeps_two_argument_component_adapters_compatible():
    engine, component = _mount(_config("deny"))
    args = {"url": "https://example.com/page"}
    assert asyncio.run(engine.evaluate_global_policy_directly("fetch_webpage", args)) == (
        L.DENY,
        "net_guard:url:example.com",
    )
    assert _check(engine, "fetch_webpage", args).permission is L.DENY
    assert component.calls == [("fetch_webpage", args), ("fetch_webpage", args)]


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_two_argument_component_reaches_every_supported_action_once(tool, action):
    engine, component = _mount(_config(action))
    # Exercise the legacy adapter without subscriptions.
    assert getattr(component, "interests", None) is None
    args = {"url": "https://example.com/page"}
    if tool == "network_connect":
        args.update(resolved_addresses=[ipv4(8, 8, 8, 8)], connect_address=ipv4(8, 8, 8, 8))
    result = _check(engine, tool, args)
    assert result.permission is L(action)
    expected_label = (
        "tools." + tool
        if action == "allow" and tool != "network_connect"
        else "net_guard:url:example.com"
    )
    assert result.matched_rule == expected_label
    assert component.calls == [(tool, args)]
    assert component.results == [result]


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("padding", (" ", "\t\n"))
def test_tool_name_whitespace_cannot_skip_the_component(tool, padding):
    engine, component = _mount(_config("deny"), baseline=L.ALLOW)
    supplied_name = padding + tool + padding
    args = {"url": "https://example.com"}
    if tool == "network_connect":
        args.update(resolved_addresses=[ipv4(8, 8, 8, 8)], connect_address=ipv4(8, 8, 8, 8))
    result = _check(engine, supplied_name, args)
    assert result.permission is L.DENY
    assert result.matched_rule == "net_guard:url:example.com"
    # The engine and its router remain unchanged; W3 normalizes locally.
    assert component.calls == [(supplied_name, args)]
    assert getattr(component, "interests", None) is None


@pytest.mark.parametrize(
    "tool",
    (
        "fetch",
        "mcp_free_search",
        "mcp_paid_search",
        "bash",
        "read_file",
        "custom_tool",
        "MCP_FETCH_WEBPAGE",
        "NETWORK_CONNECT",
        "/fetch_webpage",
        "prefix.fetch_webpage",
    ),
)
def test_non_fetch_tools_do_not_get_fetch_url_policy(tool):
    engine, component = _mount(_config(default="deny"))
    # Only exact fetch helpers inspect URL args; other network names get baseline only.
    args = {"url": "file:///private", "resolved_addresses": [], "connect_address": "bad"}
    result = _check(engine, tool, args)
    assert component.calls == [(tool, args)]
    if is_network_tool(tool):
        assert component.results[0] is not None
        assert component.results[0].permission is L.ASK
    else:
        assert component.results[0] is None
        assert result.permission is L.ASK
        assert result.matched_rule in (None, "tiered_policy:fallback(no_config)")


@pytest.mark.parametrize("tool", _FETCH_TOOLS)
@pytest.mark.parametrize("baseline", (L.ASK, L.DENY))
def test_c_allow_keeps_the_original_tool_baseline(tool, baseline):
    engine, component = _mount(_config("allow"), baseline=baseline)
    result = _check(engine, tool, {"url": "https://example.com"})
    assert component.results[0].permission is L.ALLOW
    assert result.permission is baseline
    assert result.matched_rule == "test:tool_baseline"


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
def test_disabled_url_guard_keeps_the_network_tool_baseline(tool):
    engine, component = _mount(_config(enabled=False))
    result = _check(engine, tool, {})
    if tool == "network_connect":
        assert component.results == [None]
        assert result.permission is L.ASK
    else:
        assert component.results[0].permission is L.ALLOW
        assert result.permission is L.ALLOW


@pytest.mark.parametrize(
    "args",
    [
        {"url": "https://example.com", "connect_address": ipv4(8, 8, 8, 8)},
        {"url": "https://example.com", "resolved_addresses": [ipv4(8, 8, 8, 8)]},
    ],
)
def test_connection_facts_are_required_through_engine_even_with_allow_rule(args):
    engine, component = _mount(_config("allow"))
    with pytest.raises(ValueError):
        _check(engine, "network_connect", args)
    assert len(component.calls) == 1
    assert component.results == []


def test_connection_policy_cannot_be_disabled_by_fetch_or_approval_fields():
    engine, component = _mount(_config("allow"))
    args = {
        "url": "https://example.com",
        "resolved_addresses": [ipv4(127, 0, 0, 1)],
        "connect_address": ipv4(127, 0, 0, 1),
        "approved": True,
        "enforce_host_exit": False,
        "permission": "allow",
    }
    result = _check(engine, "network_connect", args)
    assert result.permission is L.DENY
    assert len(component.calls) == 1
    assert "net_guard:connection:address_not_allowed" in result.matched_rule


@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_query_preserves_default_and_matched_rule_labels(action):
    cfg = _config(action, default=action)
    engine, _ = _mount(cfg)
    matched = asyncio.run(
        engine.evaluate_global_policy_directly("fetch_webpage", {"url": "https://example.com"})
    )
    defaulted = asyncio.run(
        engine.evaluate_global_policy_directly(
            "fetch_webpage", {"url": "https://unmatched.invalid"}
        )
    )
    if action == "allow":
        assert matched == defaulted == (L.ALLOW, "tools.fetch_webpage")
    else:
        assert matched == (L(action), "net_guard:url:example.com")
        assert defaulted == (L(action), "net_guard:defaults")


def test_failed_w3_update_preserves_its_rules_and_connection_policy():
    engine, component = _mount(_config("ask"))
    invalid = _config("allow")
    invalid["net_guard"]["connection"] = {"allow_loopback": "true"}
    with pytest.raises(ValueError):
        engine.update_config(invalid)
    args = {
        "url": "https://example.com",
        "resolved_addresses": [ipv4(8, 8, 8, 8)],
        "connect_address": ipv4(8, 8, 8, 8),
    }
    assert _check(engine, "network_connect", args).permission is L.ASK
    args.update(resolved_addresses=[ipv4(127, 0, 0, 1)], connect_address=ipv4(127, 0, 0, 1))
    assert _check(engine, "network_connect", args).permission is L.DENY
    assert engine.config == _config("ask")
    assert len(component.calls) == 2
