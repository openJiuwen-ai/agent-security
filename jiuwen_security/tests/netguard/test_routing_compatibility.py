"""W3 contracts through the current engine, without changing W6 routing.

Only the test engine supplies _build_components(). Production registration,
network_connect A/B isolation and cross-component transactions remain W6 work.
"""

import asyncio

import pytest

from jiuwen_security import PermissionEngine, PermissionResult
from jiuwen_security import PermissionLevel as L
from jiuwen_security.policy.netguard.net_guard import NetGuardChecker

_FETCH_TOOLS = ("mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage")


class _ObservedNetGuard(NetGuardChecker):
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
    return {"net_guard": {"enabled": enabled, "defaults": default, "urls": {"example.com": action}}}


def _mount(config, *, baseline=None):
    component = _ObservedNetGuard()

    class MountedEngine(PermissionEngine):
        def _build_components(self):
            return (component,) if baseline is None else (_Baseline(baseline), component)

    return MountedEngine(config), component


def _check(engine, tool, args):
    return asyncio.run(engine.check_permission(tool, args))


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_two_argument_component_reaches_every_supported_action_once(tool, action):
    engine, component = _mount(_config(action))
    # Leave subscriptions unset until W6 classifies every supported action.
    assert getattr(component, "interests", None) is None
    args = {"url": "https://example.com/page"}
    if tool == "network_connect":
        args.update(resolved_addresses=["8.8.8.8"], connect_address="8.8.8.8")
    result = _check(engine, tool, args)
    assert result.permission is L(action)
    assert result.matched_rule == "net_guard:url:example.com"
    assert component.calls == [(tool, args)]
    assert component.results == [result]


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("padding", (" ", "\t\n"))
def test_tool_name_whitespace_cannot_skip_the_component(tool, padding):
    engine, component = _mount(_config("deny"), baseline=L.ALLOW)
    supplied_name = padding + tool + padding
    args = {"url": "https://example.com"}
    if tool == "network_connect":
        args.update(resolved_addresses=["8.8.8.8"], connect_address="8.8.8.8")
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
def test_routing_category_never_expands_w3_tool_applicability(tool):
    engine, component = _mount(_config(default="deny"))
    # Unsupported actions are skipped even when their arguments resemble a
    # connection or contain an invalid URL. W3 must not return its ALLOW/default.
    args = {"url": "file:///private", "resolved_addresses": [], "connect_address": "bad"}
    result = _check(engine, tool, args)
    assert component.results == [None]
    assert result.permission is L.ASK
    assert result.matched_rule is None


@pytest.mark.parametrize("tool", _FETCH_TOOLS)
@pytest.mark.parametrize("baseline", (L.ASK, L.DENY))
def test_c_allow_keeps_the_original_tool_baseline(tool, baseline):
    engine, component = _mount(_config("allow"), baseline=baseline)
    result = _check(engine, tool, {"url": "https://example.com"})
    assert component.results[0].permission is L.ALLOW
    assert result.permission is baseline
    assert result.matched_rule == "test:tool_baseline"


@pytest.mark.parametrize("tool", (*_FETCH_TOOLS, "network_connect"))
def test_explicitly_disabled_w3_is_neutral_through_engine(tool):
    engine, component = _mount(_config(enabled=False))
    result = _check(engine, tool, {})
    assert component.results == [None]
    assert result.permission is L.ASK


@pytest.mark.parametrize(
    "args",
    [
        {
            "uri": "https://example.com",
            "resolved_addresses": ["8.8.8.8"],
            "connect_address": "8.8.8.8",
        },
        {"url": "https://example.com", "connect_address": "8.8.8.8"},
        {"url": "https://example.com", "resolved_addresses": ["8.8.8.8"]},
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
        "resolved_addresses": ["127.0.0.1"],
        "connect_address": "127.0.0.1",
        "approved": True,
        "enforce_host_exit": False,
        "permission": "allow",
    }
    result = _check(engine, "network_connect", args)
    assert result.permission is L.DENY
    assert len(component.calls) == 1
    assert "net_guard:connection:address_not_allowed" in result.matched_rule


@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_defaults_and_real_matches_stay_distinct_for_w6_query_adapter(action):
    engine, component = _mount(_config(action, default=action))
    matched = _check(engine, "fetch_webpage", {"url": "https://example.com"})
    defaulted = _check(engine, "fetch_webpage", {"url": "https://unmatched.invalid"})
    assert matched.permission is defaulted.permission is L(action)
    assert matched.matched_rule == "net_guard:url:example.com"
    assert defaulted.matched_rule == "net_guard:defaults"
    assert len(component.calls) == 2


def test_failed_w3_update_preserves_its_rules_and_connection_policy():
    engine, component = _mount(_config("ask"))
    invalid = _config("allow")
    invalid["net_guard"]["connection"] = {"allow_loopback": "true"}
    with pytest.raises(ValueError):
        engine.update_config(invalid)
    args = {
        "url": "https://example.com",
        "resolved_addresses": ["8.8.8.8"],
        "connect_address": "8.8.8.8",
    }
    assert _check(engine, "network_connect", args).permission is L.ASK
    args.update(resolved_addresses=["127.0.0.1"], connect_address="127.0.0.1")
    assert _check(engine, "network_connect", args).permission is L.DENY
    assert engine.config == _config("ask")
    assert len(component.calls) == 2
