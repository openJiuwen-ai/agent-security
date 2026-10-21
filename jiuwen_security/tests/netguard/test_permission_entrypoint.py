"""W3 through the public SDK facade and its production component set.

No engine subclass, fake baseline or external repository is used here.
Connection facts are injected; no DNS lookup or HTTP request is performed.
"""

import asyncio
import socket
from statistics import median
from time import perf_counter_ns

import pytest

from jiuwen_security import PermissionEngine, SecurityTarget
from jiuwen_security import PermissionLevel as L
from jiuwen_security.policy.netguard.component import NetGuardComponent
from jiuwen_security.policy.netguard.tool_policy import NetworkToolPolicy
from jiuwen_security.policy.routing import resolve_route

FETCH_TOOLS = ("mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage")
URL = "https://example.com/page"
ARGS = {"url": URL}
CONNECTION = {**ARGS, "resolved_addresses": ["8.8.8.8"], "connect_address": "8.8.8.8"}


def config(*, baseline="allow", action="allow", enabled=True):
    result = {"net_guard": {"enabled": enabled, "urls": {"example.com": action}}}
    if baseline is not None:
        result["tools"] = {tool: baseline for tool in FETCH_TOOLS}
    return result


def check(engine, tool="mcp_fetch_webpage", args=None):
    return asyncio.run(engine.check_permission(tool, ARGS if args is None else args))


def query(engine, tool="mcp_fetch_webpage", args=None, **kwargs):
    return asyncio.run(
        engine.evaluate_global_policy_directly(tool, ARGS if args is None else args, **kwargs)
    )


@pytest.mark.parametrize("tool", (*FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("padding", ("", " \t"))
def test_production_routing_calls_w3_once_with_network_facts(tool, padding, monkeypatch):
    calls = []
    original = NetGuardComponent.evaluate

    async def observe(self, name, args, *, route=None):
        calls.append((name, route))
        return await original(self, name, args, route=route)

    monkeypatch.setattr(NetGuardComponent, "evaluate", observe)
    engine = PermissionEngine(config(action="deny"))
    name = padding + tool + padding
    result = check(engine, name, CONNECTION if tool == "network_connect" else ARGS)

    assert result.permission is L.DENY
    assert result.matched_rule == "net_guard:url:example.com"
    assert resolve_route(name, {}).target is SecurityTarget.NETWORK
    assert calls == [(name, resolve_route(name, {}))]
    assert NetGuardComponent.interests[0].target is SecurityTarget.NETWORK


@pytest.mark.parametrize("tool", FETCH_TOOLS)
@pytest.mark.parametrize("baseline", ("allow", "undetermined", "ask", "deny", None))
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_real_network_baseline_and_c_policy_take_strictest(tool, baseline, action):
    order = {L.ALLOW: 0, L.UNDETERMINED: 1, L.ASK: 2, L.DENY: 3}
    expected = max(L(baseline or "ask"), L(action), key=order.__getitem__)
    result = check(PermissionEngine(config(baseline=baseline, action=action)), tool)
    assert result.permission is expected


@pytest.mark.parametrize("baseline", ("allow", "undetermined", "ask", "deny"))
@pytest.mark.parametrize("wrapped", (False, True))
def test_network_tool_baseline_overrides_global_default(baseline, wrapped):
    cfg = config()
    cfg["tools"]["mcp_fetch_webpage"] = {"*": baseline.upper()} if wrapped else baseline
    cfg["defaults"] = {"*": "deny"}
    result = check(PermissionEngine(cfg))
    assert result.permission is L(baseline)
    assert result.matched_rule == "tools.mcp_fetch_webpage" + (".*" if wrapped else "")


@pytest.mark.parametrize("level", ("allow", "undetermined", "ask", "deny"))
def test_network_global_default_is_not_replaced_by_c_allow(level):
    cfg = config(baseline=None)
    cfg["defaults"] = {"*": level}
    result = check(PermissionEngine(cfg))
    assert result.permission is L(level)
    assert result.matched_rule == "tiered_policy:defaults.*"


@pytest.mark.parametrize("tool", ("fetch", "mcp_free_search", "mcp_paid_search"))
def test_other_network_tools_get_a_baseline_without_inventing_url_support(tool):
    cfg = config(action="deny")
    cfg["tools"][tool] = "allow"
    result = check(PermissionEngine(cfg), tool)
    assert result.permission is L.ALLOW
    assert result.matched_rule == "tools." + tool
    # Its actual HTTP target must separately pass network_connect.
    assert check(PermissionEngine(cfg), "network_connect", CONNECTION).permission is L.DENY


def test_c_allow_does_not_replace_an_absent_a_policy_with_allow():
    engine = PermissionEngine(config(baseline=None))
    assert check(engine).permission is L.ASK
    assert query(engine) == (L.ASK, "tiered_policy:fallback(no_config)")


@pytest.mark.parametrize("level", ("ask", "deny", "undetermined"))
def test_connection_action_does_not_repeat_a_baseline_or_global_default(level):
    cfg = config()
    cfg["tools"]["network_connect"] = level
    cfg["defaults"] = {"*": level}
    cfg["tools"]["mcp_fetch_webpage"] = "deny"
    engine = PermissionEngine(cfg)
    assert check(engine).permission is L.DENY
    assert check(engine, "network_connect", CONNECTION).permission is L.ALLOW
    assert query(engine, "network_connect", CONNECTION) == (L.ALLOW, "net_guard:url:example.com")


def test_connection_action_never_invokes_network_a_policy(monkeypatch):
    async def forbidden(*args, **kwargs):
        pytest.fail("internal connection action reached Pipeline A")

    monkeypatch.setattr(NetworkToolPolicy, "evaluate", forbidden)
    engine = PermissionEngine(config())
    assert check(engine, "network_connect", CONNECTION).permission is L.ALLOW
    assert query(engine, "network_connect", CONNECTION)[0] is L.ALLOW


@pytest.mark.parametrize("enabled", (False, True))
def test_raw_query_keeps_the_execution_fallback_for_no_network_constraint(enabled):
    engine = PermissionEngine({"net_guard": {"enabled": enabled}})
    assert query(engine) == (L.ASK, "tiered_policy:fallback(no_config)")
    assert check(engine).permission is L.ASK


@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
def test_raw_query_matches_execution_for_explicit_and_default_url_policy(action):
    cfg = config(action=action)
    cfg["net_guard"]["defaults"] = action
    engine = PermissionEngine(cfg)
    expected_rule = "tools.mcp_fetch_webpage" if action == "allow" else "net_guard:url:example.com"
    assert query(engine) == (L(action), expected_rule)
    checked = check(engine)
    assert query(engine) == (checked.permission, checked.matched_rule)
    unmatched = {"url": "https://unmatched.example/"}
    expected_default = "tools.mcp_fetch_webpage" if action == "allow" else "net_guard:defaults"
    assert query(engine, args=unmatched) == (L(action), expected_default)
    checked = check(engine, args=unmatched)
    assert query(engine, args=unmatched) == (checked.permission, checked.matched_rule)


@pytest.mark.parametrize("baseline", ("allow", "undetermined", "ask", "deny"))
def test_raw_network_query_keeps_a_policy_when_c_is_neutral(baseline):
    cfg = config(baseline=baseline)
    cfg["net_guard"]["urls"] = {}
    assert query(PermissionEngine(cfg)) == (L(baseline), "tools.mcp_fetch_webpage")


def test_raw_query_bypasses_only_global_execution_switch():
    cfg = config(baseline=None, action="deny")
    cfg["enabled"] = False
    engine = PermissionEngine(cfg)
    assert check(engine).permission is L.ALLOW
    assert query(engine) == (
        L.DENY,
        "net_guard:url:example.com",
    )
    cfg["net_guard"]["enabled"] = False
    engine.update_config(cfg)
    assert query(engine) == (L.ASK, "tiered_policy:fallback(no_config)")


def test_raw_command_query_keeps_execution_checks_and_fallback():
    engine = PermissionEngine()
    assert query(engine, "bash", {"command": "echo hello"}) == (
        L.ASK,
        "tiered_policy:fallback(no_config)",
    )
    assert check(engine, "bash", {"command": "echo hello"}).permission is L.ASK
    assert query(engine, "bash", {"command": "shutdown now"})[0] is L.DENY
    assert query(engine, "bash", {"command": "echo `id`"}) == (
        L.DENY,
        "backtick command substitution",
    )
    assert query(engine, "custom_tool", {}) == (L.ASK, None)


@pytest.mark.parametrize("level", ("allow", "undetermined", "ask", "deny"))
def test_raw_command_query_keeps_explicit_four_level_policy(level):
    engine = PermissionEngine({"enabled": False, "tools": {"bash": level}})
    assert query(engine, "bash", {"command": "echo hello"})[0] is L(level)


@pytest.mark.parametrize("tool", ("fetch_webpage", "mcp_free_search", "mcp_paid_search"))
@pytest.mark.parametrize("level", ("allow", "undetermined", "ask", "deny"))
def test_network_baseline_preserves_raw_global_defaults(tool, level):
    engine = PermissionEngine({"defaults": {"*": level}})
    assert query(engine, tool, {}) == (L(level), "tiered_policy:defaults.*")
    assert check(engine, tool, {}).permission is L(level)


@pytest.mark.parametrize("tool", ("read_file", "custom_tool", "bash"))
def test_engine_does_not_dispatch_non_network_tools_to_netguard(tool, monkeypatch):
    async def forbidden(*args, **kwargs):
        raise AssertionError("Non-network tool reached NetGuard")

    monkeypatch.setattr(NetGuardComponent, "evaluate", forbidden)
    engine = PermissionEngine({"tools": {tool: "deny"}, "defaults": {"*": "deny"}})
    check(engine, tool, {})
    query(engine, tool, {})


@pytest.mark.parametrize("tool", (*FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("action", ("allow", "ask", "deny"))
@pytest.mark.parametrize(
    "args",
    ({}, {"url": None}, {"url": ""}, {"url": " \t"}, {"url": 123}, {"url": "https://[::1"}),
)
def test_absent_or_invalid_url_uses_defaults_in_both_entrypoints(tool, action, args):
    cfg = config()
    cfg["net_guard"]["defaults"] = action
    engine = PermissionEngine(cfg)
    result = check(engine, tool, args)
    expected_rule = (
        "tools." + tool
        if action == "allow" and tool != "network_connect"
        else "net_guard:defaults"
    )
    assert (result.permission, result.matched_rule) == (L(action), expected_rule)
    assert query(engine, tool, args) == (result.permission, result.matched_rule)


def test_connection_url_alias_does_not_replace_missing_url():
    cfg = config()
    cfg["net_guard"]["defaults"] = "ask"
    engine = PermissionEngine(cfg)
    args = {"uri": URL, "resolved_addresses": ["8.8.8.8"], "connect_address": "8.8.8.8"}
    assert check(engine, "network_connect", args).matched_rule == "net_guard:defaults"
    assert query(engine, "network_connect", args) == (L.ASK, "net_guard:defaults")


@pytest.mark.parametrize("tool", (*FETCH_TOOLS, "network_connect"))
@pytest.mark.parametrize("url", ("https://example.com/" + "a" * 8192, " " * 8193))
def test_overlong_url_returns_deny_in_both_entrypoints(tool, url):
    engine = PermissionEngine(config())
    result = check(engine, tool, {"url": url})
    assert (result.permission, result.matched_rule) == (L.DENY, "net_guard:url_too_long")
    assert query(engine, tool, {"url": url}) == (result.permission, result.matched_rule)


@pytest.mark.parametrize("tool", ("read_file", "custom_tool"))
def test_engine_does_not_install_a_general_non_command_baseline(tool):
    engine = PermissionEngine({"tools": {tool: "allow"}, "defaults": {"*": "allow"}})
    assert check(engine, tool, {}).permission is L.ASK
    assert query(engine, tool, {}) == (L.ASK, None)


def test_engine_registers_exactly_one_network_component():
    engine = PermissionEngine(config())
    network = [
        c
        for c in engine._components
        if any(i.target is SecurityTarget.NETWORK for i in (c.interests or ()))
    ]
    assert len(network) == 1
    assert type(network[0]) is NetGuardComponent


@pytest.mark.parametrize("method", ("check_permission", "evaluate_global_policy_directly"))
@pytest.mark.parametrize("changes", ({"resolved_addresses": []}, {"connect_address": "8.8.4.4"}))
def test_public_connection_entrypoints_reject_bad_facts(method, changes):
    engine = PermissionEngine(config())
    with pytest.raises(ValueError):
        asyncio.run(getattr(engine, method)("network_connect", {**CONNECTION, **changes}))


@pytest.mark.parametrize("addresses", (["127.0.0.1"], ["8.8.8.8", "10.0.0.1"]))
def test_connection_safety_is_stricter_than_an_explicit_url_allow(addresses):
    engine = PermissionEngine(config())
    args = {**CONNECTION, "resolved_addresses": addresses, "connect_address": addresses[0]}
    assert check(engine, "network_connect", args).permission is L.DENY
    assert query(engine, "network_connect", args)[0] is L.DENY


def test_disabled_c_never_invents_a_connection_allow():
    engine = PermissionEngine(config(enabled=False))
    assert check(engine, "network_connect", CONNECTION).permission is L.ASK
    assert query(engine, "network_connect", CONNECTION) == (L.ASK, None)


def test_public_query_validates_arguments():
    engine = PermissionEngine()
    with pytest.raises(ValueError):
        query(engine, " ", {})
    with pytest.raises(TypeError):
        query(engine, args=[])


def test_failed_w3_update_rolls_back_real_command_and_network_policy_together():
    cfg = config(baseline="deny")
    cfg.update(shell_allowlist=None, package_builtin_rules=False)
    cfg["tools"]["bash"] = "allow"
    engine = PermissionEngine(cfg)
    invalid = config()
    invalid["tools"]["bash"] = "deny"
    invalid["net_guard"]["connection"] = {"allow_loopback": "true"}
    with pytest.raises(ValueError):
        engine.update_config(invalid)
    assert engine.config == cfg
    assert check(engine).permission is L.DENY
    assert query(engine)[0] is L.DENY
    assert check(engine, "bash", {"command": "echo hello"}).permission is L.ALLOW
    engine.update_config(config(action="ask"))
    assert check(engine).permission is L.ASK
    assert query(engine)[0] is L.ASK


@pytest.mark.parametrize("value", (False, "false", " FALSE ", "0", "no", "off"))
def test_shared_package_switch_keeps_w1a_parsing_for_both_pipelines(value):
    engine = PermissionEngine(
        {
            "package_builtin_rules": value,
            "shell_allowlist": None,
            "tools": {"bash": "allow", "mcp_fetch_webpage": "allow"},
            "net_guard": {"enabled": True},
        }
    )
    assert check(engine, "bash", {"command": "shutdown now"}).permission is L.ALLOW
    assert check(engine, args={"url": "https://localhost/"}).permission is L.ALLOW
    # The engine snapshot remains the host's configuration, not W3's adapter copy.
    assert engine.config["package_builtin_rules"] == value


def test_shared_unspecified_package_switch_keeps_both_builtin_sets_enabled():
    cfg = config()
    cfg["package_builtin_rules"] = None
    engine = PermissionEngine(cfg)
    assert query(engine, "bash", {"command": "shutdown now"})[0] is L.DENY
    assert check(engine, args={"url": "https://localhost/"}).permission is L.DENY


def test_in_flight_call_keeps_one_a_c_snapshot_across_update(monkeypatch):
    original = NetGuardComponent.evaluate

    async def scenario():
        entered, proceed = asyncio.Event(), asyncio.Event()
        engine = PermissionEngine(config(action="ask"))
        old_component = next(c for c in engine._components if isinstance(c, NetGuardComponent))

        async def pause(self, *args, **kwargs):
            if self is old_component:
                entered.set()
                await proceed.wait()
            return await original(self, *args, **kwargs)

        monkeypatch.setattr(NetGuardComponent, "evaluate", pause)
        pending = asyncio.create_task(engine.check_permission("mcp_fetch_webpage", ARGS))
        await asyncio.wait_for(entered.wait(), timeout=2)
        engine.update_config(config(baseline="deny"))
        new_result = await engine.check_permission("mcp_fetch_webpage", ARGS)
        proceed.set()
        old_result = await asyncio.wait_for(pending, timeout=2)
        assert (old_result.permission, new_result.permission) == (L.ASK, L.DENY)

    asyncio.run(scenario())


def test_real_entrypoints_use_only_supplied_connection_facts(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("permission evaluation attempted network IO")

    engine = PermissionEngine(config())

    async def scenario():
        # Patch after event-loop construction so this checks evaluation itself.
        monkeypatch.setattr(socket, "getaddrinfo", forbidden)
        monkeypatch.setattr(socket, "create_connection", forbidden)
        assert (await engine.check_permission("network_connect", CONNECTION)).permission is L.ALLOW
        assert (await engine.evaluate_global_policy_directly("network_connect", CONNECTION))[
            0
        ] is L.ALLOW

    asyncio.run(scenario())


@pytest.mark.performance
@pytest.mark.parametrize("tool", ("fetch_webpage", "network_connect"))
def test_production_entrypoint_latency_at_capacity(tool):
    engine = PermissionEngine(
        {
            "tools": {"fetch_webpage": "allow"},
            "package_builtin_rules": False,
            "net_guard": {
                "enabled": True,
                "urls": {f"*host{i}.example.com": "deny" for i in range(10000)},
            },
        }
    )
    prefix = "https://host9999.example.com/"
    args = {
        "url": prefix + "a" * (8192 - len(prefix)),
        "resolved_addresses": [f"8.8.8.{i}" for i in range(1, 65)],
        "connect_address": "8.8.8.8",
    }

    async def measure():
        for _ in range(30):
            await engine.check_permission(tool, args)
        samples = []
        for _ in range(500):
            started = perf_counter_ns()
            result = await engine.check_permission(tool, args)
            samples.append((perf_counter_ns() - started) / 1_000_000)
            assert result.permission is L.DENY
        return sorted(samples)

    samples = asyncio.run(measure())
    p50, p99 = median(samples), samples[int(len(samples) * 0.99) - 1]
    print(f"W3 production {tool} latency: P50={p50:.3f}ms P99={p99:.3f}ms")
    assert p50 < 1.0
    assert p99 < 5.0
