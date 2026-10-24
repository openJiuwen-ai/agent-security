# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Capacity boundaries and reproducible, IO-free decision timing."""

import asyncio
from statistics import median
from time import perf_counter_ns

import pytest

from agent_shield.tool_permission import PermissionLevel as L

from .test_net_guard import checker, evaluate


def test_url_length_boundary():
    prefix = "https://example.com/"
    url = prefix + "a" * (8192 - len(prefix))
    assert evaluate(checker(), url).permission is L.ALLOW
    result = evaluate(checker(), url + "a")
    assert result.permission is L.DENY
    assert result.matched_rule == "net_guard:url_too_long"
    with pytest.raises(ValueError):
        checker({url + "a": "deny"})


def test_effective_rule_limit_includes_package_rules_and_rolls_back():
    rules = {f"host{i}.example.com": "deny" for i in range(9996)}
    component = checker(rules)
    assert evaluate(component, "https://host9995.example.com").permission is L.DENY
    with pytest.raises(ValueError):
        component.configure(
            {"net_guard": {"enabled": True, "urls": {**rules, "extra.example.com": "allow"}}}
        )
    assert evaluate(component, "https://host9995.example.com").permission is L.DENY
    assert (
        evaluate(
            checker({f"h{i}.example.com": "allow" for i in range(10000)}, include_package=False),
            "https://h9999.example.com",
        ).permission
        is L.ALLOW
    )
    with pytest.raises(ValueError):
        checker({f"h{i}.example.com": "allow" for i in range(10001)}, include_package=False)


def test_determinism_and_stable_matching_evidence():
    component = checker({"*.example.com": "ask", "api.example.com": "ask"})

    async def sample():
        return [
            await component.evaluate("mcp_fetch_webpage", {"url": "https://api.example.com"})
            for _ in range(20)
        ]

    results = asyncio.run(sample())
    assert all(result == results[0] for result in results)
    assert "net_guard:url:*.example.com" in results[0].matched_rule
    assert "net_guard:url:api.example.com" in results[0].matched_rule


@pytest.mark.performance
@pytest.mark.parametrize("distribution", ["exact", "glob_suffix", "glob_prefix"])
def test_decision_latency_at_capacity(distribution):
    # Each rule distribution exercises capacity, while the call also
    # exercises 64 DNS answers and the maximum URL length. No loop startup is timed.
    patterns = {
        "exact": lambda i: f"host{i}.example.com",
        "glob_suffix": lambda i: f"*host{i}.example.com",
        "glob_prefix": lambda i: f"host{i}.example.*",
    }
    rules = {patterns[distribution](i): "deny" for i in range(9996)}
    component = checker(rules)
    prefix = "https://host9995.example.com/"
    args = {
        "url": prefix + "a" * (8192 - len(prefix)),
        "resolved_addresses": [f"8.8.8.{i}" for i in range(1, 65)],
        "connect_address": "8.8.8.8",
    }

    async def measure():
        for _ in range(30):
            await component.evaluate("network_connect", args)
        samples = []
        for _ in range(500):
            started = perf_counter_ns()
            result = await component.evaluate("network_connect", args)
            samples.append((perf_counter_ns() - started) / 1_000_000)
            assert result.permission is L.DENY
        return sorted(samples)

    samples = asyncio.run(measure())
    p50, p99 = median(samples), samples[int(len(samples) * 0.99) - 1]
    print(f"W3 {distribution} capacity decision latency: P50={p50:.3f}ms P99={p99:.3f}ms")
    assert p50 < 1.0
    assert p99 < 5.0
