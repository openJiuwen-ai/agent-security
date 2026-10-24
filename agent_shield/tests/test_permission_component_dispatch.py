# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Every matching component participates in execution and raw queries."""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.netguard.iptext import ipv4
from agent_shield.tool_permission.routing import RouteInterest, SecurityTarget


class _DenyGuard:
    def __init__(self, target):
        self.interests = (RouteInterest(target),)
        self.calls = []

    def configure(self, config):
        pass

    async def evaluate(self, tool_name, tool_args, *, route=None):
        self.calls.append((tool_name, route))
        return PermissionResult(PermissionLevel.DENY, "administrative_deny")


class _LegacyDenyGuard(_DenyGuard):
    async def evaluate(self, tool_name, tool_args):
        self.calls.append((tool_name, None))
        return PermissionResult(PermissionLevel.DENY, "administrative_deny")


@pytest.mark.parametrize("target", (SecurityTarget.ALL, SecurityTarget.NETWORK))
@pytest.mark.parametrize("legacy", (False, True))
@pytest.mark.parametrize("tool", ("mcp_fetch_webpage", "network_connect"))
@pytest.mark.parametrize("method", ("check_permission", "evaluate_global_policy_directly"))
def test_network_calls_keep_every_matching_guard(target, legacy, tool, method):
    guard = (_LegacyDenyGuard if legacy else _DenyGuard)(target)

    class GuardedEngine(PermissionEngine):
        def _build_components(self):
            return (*super()._build_components(), guard)

    engine = GuardedEngine(
        {
            "tools": {"mcp_fetch_webpage": "allow"},
            "net_guard": {"enabled": True},
        }
    )
    args = {
        "url": "https://example.com/",
        "resolved_addresses": [ipv4(8, 8, 8, 8)],
        "connect_address": ipv4(8, 8, 8, 8),
    }
    result = asyncio.run(getattr(engine, method)(tool, args))
    decision = (
        (result.permission, result.matched_rule) if isinstance(result, PermissionResult) else result
    )
    assert decision == (PermissionLevel.DENY, "administrative_deny")
    assert len(guard.calls) == 1
    if not legacy:
        assert guard.calls[0][1].target is SecurityTarget.NETWORK


def test_raw_query_runs_an_ordinary_file_component_even_when_engine_is_disabled():
    guard = _DenyGuard(SecurityTarget.FILE)

    class GuardedEngine(PermissionEngine):
        def _build_components(self):
            return (*super()._build_components(), guard)

    engine = GuardedEngine({"enabled": False})
    assert (
        asyncio.run(engine.check_permission("read_file", {"path": "example"})).permission
        is PermissionLevel.ALLOW
    )
    assert guard.calls == []
    assert asyncio.run(
        engine.evaluate_global_policy_directly("read_file", {"path": "example"})
    ) == (PermissionLevel.DENY, "administrative_deny")
    assert len(guard.calls) == 1
