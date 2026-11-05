# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Shared outbound policy: protected targets, actual exits and effective rules.

Scenario provenance: jiuwenswarm xiaoyi_0.2.4.beta3.security commit
15d51f7618a8191ed3b77a74a07443cb25f2eb7e,
locking agent-core c6c64455f325777fa9fa353a4cf65a4cee7f6494.
Cases cover permissions_config_rpc.py / permissions_persist.py host settings,
web_fetch_tools.py / search_tools.py real exit targets, and
jiuwenbox/proxy/target_security.py special-address restrictions.
No reference checkout or network service is needed to execute these tests.
"""

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.netguard.component import NetGuardComponent
from agent_shield.tool_permission.netguard.iptext import ipv4, ipv6

from .test_address_policy import connect
from .test_net_guard import checker, evaluate


@pytest.mark.parametrize(
    "address",
    [
        ipv4(169, 254, 169, 254),
        ipv4(100, 100, 100, 200),
        ipv4(168, 63, 129, 16),
        ipv6("fd00", "ec2", "", "254"),
        ipv6("", "", "ffff", "") + ipv4(168, 63, 129, 16),
        ipv6("", "", "ffff", "") + ipv4(169, 254, 169, 254),
        ipv6("64", "ff9b", "", "a9fe", "a9fe"),
        ipv6("64", "ff9b", "", "808", "808"),
        ipv6("64", "ff9b", "1", "", "a00", "1"),
        ipv6("2002", "a9fe", "a9fe", "", "1"),
        ipv6("2002", "808", "808", "", "1"),
        ipv6("2001", "0", "4136", "e378", "8000", "63bf", "3fff", "fdd2"),
    ],
)
def test_metadata_and_transition_addresses_stay_blocked(address):
    component = checker(
        {"example.com": "allow"},
        connection={
            "allow_http": True,
            "allow_private_network": True,
            "allow_loopback": True,
        },
    )
    assert connect(component, [address]).permission is L.DENY
    assert connect(component, [ipv4(8, 8, 8, 8), address]).permission is L.DENY


@pytest.mark.parametrize("enforce_host_exit", [False, True])
def test_host_exit_settings_do_not_disable_url_policy(enforce_host_exit):
    component = NetGuardComponent()
    component.configure(
        {
            "enabled": True,
            "net_guard": {
                "enabled": True,
                "enforce_host_exit": enforce_host_exit,
                "max_request_mb": 10,
                "timeout_seconds": 30,
                "defaults": "ask",
                "urls": {"blocked.example.com": "deny", "allowed.example.com": "allow"},
            },
        }
    )
    assert evaluate(component, "https://blocked.example.com").permission is L.DENY
    assert evaluate(component, "https://allowed.example.com").permission is L.ALLOW
    assert evaluate(component, "https://other.example.com").permission is L.ASK


def test_reader_fallback_checks_its_actual_exit_target():
    # Swarm may retry 401/403/429 pages via r.jina.ai; input approval alone
    # must not authorize that second HTTP origin.
    component = checker({"original.example.com": "allow", "r.jina.ai": "deny"})
    assert evaluate(component, "https://original.example.com/page").permission is L.ALLOW
    assert (
        connect(
            component, [ipv4(8, 8, 8, 8)], url="https://r.jina.ai/https://original.example.com/page"
        ).permission
        is L.DENY
    )


def test_search_uses_exit_policy_without_pretending_query_is_a_fetch_url():
    component = checker({"search.example.com": "deny"})
    assert evaluate(component, tool="mcp_free_search", args={"query": "public news"}) is None
    assert (
        connect(component, [ipv4(8, 8, 8, 8)], url="https://search.example.com/?q=news").permission
        is L.DENY
    )


def test_effective_rules_are_not_recomposed_from_source_metadata():
    component = NetGuardComponent()
    component.configure(
        {
            "net_guard": {
                "enabled": True,
                "defaults": "allow",
                "urls": {
                    "api.example.com": "allow",
                    "*.example.com": "ask",
                },
            },
            "composition": {
                "schema_version": 1,
                "revision": "synthetic-reference",
                "source_order": ["user", "cloud", "builtin"],
                "net_url_layers": {"api.example.com": "user", "*.example.com": "cloud"},
            },
        }
    )
    # W1a's chosen target semantics supersede the old source-order shortcut:
    # independent matching objects still contribute ASK even when user allows.
    assert evaluate(component, "https://api.example.com").permission is L.ASK
