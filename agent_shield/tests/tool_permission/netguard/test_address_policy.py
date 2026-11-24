# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Connection snapshots, address classes and per-hop DNS validation."""

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.netguard.iptext import ipv4, ipv6

from .test_net_guard import checker, evaluate


def connect(component, addresses, *, selected=None, url="https://example.com"):
    return evaluate(
        component,
        tool="network_connect",
        args={
            "url": url,
            "resolved_addresses": addresses,
            "connect_address": selected if selected is not None else addresses[0],
        },
    )


@pytest.mark.parametrize(
    "address, allowed",
    [
        (ipv4(8, 8, 8, 8), True),
        (ipv4(1, 1, 1, 1), True),
        (ipv6("2001", "4860", "4860", "", "8888"), True),
        (ipv6("", "", "ffff", "") + ipv4(8, 8, 8, 8), True),
        (ipv4(127, 0, 0, 2), False),
        (ipv6("", "", "1"), False),
        (ipv6("", "", "ffff", "") + ipv4(127, 0, 0, 1), False),
        (ipv4(10, 2, 3, 4), False),
        (ipv4(172, 16, 0, 1), False),
        (ipv4(192, 168, 1, 1), False),
        (ipv4(169, 254, 169, 254), False),
        (ipv4(169, 254, 1, 2), False),
        (ipv6("fc00", "", "1"), False),
        (ipv6("fe80", "", "1"), False),
        (ipv4(0, 0, 0, 0), False),
        (ipv6("", "", ""), False),
        (ipv4(224, 0, 0, 1), False),
        (ipv6("ff02", "", "1"), False),
        (ipv4(240, 0, 0, 1), False),
        (ipv4(100, 64, 0, 1), False),
        (ipv4(192, 0, 2, 1), False),
        (ipv6("2001", "db8", "", "1"), False),
    ],
)
def test_default_public_only_policy(address, allowed):
    result = connect(checker(), [address])
    assert result.permission is (L.ALLOW if allowed else L.DENY)


def test_all_answers_are_checked_and_mixed_classes_never_pass():
    component = checker(connection={"allow_private_network": True, "allow_loopback": True})
    assert connect(component, [ipv4(8, 8, 8, 8), ipv4(10, 1, 2, 3)]).permission is L.DENY
    assert connect(component, [ipv4(127, 0, 0, 1), ipv4(10, 1, 2, 3)]).permission is L.DENY
    assert connect(component, [ipv4(8, 8, 8, 8), ipv4(169, 254, 169, 254)]).permission is L.DENY
    assert connect(component, [ipv4(8, 8, 8, 8), ipv4(1, 1, 1, 1)], selected=ipv4(1, 1, 1, 1)).permission is L.ALLOW


def test_exceptions_are_explicit_and_independent():
    private = checker(connection={"allow_private_network": True})
    assert connect(private, [ipv4(10, 1, 2, 3), ipv4(192, 168, 1, 2)]).permission is L.ALLOW
    assert connect(private, [ipv6("fc00", "", "1")]).permission is L.DENY
    assert connect(private, [ipv4(127, 0, 0, 2)]).permission is L.DENY
    assert connect(private, [ipv4(10, 1, 2, 3)], url="http://example.com").permission is L.DENY
    loopback = checker({"localhost": "allow"}, connection={"allow_loopback": True})
    assert connect(loopback, [ipv4(127, 0, 0, 1), ipv6("", "", "1")], url="https://localhost").permission is L.ALLOW
    assert (
        connect(checker({"localhost": "allow"}), [ipv4(127, 0, 0, 1)], url="https://localhost").permission
        is L.DENY
    )
    assert (
        connect(
            checker(connection={"allow_http": True}), [ipv4(8, 8, 8, 8)], url="http://example.com"
        ).permission
        is L.ALLOW
    )


@pytest.mark.parametrize(
    "args",
    [
        {"url": "https://example.com"},
        {"url": "https://example.com", "resolved_addresses": []},
        {
            "url": "https://example.com",
            "resolved_addresses": ipv4(8, 8, 8, 8),
            "connect_address": ipv4(8, 8, 8, 8),
        },
        {"url": "https://example.com", "resolved_addresses": [ipv4(8, 8, 8, 8)]},
        {
            "url": "https://example.com",
            "resolved_addresses": [ipv4(8, 8, 8, 8)],
            "connect_address": ipv4(1, 1, 1, 1),
        },
        {
            "url": "https://example.com",
            "resolved_addresses": [ipv4(8, 8, 8, 8), "bad"],
            "connect_address": ipv4(8, 8, 8, 8),
        },
        {
            "url": "https://example.com",
            "resolved_addresses": [ipv6("fe80", "", "1") + "%eth0"],
            "connect_address": ipv6("fe80", "", "1") + "%eth0",
        },
        {"url": "https://example.com", "resolved_addresses": [123], "connect_address": ipv4(8, 8, 8, 8)},
        {"url": "https://" + ipv4(8, 8, 8, 8),
            "resolved_addresses": [ipv4(1, 1, 1, 1)],
            "connect_address": ipv4(1, 1, 1, 1)},
        {
            "url": "https://" + ipv4(8, 8, 8, 8),
            "resolved_addresses": [ipv4(8, 8, 8, 8), ipv4(1, 1, 1, 1)],
            "connect_address": ipv4(8, 8, 8, 8),
        },
    ],
)
def test_invalid_connection_facts_raise_without_a_decision(args):
    with pytest.raises(ValueError):
        evaluate(checker(), tool="network_connect", args=args)


def test_snapshot_limit_is_checked_before_deduplication():
    assert connect(checker(), [ipv4(8, 8, 8, 8)] * 64).permission is L.ALLOW
    with pytest.raises(ValueError):
        connect(checker(), [ipv4(8, 8, 8, 8)] * 65)


def test_ip_literal_equivalence_and_mapping():
    assert (
        connect(
            checker(), [ipv6("2001", "4860", "4860", "", "8888")], url="https://[" + ipv6("2001",
                "4860",
                "4860",
                "0",
                "0",
                "0",
                "0",
                "8888") + "]"
        ).permission
        is L.ALLOW
    )
    assert connect(checker(),
        [ipv4(8, 8, 8, 8)],
        url="https://[" + ipv6("", "", "ffff", "") + ipv4(8, 8, 8, 8) + "]").permission is L.ALLOW


def test_url_policy_still_participates_in_connection_decision():
    assert connect(checker({"example.com": "deny"}), [ipv4(8, 8, 8, 8)]).permission is L.DENY
    assert connect(checker({"example.com": "ask"}), [ipv4(8, 8, 8, 8)]).permission is L.ASK
    assert connect(checker({"example.com": "ask"}), [ipv4(10, 1, 2, 3)]).permission is L.DENY


def test_rebinding_reconnect_and_redirect_cannot_reuse_an_old_allow():
    component = checker({"example.com": "allow"})
    assert connect(component, [ipv4(8, 8, 8, 8)]).permission is L.ALLOW
    assert connect(component, [ipv4(127, 0, 0, 1)]).permission is L.DENY
    assert connect(component, [ipv4(8, 8, 8, 8)]).permission is L.ALLOW
    assert (
        connect(component, [ipv4(169, 254, 169, 254)], url="https://redirect.example").permission is L.DENY
    )
