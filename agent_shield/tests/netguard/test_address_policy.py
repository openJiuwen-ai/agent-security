"""Connection snapshots, address classes and per-hop DNS validation."""

import pytest

from agent_shield.tool_permission import PermissionLevel as L

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
        ("8.8.8.8", True),
        ("1.1.1.1", True),
        ("2001:4860:4860::8888", True),
        ("::ffff:8.8.8.8", True),
        ("127.0.0.2", False),
        ("::1", False),
        ("::ffff:127.0.0.1", False),
        ("10.2.3.4", False),
        ("172.16.0.1", False),
        ("192.168.1.1", False),
        ("169.254.169.254", False),
        ("169.254.1.2", False),
        ("fc00::1", False),
        ("fe80::1", False),
        ("0.0.0.0", False),
        ("::", False),
        ("224.0.0.1", False),
        ("ff02::1", False),
        ("240.0.0.1", False),
        ("100.64.0.1", False),
        ("192.0.2.1", False),
        ("2001:db8::1", False),
    ],
)
def test_default_public_only_policy(address, allowed):
    result = connect(checker(), [address])
    assert result.permission is (L.ALLOW if allowed else L.DENY)


def test_all_answers_are_checked_and_mixed_classes_never_pass():
    component = checker(connection={"allow_private_network": True, "allow_loopback": True})
    assert connect(component, ["8.8.8.8", "10.1.2.3"]).permission is L.DENY
    assert connect(component, ["127.0.0.1", "10.1.2.3"]).permission is L.DENY
    assert connect(component, ["8.8.8.8", "169.254.169.254"]).permission is L.DENY
    assert connect(component, ["8.8.8.8", "1.1.1.1"], selected="1.1.1.1").permission is L.ALLOW


def test_exceptions_are_explicit_and_independent():
    private = checker(connection={"allow_private_network": True})
    assert connect(private, ["10.1.2.3", "192.168.1.2"]).permission is L.ALLOW
    assert connect(private, ["fc00::1"]).permission is L.DENY
    assert connect(private, ["127.0.0.2"]).permission is L.DENY
    assert connect(private, ["10.1.2.3"], url="http://example.com").permission is L.DENY
    loopback = checker({"localhost": "allow"}, connection={"allow_loopback": True})
    assert connect(loopback, ["127.0.0.1", "::1"], url="https://localhost").permission is L.ALLOW
    assert (
        connect(checker({"localhost": "allow"}), ["127.0.0.1"], url="https://localhost").permission
        is L.DENY
    )
    assert (
        connect(
            checker(connection={"allow_http": True}), ["8.8.8.8"], url="http://example.com"
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
            "resolved_addresses": "8.8.8.8",
            "connect_address": "8.8.8.8",
        },
        {"url": "https://example.com", "resolved_addresses": ["8.8.8.8"]},
        {
            "url": "https://example.com",
            "resolved_addresses": ["8.8.8.8"],
            "connect_address": "1.1.1.1",
        },
        {
            "url": "https://example.com",
            "resolved_addresses": ["8.8.8.8", "bad"],
            "connect_address": "8.8.8.8",
        },
        {
            "url": "https://example.com",
            "resolved_addresses": ["fe80::1%eth0"],
            "connect_address": "fe80::1%eth0",
        },
        {"url": "https://example.com", "resolved_addresses": [123], "connect_address": "8.8.8.8"},
        {"url": "https://8.8.8.8", "resolved_addresses": ["1.1.1.1"], "connect_address": "1.1.1.1"},
        {
            "url": "https://8.8.8.8",
            "resolved_addresses": ["8.8.8.8", "1.1.1.1"],
            "connect_address": "8.8.8.8",
        },
    ],
)
def test_invalid_connection_facts_raise_without_a_decision(args):
    with pytest.raises(ValueError):
        evaluate(checker(), tool="network_connect", args=args)


def test_snapshot_limit_is_checked_before_deduplication():
    assert connect(checker(), ["8.8.8.8"] * 64).permission is L.ALLOW
    with pytest.raises(ValueError):
        connect(checker(), ["8.8.8.8"] * 65)


def test_ip_literal_equivalence_and_mapping():
    assert (
        connect(
            checker(), ["2001:4860:4860::8888"], url="https://[2001:4860:4860:0:0:0:0:8888]"
        ).permission
        is L.ALLOW
    )
    assert connect(checker(), ["8.8.8.8"], url="https://[::ffff:8.8.8.8]").permission is L.ALLOW


def test_url_policy_still_participates_in_connection_decision():
    assert connect(checker({"example.com": "deny"}), ["8.8.8.8"]).permission is L.DENY
    assert connect(checker({"example.com": "ask"}), ["8.8.8.8"]).permission is L.ASK
    assert connect(checker({"example.com": "ask"}), ["10.1.2.3"]).permission is L.DENY


def test_rebinding_reconnect_and_redirect_cannot_reuse_an_old_allow():
    component = checker({"example.com": "allow"})
    assert connect(component, ["8.8.8.8"]).permission is L.ALLOW
    assert connect(component, ["127.0.0.1"]).permission is L.DENY
    assert connect(component, ["8.8.8.8"]).permission is L.ALLOW
    assert (
        connect(component, ["169.254.169.254"], url="https://redirect.example").permission is L.DENY
    )
