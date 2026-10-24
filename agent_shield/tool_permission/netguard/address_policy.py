# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Validate host-provided DNS snapshots without making network calls."""

# All invalid configuration/action inputs follow W3's ValueError contract.
# ruff: noqa: TRY004

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass

from .iptext import cidr, ipv4, ipv6
from .url_safety import UrlTarget

MAX_DNS_ADDRESSES = 64


def _ip_networks(cidrs: tuple[str, ...]) -> tuple:
    """Build IP networks from CIDR text."""

    networks = []
    for cidr in cidrs:
        networks.append(ipaddress.ip_network(cidr))
    return tuple(networks)


def _ip_addresses(values: tuple[str, ...]) -> frozenset:
    """Build IP addresses from literal text."""

    addresses = []
    for value in values:
        addresses.append(ipaddress.ip_address(value))
    return frozenset(addresses)


_PRIVATE_V4 = _ip_networks((
    cidr(ipv4(10, 0, 0, 0), 8),
    cidr(ipv4(172, 16, 0, 0), 12),
    cidr(ipv4(192, 168, 0, 0), 16),
))
# Keep the Xiaoyi inference proxy's special-target exclusions explicit rather
# than relying on Python-version-specific is_global/is_reserved classifications.
_FORBIDDEN_ENDPOINTS = _ip_addresses((
    ipv4(100, 100, 100, 200),
    ipv4(168, 63, 129, 16),
    ipv6("fd00", "ec2", "", "254"),
))
_IPV6_TRANSITION_NETWORKS = _ip_networks((
    cidr(ipv6("2002", "", ""), 16),
    cidr(ipv6("2001", "", ""), 32),
    cidr(ipv6("64", "ff9b", "", ""), 96),
    cidr(ipv6("64", "ff9b", "1", "", ""), 48),
))
# Explicit exclusions keep older supported Python registries conservative.
# Sources: IANA IPv4/IPv6 Special-Purpose Address Space, reviewed 2026-10-19.
_SPECIAL_V4 = ipaddress.ip_network(cidr(ipv4(192, 0, 0, 0), 24))
_SPECIAL_V4_PUBLIC = _ip_addresses((
    ipv4(192, 0, 0, 9),
    ipv4(192, 0, 0, 10),
))
_DEPRECATED_RELAY = ipaddress.ip_network(cidr(ipv4(192, 88, 99, 0), 24))
_NON_PUBLIC_V6 = _ip_networks((
    cidr(ipv6("100", "0", "0", "1", "", ""), 64),
    cidr(ipv6("3fff", "", ""), 20),
    cidr(ipv6("5f00", "", ""), 16),
    cidr(ipv6("fec0", "", ""), 10),
))


@dataclass(frozen=True, slots=True)
class ConnectionPolicy:
    allow_http: bool = False
    allow_loopback: bool = False
    allow_private_network: bool = False


def build_connection_policy(value: object) -> ConnectionPolicy:
    if not isinstance(value, Mapping):
        raise ValueError("net_guard.connection must be a mapping")
    fields = {"allow_http", "allow_loopback", "allow_private_network"}
    invalid_type = False
    for item in value.values():
        if not isinstance(item, bool):
            invalid_type = True
            break
    if set(value) - fields or invalid_type:
        raise ValueError("Invalid network connection policy")
    return ConnectionPolicy(**value)


def normalize_address(value: object) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value:
        raise ValueError("DNS snapshot requires IP literals without zones")
    if len(value) > 45 or "%" in value:
        raise ValueError("DNS snapshot requires IP literals without zones")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise ValueError("Invalid IP in connection snapshot") from None
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _address_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if address in _FORBIDDEN_ENDPOINTS:
        return "blocked"
    if isinstance(address, ipaddress.IPv6Address):
        if any(address in network for network in (*_IPV6_TRANSITION_NETWORKS, *_NON_PUBLIC_V6)):
            return "blocked"
    elif address in _DEPRECATED_RELAY or (
        address in _SPECIAL_V4 and address not in _SPECIAL_V4_PUBLIC
    ):
        return "blocked"
    if address.is_loopback:
        return "loopback"
    if isinstance(address, ipaddress.IPv4Address) and any(address in net for net in _PRIVATE_V4):
        return "private"
    if address.is_global and not any(
        (
            address.is_multicast,
            address.is_reserved,
            address.is_link_local,
            address.is_unspecified,
        )
    ):
        return "public"
    return "blocked"


def connection_rejection_reason(
    target: UrlTarget,
    args: Mapping[str, object],
    policy: ConnectionPolicy,
) -> str | None:
    """Validate the complete snapshot and selected peer before deciding policy."""
    supplied = args.get("resolved_addresses")
    if not isinstance(supplied, list) or not supplied or len(supplied) > MAX_DNS_ADDRESSES:
        raise ValueError("DNS snapshot must contain 1 to 64 addresses")
    if any(not isinstance(value, str) for value in supplied):
        raise ValueError("DNS snapshot requires IP strings")
    addresses = frozenset(normalize_address(value) for value in supplied)
    selected = normalize_address(args.get("connect_address"))
    if selected not in addresses:
        raise ValueError("Connection address is not in the DNS snapshot")
    try:
        literal_host = ipaddress.ip_address(target.host)
    except ValueError:
        literal_host = None
    if literal_host is not None and addresses != {normalize_address(target.host)}:
        raise ValueError("URL IP literal does not match the connection snapshot")
    if target.host == "metadata.google.internal" or target.host.endswith(
        ".metadata.google.internal"
    ):
        return "metadata_host_not_allowed"
    classes = {_address_class(address) for address in addresses}
    if target.scheme == "http" and not policy.allow_http:
        return "http_not_allowed"
    if classes == {"public"}:
        return None
    if classes == {"loopback"} and policy.allow_loopback:
        return None
    if classes == {"private"} and policy.allow_private_network:
        return None
    return "address_not_allowed"
