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
    for value in cidrs:
        networks.append(ipaddress.ip_network(value))
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
# Fixed IPv4 registry. Walking ipaddress.is_global on every answer follows
# whichever special-purpose list that Python build shipped, and it dominates
# a 64-address decision. These prefixes are the ranges that classifier
# already treats as not public.
_NON_PUBLIC_V4 = _ip_networks((
    cidr(ipv4(0, 0, 0, 0), 8),
    cidr(ipv4(100, 64, 0, 0), 10),
    cidr(ipv4(169, 254, 0, 0), 16),
    cidr(ipv4(192, 0, 2, 0), 24),
    cidr(ipv4(198, 18, 0, 0), 15),
    cidr(ipv4(198, 51, 100, 0), 24),
    cidr(ipv4(203, 0, 113, 0), 24),
    cidr(ipv4(224, 0, 0, 0), 3),
))


def _v4_prefix(network: ipaddress.IPv4Network) -> tuple[int, int]:
    return int(network.network_address), int(network.netmask)


def _in_prefix(packed: int, prefix: tuple[int, int]) -> bool:
    base, mask = prefix
    return packed & mask == base


_FORBIDDEN_V4 = frozenset(
    int(item) for item in _FORBIDDEN_ENDPOINTS if isinstance(item, ipaddress.IPv4Address)
)
_RELAY_PREFIX = _v4_prefix(_DEPRECATED_RELAY)
_SPECIAL_PREFIX = _v4_prefix(_SPECIAL_V4)
_SPECIAL_PUBLIC_V4 = frozenset(int(item) for item in _SPECIAL_V4_PUBLIC)
_LOOPBACK_V4 = _v4_prefix(ipaddress.ip_network(cidr(ipv4(127, 0, 0, 0), 8)))
_PRIVATE_V4_PREFIXES = tuple(_v4_prefix(network) for network in _PRIVATE_V4)
_NON_PUBLIC_V4_PREFIXES = tuple(_v4_prefix(network) for network in _NON_PUBLIC_V4)
_V4_PUBLIC = 0
_V4_BLOCKED = 1
_V4_LOOPBACK = 2
_V4_PRIVATE = 3
_V4_MIXED = 4
_V4_CLASS_NAME = ("public", "blocked", "loopback", "private")


def _fill_v4_hi(table: bytearray, base: int, mask: int, code: int) -> None:
    """Paint prefixes of /16 or shorter. Longer prefixes stay on the slow path."""

    prefix_len = mask.bit_count()
    if prefix_len > 16:
        return
    count = 1 << (16 - prefix_len)
    start = base >> 16
    table[start:start + count] = bytes([code]) * count


def _mark_v4_mixed(table: bytearray, base: int) -> None:
    hi = base >> 16
    if table[hi] == _V4_PUBLIC:
        table[hi] = _V4_MIXED


def _build_v4_hi() -> bytes:
    table = bytearray(65536)
    loop_base, loop_mask = _LOOPBACK_V4
    _fill_v4_hi(table, loop_base, loop_mask, _V4_LOOPBACK)
    for base, mask in _PRIVATE_V4_PREFIXES:
        _fill_v4_hi(table, base, mask, _V4_PRIVATE)
    for base, mask in _NON_PUBLIC_V4_PREFIXES:
        _fill_v4_hi(table, base, mask, _V4_BLOCKED)
    for base, mask in (_RELAY_PREFIX, _SPECIAL_PREFIX):
        _mark_v4_mixed(table, base)
    for base, mask in _NON_PUBLIC_V4_PREFIXES:
        if mask.bit_count() > 16:
            _mark_v4_mixed(table, base)
    for packed in _FORBIDDEN_V4:
        _mark_v4_mixed(table, packed)
    return bytes(table)


_V4_HI = _build_v4_hi()


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


def _v4_class_fine(packed: int) -> str:
    """Classify an address whose /16 contains more than one class."""

    if packed in _FORBIDDEN_V4:
        return "blocked"
    if _in_prefix(packed, _RELAY_PREFIX):
        return "blocked"
    if _in_prefix(packed, _SPECIAL_PREFIX) and packed not in _SPECIAL_PUBLIC_V4:
        return "blocked"
    if _in_prefix(packed, _LOOPBACK_V4):
        return "loopback"
    for prefix in _PRIVATE_V4_PREFIXES:
        if _in_prefix(packed, prefix):
            return "private"
    for prefix in _NON_PUBLIC_V4_PREFIXES:
        if _in_prefix(packed, prefix):
            return "blocked"
    return "public"


def _v4_class(packed: int) -> str:
    """Classify one IPv4 integer without walking ipaddress.is_global."""

    kind = _V4_HI[packed >> 16]
    if kind == _V4_MIXED:
        return _v4_class_fine(packed)
    return _V4_CLASS_NAME[kind]


def _strict_ipv4(value: str) -> int | None:
    """Parse dotted decimal the way IPv4Address does, or return None."""

    parts = value.split(".")
    if len(parts) != 4:
        return None
    packed = 0
    for part in parts:
        not_decimal = not part.isascii() or not part.isdigit()
        leading_zero = len(part) > 1 and part[0] == "0"
        if not_decimal or leading_zero or len(part) > 3:
            return None
        number = int(part)
        if number > 255:
            return None
        packed = (packed << 8) | number
    return packed


def _address_class(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if isinstance(address, ipaddress.IPv4Address):
        return _v4_class(int(address))
    if address in _FORBIDDEN_ENDPOINTS:
        return "blocked"
    if any(address in network for network in (*_IPV6_TRANSITION_NETWORKS, *_NON_PUBLIC_V6)):
        return "blocked"
    if address.is_loopback:
        return "loopback"
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


def _fast_ipv4_classes(supplied: list, selected_raw: object, host: str) -> set[str] | None:
    """Classify a snapshot when every answer is strict dotted IPv4.

    Returns None so the caller can use the general parser for IPv6, mapped
    addresses, and rejected text.
    """

    seen: set[int] = set()
    classes: set[str] = set()
    for value in supplied:
        if not isinstance(value, str):
            raise ValueError("DNS snapshot requires IP strings")
        packed = _strict_ipv4(value)
        if packed is None:
            return None
        seen.add(packed)
        classes.add(_v4_class(packed))
    if not isinstance(selected_raw, str):
        return None
    selected = _strict_ipv4(selected_raw)
    if selected is None:
        return None
    if selected not in seen:
        raise ValueError("Connection address is not in the DNS snapshot")
    if host[:1].isdigit() or ":" in host:
        try:
            literal = ipaddress.ip_address(host)
        except ValueError:
            literal = None
        else:
            if isinstance(literal, ipaddress.IPv6Address) and literal.ipv4_mapped is not None:
                literal = literal.ipv4_mapped
            if not isinstance(literal, ipaddress.IPv4Address) or seen != {int(literal)}:
                raise ValueError("URL IP literal does not match the connection snapshot")
    return classes


def connection_rejection_reason(
    target: UrlTarget,
    args: Mapping[str, object],
    policy: ConnectionPolicy,
) -> str | None:
    """Validate the complete snapshot and selected peer before deciding policy."""
    supplied = args.get("resolved_addresses")
    if not isinstance(supplied, list) or not supplied or len(supplied) > MAX_DNS_ADDRESSES:
        raise ValueError("DNS snapshot must contain 1 to 64 addresses")
    fast_classes = _fast_ipv4_classes(supplied, args.get("connect_address"), target.host)
    if fast_classes is not None:
        return _class_decision(target, fast_classes, policy)
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
    classes = {_address_class(address) for address in addresses}
    return _class_decision(target, classes, policy)


def _class_decision(target: UrlTarget, classes: set[str], policy: ConnectionPolicy) -> str | None:
    if target.host == "metadata.google.internal" or target.host.endswith(
        ".metadata.google.internal"
    ):
        return "metadata_host_not_allowed"
    if target.scheme == "http" and not policy.allow_http:
        return "http_not_allowed"
    if classes == {"public"}:
        return None
    if classes == {"loopback"} and policy.allow_loopback:
        return None
    if classes == {"private"} and policy.allow_private_network:
        return None
    return "address_not_allowed"
