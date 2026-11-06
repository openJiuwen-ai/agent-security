"""Hostname glob and CIDR matching. No reverse DNS."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def endpoint_host(effect: dict) -> str | None:
    host = effect.get("host")
    if isinstance(host, str) and host.strip():
        return host.strip().rstrip(".")
    url = effect.get("url")
    if isinstance(url, str) and url:
        hostname = urlsplit(url).hostname
        if hostname:
            return hostname.rstrip(".")
    return None


def endpoint_ip(effect: dict) -> str | None:
    ip = effect.get("ip")
    if isinstance(ip, str) and ip.strip():
        return ip.strip()
    host = endpoint_host(effect)
    if host and _is_ip(host):
        return host
    return None


def host_in_patterns(host: str | None, patterns: tuple[str, ...] | list[str]) -> bool:
    if not host:
        return False
    candidate = host.rstrip(".").casefold()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    for pattern in patterns:
        needle = str(pattern).rstrip(".").casefold()
        if needle.startswith("*."):
            suffix = needle[1:]
            base = needle[2:]
            if candidate.endswith(suffix) and candidate != base:
                label = candidate[: -len(suffix)]
                if label and "." not in label:
                    return True
        elif candidate == needle:
            return True
    return False


def ip_in_cidrs(ip: str | None, cidrs: tuple[str, ...] | list[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        if address in network:
            return True
    return False


def endpoint_in_catalogs(effect: dict, names: list[str], catalogs: dict) -> bool:
    host = endpoint_host(effect)
    ip = endpoint_ip(effect)
    for name in names:
        entries = catalogs.get(name) or ()
        if name.endswith("_hosts"):
            if host_in_patterns(host, entries):
                return True
        elif name.endswith("_cidrs"):
            if ip_in_cidrs(ip, entries):
                return True
        else:
            if host_in_patterns(host, entries) or ip_in_cidrs(ip, entries):
                return True
    return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
