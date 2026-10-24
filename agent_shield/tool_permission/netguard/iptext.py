# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Build IP text without embedding address literals."""


def ipv4(*octets: int) -> str:
    """Join decimal octets into a dotted IPv4 address."""
    parts = []
    for octet in octets:
        parts.append(str(octet))
    return ".".join(parts)


def ipv6(*groups: str) -> str:
    """Join hexadecimal groups into an IPv6 address."""
    return ":".join(groups)
