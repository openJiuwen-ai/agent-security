# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Project host permission rules onto a sandbox policy fragment.

NetGuard and FileGuard rules that are a single host or an absolute path become
sandbox domain and filesystem lists. Command guards, globs, path-specific URL
rules, and ASK stay in ``skipped``: the sandbox enforces lists, and those
decisions still run on the host per request.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from .models import PermissionLevel
from .netguard.builtin_rules import package_rules_enabled
from .netguard.net_urls import build_net_urls

_HOST_ONLY_SECTIONS = (
    ("host_guard", "host_guard"),
    ("tool_guard", "tool_guard"),
    ("command_allowlist", "tool_guard"),
    ("destructive_warning", "tool_guard"),
    ("injection", "tool_guard"),
    ("tiered", "tool_guard"),
)


@dataclass(frozen=True, slots=True)
class SkippedSandboxRule:
    """A host rule the sandbox policy cannot enforce."""

    component: str
    rule: str
    permission: str
    reason: str


@dataclass(slots=True)
class SandboxPolicyProjection:
    """Domain and path lists plus the rules left on the host."""

    allow_domains: list[str] = field(default_factory=list)
    deny_domains: list[str] = field(default_factory=list)
    allow_ips: list[str] = field(default_factory=list)
    deny_ips: list[str] = field(default_factory=list)
    allow_read: list[str] = field(default_factory=list)
    allow_write: list[str] = field(default_factory=list)
    deny_read: list[str] = field(default_factory=list)
    deny_write: list[str] = field(default_factory=list)
    skipped: list[SkippedSandboxRule] = field(default_factory=list)

    def to_policy_fragment(self) -> dict[str, Any]:
        """Fragment for ``PolicyEngine.merge_policy`` (append).

        The same domain and path lists are written to the platform-neutral
        ``network.egress`` and to ``windows``, so Linux and Windows sandboxes
        both receive them.
        """
        egress = {
            "allowed_domains": list(self.allow_domains),
            "blocked_domains": list(self.deny_domains),
            "allowed_ips": list(self.allow_ips),
            "blocked_ips": list(self.deny_ips),
        }
        filesystem = {
            "allow_read": list(self.allow_read),
            "allow_write": list(self.allow_write),
            "deny_read": list(self.deny_read),
            "deny_write": list(self.deny_write),
        }
        return {
            "network": {"egress": egress},
            "windows": {
                "network": {"egress": egress},
                "filesystem": filesystem,
            },
        }


def project_sandbox_policy(config: Mapping[str, Any]) -> SandboxPolicyProjection:
    """Build a sandbox fragment from a PermissionEngine config mapping."""
    if not isinstance(config, Mapping):
        raise TypeError("permission config must be a mapping")
    projected = SandboxPolicyProjection()
    _project_net_guard(config, projected)
    _project_file_guard(config, projected)
    _project_host_only(config, projected)
    return projected


def _project_net_guard(config: Mapping[str, Any], projected: SandboxPolicyProjection) -> None:
    section = config.get("net_guard", {})
    if not isinstance(section, Mapping):
        raise ValueError("net_guard must be a mapping")
    enabled = section.get("enabled", False)
    if type(enabled) is not bool:
        raise ValueError("net_guard.enabled must be a boolean")
    if not enabled:
        return

    default = str(section.get("defaults", "allow")).strip().lower()
    if default != "allow":
        projected.skipped.append(SkippedSandboxRule(
            "net_guard",
            "defaults",
            default,
            "per-request default is not a domain list",
        ))
    connection = section.get("connection")
    if isinstance(connection, Mapping) and connection:
        projected.skipped.append(SkippedSandboxRule(
            "net_guard",
            "connection",
            "deny",
            "connection checks run per request on the host",
        ))

    rules = build_net_urls(
        section.get("urls", {}),
        include_package=package_rules_enabled(config.get("package_builtin_rules")),
    )
    for rule in rules:
        permission = rule.action.value
        if rule.host_glob is not None:
            _skip(projected, "net_guard", rule.pattern, permission, "host glob is not a sandbox domain")
            continue
        if _url_is_narrower_than_host(rule):
            _skip(
                projected,
                "net_guard",
                rule.pattern,
                permission,
                "path or query rule is narrower than a domain",
            )
            continue
        if permission in {PermissionLevel.ASK.value, PermissionLevel.UNDETERMINED.value}:
            _skip(projected, "net_guard", rule.pattern, permission, "ASK stays on the host")
            continue
        _add_host(projected, rule.host, allow=permission == PermissionLevel.ALLOW.value)


def _url_is_narrower_than_host(rule: Any) -> bool:
    target = rule.target
    if target is None:
        return False
    if target.has_query:
        return True
    path = str(target.path or "")
    return path not in {"", "/"}


def _add_host(projected: SandboxPolicyProjection, host: str, *, allow: bool) -> None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        bucket = projected.allow_domains if allow else projected.deny_domains
        _append_unique(bucket, host)
        return
    suffix = "/128" if address.version == 6 else "/32"
    bucket = projected.allow_ips if allow else projected.deny_ips
    _append_unique(bucket, f"{address}{suffix}")


def _project_file_guard(config: Mapping[str, Any], projected: SandboxPolicyProjection) -> None:
    section = config.get("file_guard", {})
    if not isinstance(section, Mapping) or section.get("enabled") is False:
        return
    paths = section.get("paths")
    if not isinstance(paths, list):
        return
    for item in paths:
        if not isinstance(item, Mapping):
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue
        path = raw_path.strip()
        if item.get("match") == "glob" or "*" in path or "?" in path:
            _skip(projected, "file_guard", path, "ask", "glob path is not a sandbox filesystem entry")
            continue
        if not _is_absolute_path(path):
            _skip(projected, "file_guard", path, "ask", "relative path is resolved per request")
            continue
        read = str(item.get("read", "allow")).strip().lower()
        write = str(item.get("write", "allow")).strip().lower()
        if read == "deny":
            write = "deny"
        _place_path(projected, path, read, is_write=False)
        _place_path(projected, path, write, is_write=True)


def _place_path(
    projected: SandboxPolicyProjection,
    path: str,
    level: str,
    *,
    is_write: bool,
) -> None:
    axis = "write" if is_write else "read"
    if level == PermissionLevel.ALLOW.value:
        _append_unique(projected.allow_write if is_write else projected.allow_read, path)
        return
    if level == PermissionLevel.DENY.value:
        _append_unique(projected.deny_write if is_write else projected.deny_read, path)
        return
    _skip(projected, "file_guard", path, level, f"{axis} {level} stays on the host")


def _project_host_only(config: Mapping[str, Any], projected: SandboxPolicyProjection) -> None:
    seen: set[str] = set()
    for key, component in _HOST_ONLY_SECTIONS:
        section = config.get(key)
        if not isinstance(section, Mapping) or section.get("enabled") is False:
            continue
        if component in seen:
            continue
        seen.add(component)
        projected.skipped.append(SkippedSandboxRule(
            component,
            key,
            "ask",
            "command rules run per request on the host",
        ))


def _is_absolute_path(path: str) -> bool:
    if path.startswith("/") and not path.startswith("//"):
        return True
    return len(path) > 2 and path[1] == ":" and path[2] in {"\\", "/"}


def _append_unique(items: list[str], value: str) -> None:
    if value not in items:
        items.append(value)


def _skip(
    projected: SandboxPolicyProjection,
    component: str,
    rule: str,
    permission: str,
    reason: str,
) -> None:
    projected.skipped.append(SkippedSandboxRule(component, rule, permission, reason))
