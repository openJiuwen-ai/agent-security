"""Dispatch an object rule to the file, domain, command, or tool matcher."""

from __future__ import annotations

import ipaddress

from agent_shield.policy_engine.matchers.command import (
    argv_of,
    command_object_matches,
    normalize_program,
    tokenize,
)
from agent_shield.policy_engine.matchers.network import (
    endpoint_host,
    endpoint_ip,
    host_in_patterns,
    ip_in_cidrs,
)
from agent_shield.policy_engine.matchers.paths import (
    event_os,
    glob_match,
    is_within,
    normalize_path,
    paths_equal,
)
from agent_shield.policy_engine.matchers.tools import matches_native_tool
from agent_shield.policy_engine.models.types import ObjectRule

_FILE_OP = {"fs.read": "read", "fs.write": "write", "fs.delete": "delete"}
_NET_OP = {"net.connect": "connect", "net.fetch": "fetch", "net.egress": "egress"}


def matches_object(rule: ObjectRule, effect: dict, event: dict) -> bool:
    if rule.object == "file":
        return _file(rule, effect, event)
    if rule.object == "domain":
        return _domain(rule, effect)
    if rule.object == "command":
        return _command(rule, effect, event)
    if rule.object == "nativeTools":
        return matches_native_tool(rule, effect, event)
    return False


def _file(rule: ObjectRule, effect: dict, event: dict) -> bool:
    op = _FILE_OP.get(effect.get("type"))
    if op is None or not _op_allowed(rule, op):
        return False
    path = str(effect.get("path") or "")
    os_name = event_os(event)
    if rule.path:
        return paths_equal(rule.path, path, os_name=os_name)
    return any(_path_matches(pattern, path, event) for pattern in rule.pattern)


def _domain(rule: ObjectRule, effect: dict) -> bool:
    op = _NET_OP.get(effect.get("type"))
    if op is None or not _op_allowed(rule, op):
        return False
    if rule.source == "user_grant":
        return _exact_endpoint(rule.hosts[0] if rule.hosts else "", effect)
    host = endpoint_host(effect)
    ip = endpoint_ip(effect)
    return host_in_patterns(host, rule.hosts) or ip_in_cidrs(ip, rule.cidrs)


def _command(rule: ObjectRule, effect: dict, event: dict) -> bool:
    if effect.get("type") != "process.exec":
        return False
    windows = event_os(event) == "windows"
    tokens, has_line = _command_input(effect)
    if rule.tokens:
        return has_line and _exact_tokens(rule.tokens, tokens, windows)
    if not rule.match:
        return False
    return command_object_matches(
        rule.match,
        action=rule.action,
        command_tokens=tokens,
        shell_argv=argv_of(effect),
        windows=windows,
        has_command_line=has_line,
    )


def _op_allowed(rule: ObjectRule, op: str) -> bool:
    if rule.source == "user_grant":
        return len(rule.ops) == 1 and rule.ops[0] == op
    return not rule.ops or op in rule.ops


def _exact_endpoint(expected: str, effect: dict) -> bool:
    if not expected or "*" in expected:
        return False
    host = endpoint_host(effect)
    if host and host.casefold() == expected.casefold():
        return True
    ip = endpoint_ip(effect)
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) == ipaddress.ip_address(expected)
    except ValueError:
        return False


def _command_input(effect: dict) -> tuple[list[str], bool]:
    stored = effect.get("command_tokens")
    if isinstance(stored, list) and stored and all(isinstance(item, str) and item for item in stored):
        return list(stored), True
    line = effect.get("command_line")
    if isinstance(line, str) and line.strip():
        return tokenize(line), True
    return [], False


def _exact_tokens(expected: tuple[str, ...], actual: list[str], windows: bool) -> bool:
    if len(expected) != len(actual):
        return False
    if normalize_program(expected[0], windows) != normalize_program(actual[0], windows):
        return False
    return list(expected[1:]) == actual[1:]


def _path_matches(pattern: str, path: str, event: dict) -> bool:
    os_name = event_os(event)
    if glob_match(pattern, path, os_name=os_name):
        return True
    child = normalize_path(path)
    for root in _roots(event):
        parent = normalize_path(root)
        if not is_within(path, root, os_name=os_name):
            continue
        relative = child[len(parent):].lstrip("/")
        if glob_match(pattern, relative, os_name=os_name):
            return True
    return False


def _roots(event: dict) -> list[str]:
    workspace = event.get("workspace") if isinstance(event.get("workspace"), dict) else {}
    roots = []
    root = workspace.get("root")
    if isinstance(root, str) and root:
        roots.append(root)
    trusted = workspace.get("trusted_dirs") or []
    if isinstance(trusted, list):
        roots.extend(item for item in trusted if isinstance(item, str) and item)
    return roots
