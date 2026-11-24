"""Decide whether a behavior rule's when matches one effect."""

from __future__ import annotations

from typing import Any

from agent_shield.policy_engine.matchers.command import argv_of, normalize_program
from agent_shield.policy_engine.matchers.network import (
    endpoint_host,
    endpoint_ip,
    host_in_patterns,
    ip_in_cidrs,
)
from agent_shield.policy_engine.matchers.paths import (
    event_os,
    glob_any,
    in_system_critical,
    in_system_prefixes,
    path_scope,
)


def matches_when(when: dict, effect: dict, event: dict, catalogs: dict[str, Any] | None = None) -> bool:
    return _matches(when, effect, event, catalogs or {}, event_os(event) == "windows", require_effect=True)


def _matches(when: dict, effect: dict, event: dict, catalogs: dict, windows: bool, *, require_effect: bool) -> bool:
    if "effect" in when:
        if not _effect_in(effect.get("type"), when["effect"]):
            return False
    elif require_effect and "any" not in when:
        return False
    for key, expected in when.items():
        if key == "effect":
            continue
        if key == "any":
            if not any(
                _matches(branch, effect, event, catalogs, windows, require_effect="effect" in branch)
                for branch in expected
            ):
                return False
            continue
        if key == "not":
            if _matches(expected, effect, event, catalogs, windows, require_effect=False):
                return False
            continue
        if not _clause(key, expected, effect, event, catalogs, windows):
            return False
    return True


def _clause(key: str, expected, effect: dict, event: dict, catalogs: dict, windows: bool) -> bool:
    if key == "argv0":
        argv = argv_of(effect)
        if not argv:
            return False
        actual = normalize_program(argv[0], windows)
        return actual in {normalize_program(str(item), windows) for item in _as_list(expected)}
    if key == "argv_prefix":
        argv = argv_of(effect)
        wanted = [str(item).casefold() for item in expected]
        if len(argv) < 1 + len(wanted):
            return False
        return [item.casefold() for item in argv[1:1 + len(wanted)]] == wanted
    if key == "argv_contains":
        have = {item.casefold() for item in argv_of(effect)}
        return all(str(token).casefold() in have for token in expected)
    if key == "argv_has_any":
        have = {item.casefold() for item in argv_of(effect)}
        return any(str(token).casefold() in have for token in expected)
    if key == "argv_has_any_prefix":
        tokens = [item.casefold() for item in argv_of(effect)]
        prefixes = [str(prefix).casefold() for prefix in expected]
        return any(token.startswith(prefix) for token in tokens for prefix in prefixes)
    if key == "shell_meta.privilege":
        return _flag(effect, "privilege", expected)
    if key == "shell_meta.obfuscated":
        return _flag(effect, "obfuscated", expected)
    if key == "shell_meta.interpreter_sink":
        return _flag(effect, "interpreter_sink", expected)
    if key == "path.scope":
        return path_scope(str(effect.get("path") or ""), event) in set(_as_list(expected))
    if key == "path.glob_any":
        return glob_any(str(effect.get("path") or ""), _glob_patterns(expected, catalogs), os_name=event_os(event))
    if key == "path.in_catalog":
        return _path_in_catalog(effect, expected, event, catalogs)
    if key == "path_kind":
        return (effect.get("path_kind") or "file") in set(_as_list(expected))
    if key == "device_class":
        return effect.get("device_class") in set(_as_list(expected))
    if key == "exists":
        return effect.get("exists", None) in set(_as_list(expected))
    if key in {"force", "bulk", "secret_like"}:
        return (effect.get(key) is True) if expected is True else effect.get(key) is not True
    if key == "local_file_attached":
        attached = effect.get("local_file_attached") is True or bool(effect.get("local_files"))
        return attached if expected is True else not attached
    if key == "local_files.glob_any":
        files = effect.get("local_files") or []
        patterns = _glob_patterns(expected, catalogs)
        os_name = event_os(event)
        return any(isinstance(item, str) and glob_any(item, patterns, os_name=os_name) for item in files)
    if key == "endpoint.in_any_catalog":
        return _endpoint_in(effect, expected, catalogs)
    if key == "method":
        method = effect.get("method")
        if not isinstance(method, str):
            return False
        return method.casefold() in {str(item).casefold() for item in _as_list(expected)}
    return False


def _glob_patterns(expected, catalogs: dict) -> list[str]:
    if isinstance(expected, list):
        return [str(item) for item in expected]
    catalog = catalogs.get(str(expected)) or {}
    if catalog.get("kind") != "glob":
        return []
    return [str(item) for item in catalog.get("entries") or ()]


def _path_in_catalog(effect: dict, expected, event: dict, catalogs: dict) -> bool:
    path = str(effect.get("path") or "")
    os_name = event_os(event)
    for name in _as_list(expected):
        catalog = catalogs.get(str(name)) or {}
        entries = _os_entries(catalog, os_name)
        kind = catalog.get("kind")
        if kind == "glob" and glob_any(path, entries, os_name=os_name):
            return True
        if kind == "path" and in_system_critical(path, entries, os_name=os_name):
            return True
        if kind == "prefix" and in_system_prefixes(path, entries, os_name=os_name):
            return True
        if kind == "user" and _in_user_files(path, entries, event):
            return True
    return False


def _os_entries(catalog: dict, os_name: str) -> list[str]:
    entries = list(catalog.get("entries") or ())
    entries.extend(catalog.get(os_name) or ())
    return [str(item) for item in entries]


def _in_user_files(path: str, entries: list[str], event: dict) -> bool:
    if path_scope(path, event) == "workspace":
        return True
    return in_system_critical(path, entries, os_name=event_os(event))


def _endpoint_in(effect: dict, expected, catalogs: dict) -> bool:
    host = endpoint_host(effect)
    ip = endpoint_ip(effect)
    if isinstance(expected, dict):
        return host_in_patterns(host, expected.get("hosts") or ()) or ip_in_cidrs(ip, expected.get("cidrs") or ())
    for name in _as_list(expected):
        catalog = catalogs.get(str(name)) or {}
        entries = catalog.get("entries") or ()
        kind = catalog.get("kind")
        if kind == "host" and host_in_patterns(host, entries):
            return True
        if kind == "cidr" and ip_in_cidrs(ip, entries):
            return True
    return False


def _flag(effect: dict, name: str, expected) -> bool:
    meta = effect.get("shell_meta") if isinstance(effect.get("shell_meta"), dict) else {}
    actual = meta.get(name) is True or (name == "privilege" and effect.get("type") == "privilege.escalate")
    return actual if expected is True else not actual


def _effect_in(actual, expected) -> bool:
    return actual in set(_as_list(expected))


def _as_list(value) -> list:
    if isinstance(value, list):
        return value
    return [value]
