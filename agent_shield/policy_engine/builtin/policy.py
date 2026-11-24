"""Builtin catalog view used by adapters, intent checks, and audit redaction."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from agent_shield.policy_engine.matchers.paths import implicit_windows_prefixes

RISK_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Policy:
    catalogs: dict[str, Any]
    rules: tuple[Any, ...] = ()

    def catalog(self, name: str) -> tuple[str, ...]:
        value = self.catalogs.get(name, ())
        if isinstance(value, tuple):
            return value
        return tuple(value)

    def os_catalog(self, name: str, os_name: str) -> tuple[str, ...]:
        value = self.catalogs.get(name) or {}
        if not isinstance(value, dict):
            return tuple(value)
        entries = list(value.get(os_name) or ())
        if name == "system_prefixes" and os_name == "windows":
            entries.extend(implicit_windows_prefixes())
        return tuple(entries)

    def privilege_names(self) -> set[str]:
        return {item.casefold() for item in self.catalog("privilege_argv0")}


@lru_cache(maxsize=1)
def load_builtin_policy() -> Policy:
    from agent_shield.policy_engine.builtin.rules import builtin_catalogs

    raw = builtin_catalogs()

    def entries(name: str) -> tuple[str, ...]:
        value = raw.get(name) or {}
        if isinstance(value, dict):
            return tuple(str(item) for item in value.get("entries") or ())
        return ()

    def split(name: str) -> dict[str, tuple[str, ...]]:
        value = raw.get(name) or {}
        return {
            "posix": tuple(str(item) for item in value.get("posix") or ()),
            "windows": tuple(str(item) for item in value.get("windows") or ()),
        }

    catalogs = {
        "sensitive_globs": entries("sensitiveFiles"),
        "privilege_argv0": entries("privilege_argv0"),
        "interpreter_sinks": entries("interpreter_sinks"),
        "allowlist_hosts": entries("allowlist_hosts"),
        "allowlist_cidrs": entries("allowlist_cidrs"),
        "builtin_denylist_hosts": (),
        "builtin_denylist_cidrs": (),
        "user_denylist_hosts": (),
        "user_denylist_cidrs": (),
        "system_critical": split("protectedFiles"),
        "system_prefixes": split("systemPrefixes"),
    }
    return Policy(catalogs=catalogs)
