"""Build immutable URL rules from package defaults and effective host policy."""

# All invalid configuration/action inputs follow W3's ValueError contract.
# ruff: noqa: TRY004

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from fnmatch import translate

from ..models import PermissionLevel
from .builtin_rules import package_net_urls
from .url_safety import MAX_URL_CHARS, UrlTarget, normalize_host, parse_url

MAX_URL_RULES = 10_000


def parse_action(value: object) -> PermissionLevel:
    if not isinstance(value, str) or value not in {"allow", "ask", "deny"}:
        raise ValueError("Network action must be allow, ask or deny")
    return PermissionLevel(value)


def compile_glob(pattern: str) -> re.Pattern[str]:
    # Only * and ? are wildcards. fnmatch's atomic translation avoids the
    # exponential backtracking of a naive repeated .* regular expression.
    return re.compile(translate(pattern.replace("[", "[[]")))


@dataclass(frozen=True, slots=True)
class NetUrlRule:
    pattern: str
    action: PermissionLevel
    host: str
    host_glob: re.Pattern[str] | None
    target: UrlTarget | None
    path_glob: re.Pattern[str] | None
    query_glob: re.Pattern[str] | None

    def matches(self, target: UrlTarget) -> bool:
        if self.host_glob is not None:
            if self.host_glob.fullmatch(target.host) is None:
                return False
        elif self.host != target.host:
            return False
        if self.target is None:
            return True
        if (self.target.scheme, self.target.port) != (target.scheme, target.port):
            return False
        if self.path_glob is not None:
            path_matches = self.path_glob.fullmatch(target.path) is not None
        elif self.target.has_query:
            path_matches = target.path == self.target.path
        else:
            path_matches = target.path.startswith(self.target.path)
        if not path_matches or not self.target.has_query:
            return path_matches
        if self.query_glob is not None:
            return self.query_glob.fullmatch(target.query) is not None
        return target.query == self.target.query


def compile_rule(pattern: str, action: PermissionLevel) -> NetUrlRule:
    target = parse_url(pattern, pattern=True) if "://" in pattern else None
    host = target.host if target is not None else normalize_host(pattern, pattern=True)
    host_glob = compile_glob(host) if "*" in host or "?" in host else None
    path_glob = compile_glob(target.path) if target is not None and "*" in target.path else None
    query_glob = None
    if target is not None and ("*" in target.query or "?" in target.query):
        query_glob = compile_glob(target.query)
    return NetUrlRule(pattern, action, host, host_glob, target, path_glob, query_glob)


def build_net_urls(urls: object, *, include_package: bool) -> tuple[NetUrlRule, ...]:
    """Overlay only identical pattern keys; independent matches stay strict."""
    if not isinstance(urls, Mapping):
        raise ValueError("net_guard.urls must be a mapping")
    if len(urls) > MAX_URL_RULES:
        raise ValueError("Too many network URL rules")
    merged = package_net_urls() if include_package else {}
    supplied = set()
    for raw_pattern, value in urls.items():
        if not isinstance(raw_pattern, str):
            raise ValueError("Network pattern must be a string")
        if len(raw_pattern) > MAX_URL_CHARS:
            raise ValueError("Invalid network pattern length")
        pattern = raw_pattern.strip()
        if not pattern or len(pattern) > MAX_URL_CHARS:
            raise ValueError("Invalid network pattern length")
        if pattern in supplied:
            raise ValueError("Duplicate network pattern after trimming")
        supplied.add(pattern)
        merged[pattern] = parse_action(value)
    if len(merged) > MAX_URL_RULES:
        raise ValueError("Too many effective network URL rules")
    return tuple(compile_rule(pattern, parse_action(action)) for pattern, action in merged.items())
