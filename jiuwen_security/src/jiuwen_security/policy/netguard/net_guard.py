"""Engine-owned Pipeline C component. Configuration is committed atomically."""

# All invalid configuration/action inputs follow W3's ValueError contract.
# ruff: noqa: TRY004

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from itertools import chain
from types import MappingProxyType

from ..models import PermissionLevel, PermissionResult
from .address_policy import ConnectionPolicy, build_connection_policy, connection_rejection_reason
from .net_urls import NetUrlRule, build_net_urls, parse_action
from .url_safety import MAX_URL_CHARS, UrlTarget, has_secret_query, parse_url, rule_label

_FETCH_TOOLS = frozenset({"mcp_fetch_webpage", "fetch_webpage", "web_fetch_webpage"})
_URL_ARG_KEYS = ("url", "uri", "href", "webpage", "page_url", "target_url")
_RANK = {PermissionLevel.ALLOW: 0, PermissionLevel.ASK: 1, PermissionLevel.DENY: 2}


@dataclass(frozen=True, slots=True)
class _State:
    enabled: bool
    default: PermissionLevel
    exact_hosts: Mapping[str, tuple[NetUrlRule, ...]]
    wildcard_prefixes: Mapping[str, tuple[NetUrlRule, ...]]
    wildcard_suffixes: Mapping[str, tuple[NetUrlRule, ...]]
    connection: ConnectionPolicy


def extract_fetch_url(args: Mapping[str, object]) -> str | None:
    for key in _URL_ARG_KEYS:
        value = args.get(key)
        if isinstance(value, str) and len(value) > MAX_URL_CHARS:
            raise ValueError("URL exceeds 8192 characters")
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _check_rules(target: UrlTarget, state: _State) -> tuple[PermissionLevel, str]:
    """Preserve a distinct defaults marker for the later raw-query adapter."""
    strongest = None
    hits = []
    # Every glob has a necessary literal prefix/suffix. Index the longer one;
    # checking all host substrings here also preserves globs within DNS labels.
    candidates = chain(
        state.exact_hosts.get(target.host, ()),
        *(state.wildcard_prefixes.get(target.host[:i], ()) for i in range(len(target.host) + 1)),
        *(state.wildcard_suffixes.get(target.host[i:], ()) for i in range(len(target.host) + 1)),
    )
    for rule in candidates:
        if not rule.matches(target):
            continue
        if strongest is None or _RANK[rule.action] > _RANK[strongest]:
            strongest = rule.action
            hits = [rule_label(rule.pattern, query=rule.target.query if rule.target else "")]
        elif rule.action == strongest:
            hits.append(rule_label(rule.pattern, query=rule.target.query if rule.target else ""))
    if strongest is None:
        return state.default, "net_guard:defaults"
    return strongest, "|".join("net_guard:url:" + hit for hit in sorted(hits))


class NetGuardChecker:
    """Internal component; applications keep using the PermissionEngine facade.

    No route interest is declared yet: the component checks exact supported
    tool names itself, including legacy aliases missing from the current router.
    W6 owns final component construction and routing.
    """

    def __init__(self) -> None:
        self._state: _State | None = None

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise ValueError("Engine configuration must be a mapping")
        section = config.get("net_guard", {})
        if not isinstance(section, Mapping):
            raise ValueError("net_guard must be a mapping")
        enabled = section.get("enabled", False)
        include_package = config.get("package_builtin_rules", True)
        if type(enabled) is not bool or type(include_package) is not bool:
            raise ValueError("Network policy switches must be boolean")
        default = parse_action(section.get("defaults", "allow"))
        connection = build_connection_policy(section.get("connection", {}))
        rules = build_net_urls(section.get("urls", {}), include_package=include_package)
        exact: dict[str, list[NetUrlRule]] = {}
        prefixes: dict[str, list[NetUrlRule]] = {}
        suffixes: dict[str, list[NetUrlRule]] = {}
        for rule in rules:
            if rule.host_glob is None:
                exact.setdefault(rule.host, []).append(rule)
            else:
                positions = [i for i, char in enumerate(rule.host) if char in "*?"]
                prefix, suffix = rule.host[: positions[0]], rule.host[positions[-1] + 1 :]
                index, key = (prefixes, prefix) if len(prefix) > len(suffix) else (suffixes, suffix)
                index.setdefault(key, []).append(rule)
        # No state is mutated until every field and rule has been validated.
        self._state = _State(
            enabled,
            default,
            MappingProxyType({host: tuple(items) for host, items in exact.items()}),
            MappingProxyType({key: tuple(items) for key, items in prefixes.items()}),
            MappingProxyType({key: tuple(items) for key, items in suffixes.items()}),
            connection,
        )

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
    ) -> PermissionResult | None:
        state = self._state
        if state is None:
            raise RuntimeError("NetGuardChecker must be configured before evaluation")
        if not state.enabled or tool_name not in _FETCH_TOOLS | {"network_connect"}:
            return None
        if not isinstance(tool_args, Mapping):
            raise ValueError("Network tool arguments must be a mapping")
        if tool_name == "network_connect":
            url = tool_args.get("url")
            if not isinstance(url, str) or not url:
                raise ValueError("network_connect requires a URL")
        else:
            url = extract_fetch_url(tool_args)
        if url is None:
            return PermissionResult(
                state.default, "net_guard:defaults", "Network URL absent; using defaults"
            )
        target = parse_url(url)
        permission, matched = _check_rules(target, state)
        if tool_name == "network_connect":
            rejection = connection_rejection_reason(target, tool_args, state.connection)
            if rejection is not None:
                permission = PermissionLevel.DENY
                matched = matched + "|net_guard:connection:" + rejection
        warnings = ["network_secret_query"] if has_secret_query(target.query) else []
        return PermissionResult(
            permission,
            matched,
            "Network policy result: " + permission.value,
            warnings=warnings,
        )
