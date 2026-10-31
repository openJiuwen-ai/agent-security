# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Layered command permission policy (R06-R12).

The engine expands candidates (original / unwrapped / subcommands).  This
component judges **one** candidate:

    approval → rules → tool baseline → defaults → ASK
"""

from __future__ import annotations

from collections.abc import Mapping
import logging
import re
import sys
from typing import Any

from ..models import PermissionLevel, PermissionResult
from ..routing import CandidateKind, RouteContext
from .builtin_rules import SHELL_TOOLS, package_command_rules
from .shell_ast import ShellAstParseResult, ShellSubcommand, parse_shell_for_permission

logger = logging.getLogger(__name__)

_PREFIX = "tiered_policy"
_STRICTNESS = {
    PermissionLevel.DENY: 0,
    PermissionLevel.ASK: 1,
    PermissionLevel.UNDETERMINED: 2,
    PermissionLevel.ALLOW: 3,
}
_SHELL_TOOLS = frozenset(SHELL_TOOLS)
_GUARD_IDS = ("too_complex", "parse_unavailable", "interpreter_sink")
_INTERPRETER_SINK_NAMES = frozenset({
    "bash", "sh", "zsh", "dash", "ash", "fish",
    "python", "python3", "pythonw", "py",
    "node", "nodejs", "ruby", "perl",
    "pwsh", "powershell", "cmd",
    "iex", "invoke-expression", "invoke-command",
})
_FALSE_STRINGS = frozenset({"false", "0", "no", "off"})


def _as_rules(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, Mapping)]


def _level(value: object) -> PermissionLevel | None:
    if not isinstance(value, str):
        return None
    try:
        return PermissionLevel(value.strip().lower())
    except ValueError:
        return None


def _tools(rule: Mapping[str, Any]) -> tuple[str, ...]:
    raw = rule.get("tools", ())
    values = (raw,) if isinstance(raw, str) else raw
    if not isinstance(values, (list, tuple, set, frozenset)):
        return ()
    return tuple(value.strip() for value in values if isinstance(value, str) and value.strip())


def _rule_targets_tool(rule: Mapping[str, Any], tool_name: str) -> bool:
    names = rule["_tools"]
    # The former "shell" category shorthand is intentionally not supported.
    return tool_name in names and all(name in _SHELL_TOOLS for name in names)


def _command_text(args: Mapping[str, Any]) -> str:
    return str(args.get("command", "") or args.get("cmd", "") or "").strip()


def _strictest(*levels: PermissionLevel) -> PermissionLevel:
    return min(levels, key=_STRICTNESS.__getitem__)


def _package_rules_enabled(value: object) -> bool:
    if isinstance(value, bool):
        return value
    return not (isinstance(value, str) and value.strip().lower() in _FALSE_STRINGS)


def _guard_actions(config: Mapping[str, object]) -> dict[str, PermissionLevel]:
    """Response per structure check (R09); every check defaults to ASK."""
    actions = {guard: PermissionLevel.ASK for guard in _GUARD_IDS}
    legacy = config.get("shell_guard")
    if isinstance(legacy, Mapping):
        if legacy.get("unknown_structure") is False:
            actions["too_complex"] = actions["parse_unavailable"] = PermissionLevel.ALLOW
        if legacy.get("interpreter_sink") is False:
            actions["interpreter_sink"] = PermissionLevel.ALLOW
    configured = config.get("guard_actions")
    if isinstance(configured, Mapping):
        for guard in _GUARD_IDS:
            level = _level(configured.get(guard))
            if level is not None:
                actions[guard] = level
    return actions


def _sink_basename(subcommand: ShellSubcommand) -> str:
    token = subcommand.argv[0] if subcommand.argv else (subcommand.text.split() or [""])[0]
    base = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _has_interpreter_sink(parse: ShellAstParseResult) -> bool:
    piped = parse.flags.has_pipeline or any(
        "|" in sub.parent_operators for sub in parse.subcommands
    )
    return piped and any(
        _sink_basename(sub) in _INTERPRETER_SINK_NAMES for sub in parse.subcommands[1:]
    )


def _structure_floors(
    parse: ShellAstParseResult, actions: Mapping[str, PermissionLevel]
) -> list[tuple[PermissionLevel, str]]:
    """Structure-level checks only a parse can see (R09)."""
    flags = parse.flags
    floors: list[tuple[PermissionLevel, str]] = []
    if parse.kind == "too_complex":
        reason = parse.reason or "unsupported_complex_structure"
        floors.append((actions["too_complex"], f"{_PREFIX}:shell_ast:too_complex:{reason}"))
    elif parse.kind == "parse_unavailable" and flags.has_risky_structure():
        # Redirection alone is a file-path concern (FileGuard); do not raise a
        # command structure floor for `>` / `<` without other risk flags.
        non_redir_risk = any((
            flags.has_compound_operators,
            flags.has_pipeline,
            flags.has_subshell,
            flags.has_command_group,
            flags.has_command_substitution,
            flags.has_process_substitution,
            flags.has_parameter_expansion,
            flags.has_heredoc,
        ))
        if non_redir_risk:
            reason = parse.reason or "conservative_fallback"
            label = f"{_PREFIX}:shell_ast:parse_unavailable:{reason}"
            floors.append((actions["parse_unavailable"], label))
    # Command / process substitution and heredoc are denied by InjectionComponent.
    if parse.kind == "simple" and _has_interpreter_sink(parse):
        floors.append((actions["interpreter_sink"], f"{_PREFIX}:shell_guard:interpreter_sink"))
    return floors


def _compile_wildcard(pattern: str) -> re.Pattern[str] | None:
    """Prepare the original restricted wildcard matcher once at configuration."""
    # Exclude only shell metacharacters, newlines and NUL to prevent command
    # splicing; everything else (including non-ASCII) is allowed.
    chars = r"[^;|&`$()<>\\\n\r\x00]"
    normalized_pattern = pattern.replace("\\", "/")
    to_escape = set(".+^${}()|[]\\")
    escaped = "".join("\\" + char if char in to_escape else char for char in normalized_pattern)
    escaped = escaped.replace("?", chars)
    if escaped.endswith(" *"):
        escaped = escaped[:-2] + "( " + chars + "*)?"
    else:
        escaped = escaped.replace("*", chars + "*")
    flags = re.IGNORECASE if sys.platform == "win32" else 0
    try:
        return re.compile(escaped, flags)
    except re.error:
        return None


def _rule_matches(rule: Mapping[str, Any], command: str) -> bool:
    if not command or not rule["_is_command"]:
        return False
    kind = rule["_kind"]
    if kind == "regex":
        return any(
            pattern.search(text)
            for pattern in rule["_patterns"]
            for text in (command, command.replace("\\", "/"))
        )
    if kind == "wildcard":
        pattern = rule["_wildcard"]
        return pattern is not None and pattern.fullmatch(command.replace("\\", "/")) is not None
    return command == rule["_exact"]


def _pattern(rule: Mapping[str, Any]) -> str | None:
    pattern = rule.get("pattern")
    return pattern.strip() if isinstance(pattern, str) and pattern.strip() else None


def _rule_level(rule: Mapping[str, Any], permission_mode: str) -> PermissionLevel:
    action = _level(rule.get("action"))
    if action is not None:
        return action
    severity = str(rule.get("severity") or "").strip().upper()
    if not severity:
        return PermissionLevel.ASK
    if severity in {"LOW", "MEDIUM"}:
        return PermissionLevel.ALLOW
    if severity == "HIGH":
        return PermissionLevel.ASK
    if severity == "CRITICAL":
        return PermissionLevel.DENY if permission_mode == "strict" else PermissionLevel.ASK
    return PermissionLevel.ASK


def _rule_label(namespace: str, rule: Mapping[str, Any]) -> str:
    rid = rule.get("id")
    return f"{namespace}[{rid}]" if isinstance(rid, str) and rid else f"{namespace}[?]"


class TieredPolicyComponent:
    """Judge one candidate: approvals, rules, tool baselines and defaults."""

    def __init__(self) -> None:
        self._tools: dict[str, tuple[PermissionLevel, str]] = {}
        self._default: PermissionLevel | None = None
        self._builtin_rules: list[dict[str, Any]] = []
        self._user_rules: list[dict[str, Any]] = []
        self._approval_overrides: list[dict[str, Any]] = []
        self._guard_actions: dict[str, PermissionLevel] = _guard_actions({})

    def configure(self, config: Mapping[str, object]) -> None:
        """Prepare this component's rule state from the complete engine config."""
        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        prepared = dict(config)
        tools = prepared.get("tools")
        defaults = prepared.get("defaults")
        all_rules = _as_rules(prepared.get("rules"))
        overrides = _as_rules(prepared.get("approval_overrides"))
        mode = str(prepared.get("permission_mode", "normal")).strip().lower()
        if mode not in {"normal", "strict"}:
            mode = "normal"

        builtins = [rule for rule in all_rules if rule.get("layer") == "builtin"]
        users = [rule for rule in all_rules if rule.get("layer") != "builtin"]
        if not _package_rules_enabled(prepared.get("package_builtin_rules")):
            builtins = []
        elif not builtins:
            builtins = package_command_rules()

        # A user action override is addressed by one tool name plus the pattern, never a
        # rule id.  It replaces the action of that builtin detector for that tool only.
        builtin_pairs: set[tuple[str, str]] = set()
        for rule in builtins:
            pattern = _pattern(rule)
            if pattern is None:
                continue
            for tool in _tools(rule):
                builtin_pairs.add((tool, pattern))
        action_overrides: dict[tuple[str, str], PermissionLevel] = {}
        configured_users: list[dict[str, Any]] = []
        for rule in users:
            pattern = _pattern(rule)
            action = _level(rule.get("action"))
            covered: set[str] = set()
            if pattern is not None and action is not None:
                covered = {tool for tool in _tools(rule) if (tool, pattern) in builtin_pairs}
                action_overrides.update({(tool, pattern): action for tool in covered})
            remaining = [tool for tool in _tools(rule) if tool not in covered]
            if covered and not remaining:
                continue
            configured_users.append(
                self._prepare_rule({**rule, "tools": remaining} if covered else rule, mode)
            )
        configured_builtins: list[dict[str, Any]] = []
        for rule in builtins:
            prepared_rule = self._prepare_rule(dict(rule), mode)
            pattern = _pattern(rule)
            prepared_rule["_by_tool"] = {
                tool: action_overrides[(tool, pattern)]
                for tool in prepared_rule["_tools"]
                if pattern is not None and (tool, pattern) in action_overrides
            }
            configured_builtins.append(prepared_rule)
        prepared_overrides = [self._prepare_rule(rule, mode) for rule in overrides]
        baselines: dict[str, tuple[PermissionLevel, str]] = {}
        for name, raw in (tools.items() if isinstance(tools, Mapping) else ()):
            suffix = ".*" if isinstance(raw, Mapping) else ""
            level = _level(raw.get("*") if isinstance(raw, Mapping) else raw)
            if level is not None:
                baselines[name] = (level, f"tools.{name}{suffix}")

        self._tools = baselines
        self._default = _level(defaults.get("*")) if isinstance(defaults, Mapping) else None
        self._builtin_rules = configured_builtins
        self._user_rules = configured_users
        self._approval_overrides = prepared_overrides
        self._guard_actions = _guard_actions(prepared)

    def match_approval(self, tool_name: str, command: str) -> PermissionResult | None:
        """Return ALLOW when ``command`` hits an approval override; else ``None``.

        Used by the engine for whole-call / per-candidate short-circuits.
        """

        hit = self._approval(tool_name, command)
        if hit is None:
            return None
        return self._result(*hit)

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        """Judge one candidate (rules / baseline / defaults / structure floors)."""

        baseline = self._tools.get(tool_name)
        command = _command_text(tool_args)
        is_shell = bool(route is not None and route.is_shell) or tool_name in _SHELL_TOOLS
        kind = route.kind if route is not None else CandidateKind.ORIGINAL
        # Structure floors need the whole (or unwrapped) view, not a leaf.
        apply_floors = (
            is_shell
            and kind in (CandidateKind.ORIGINAL, CandidateKind.UNWRAPPED)
            and tool_name in _SHELL_TOOLS
            and bool(command)
        )
        parse = parse_shell_for_permission(command) if apply_floors else None
        # 裁决 #9: quoted operators are not compound. Only the tree-sitter backend
        # can prove that; the conservative fallback does not understand quotes and
        # must not suppress shell_compound_chain (e.g. `sleep 1 &` stays ASK).
        skip_ids: frozenset[str] = frozenset()
        # Named predicate keeps the if below under G.CTL.03's boolean-expr budget.
        is_simple_tree_sitter = (
            parse is not None
            and parse.backend == "tree-sitter"
            and parse.kind == "simple"
            and len(parse.subcommands) <= 1
        )
        if is_simple_tree_sitter and parse is not None:
            flags = parse.flags
            structural = (
                flags.has_compound_operators
                or flags.has_pipeline
                or flags.has_parameter_expansion
            )
            if not structural:
                skip_ids = frozenset({"shell_compound_chain"})

        judged = self._judge(
            tool_name, command, baseline, is_shell=is_shell, skip_rule_ids=skip_ids
        )

        if apply_floors and parse is not None:
            floors = _structure_floors(parse, self._guard_actions)
            if judged is None and floors:
                level, label = floors[0]
                for floor, floor_label in floors[1:]:
                    if _STRICTNESS[floor] < _STRICTNESS[level]:
                        level, label = floor, floor_label
                return self._result(level, label)
            if judged is not None:
                level, label = judged
                for floor, floor_label in floors:
                    tie_with_label = floor is level and "interpreter_sink" in floor_label
                    if _STRICTNESS[floor] < _STRICTNESS[level] or tie_with_label:
                        level, label = floor, f"{floor_label}|{label}"
                return self._result(level, label)
        if judged is None:
            return None
        return self._result(*judged)

    def _judge(
        self,
        tool_name: str,
        command: str,
        baseline: tuple[PermissionLevel, str] | None,
        *,
        is_shell: bool,
        skip_rule_ids: frozenset[str] = frozenset(),
    ) -> tuple[PermissionLevel, str] | None:
        """One judgement: overrides, rules, tool baseline, defaults; shell ASK fallback."""
        approval = self._approval(tool_name, command)
        if approval is not None:
            return approval
        hit = self._rules_only(tool_name, command, skip_rule_ids=skip_rule_ids)
        if hit is not None:
            return hit
        if baseline is not None:
            return baseline
        if self._default is not None:
            return self._default, f"{_PREFIX}:defaults.*"
        # Shell stays fail-closed; non-shell abstains so Net/File can speak alone.
        if is_shell:
            return PermissionLevel.ASK, f"{_PREFIX}:fallback(no_config)"
        return None

    def _approval(self, tool_name: str, command: str) -> tuple[PermissionLevel, str] | None:
        labels = []
        for rule in self._approval_overrides:
            if rule["_explicit_action"] is not PermissionLevel.ALLOW:
                continue
            if not _rule_targets_tool(rule, tool_name):
                continue
            if not _rule_matches(rule, command):
                continue
            labels.append(_rule_label("approval_overrides", rule))
        labels = sorted(set(labels))
        if not labels:
            return None
        return PermissionLevel.ALLOW, f"{_PREFIX}:approval_overrides:" + "+".join(labels)

    def _rules_only(
        self,
        tool_name: str,
        command: str,
        *,
        skip_rule_ids: frozenset[str] = frozenset(),
    ) -> tuple[PermissionLevel, str] | None:
        hits: list[tuple[PermissionLevel, str, str]] = []
        for namespace, rules in (("builtin", self._builtin_rules), ("rules", self._user_rules)):
            for rule in rules:
                rid = rule.get("id")
                if isinstance(rid, str) and rid in skip_rule_ids:
                    continue
                if _rule_targets_tool(rule, tool_name) and _rule_matches(rule, command):
                    decision = rule["_by_tool"].get(tool_name, rule["_decision"])
                    hits.append((decision, namespace, _rule_label(namespace, rule)))
        if not hits:
            return None
        level = _strictest(*(hit[0] for hit in hits))
        selected = sorted({label for hit_level, _, label in hits if hit_level is level})
        namespaces = {ns for hit_level, ns, _ in hits if hit_level is level}
        namespace = "builtin" if namespaces == {"builtin"} else "rules"
        severity_label = ":deny" if level is PermissionLevel.DENY else ""
        return level, f"{_PREFIX}:{namespace}{severity_label}:" + "+".join(selected)

    @staticmethod
    def _prepare_rule(rule: dict[str, Any], mode: str) -> dict[str, Any]:
        """Compile regex rules once during configuration, not per evaluation."""
        rule["_tools"] = _tools(rule)
        rule["_is_command"] = str(rule.get("match_type") or "command").strip().lower() == "command"
        rule["_decision"] = _rule_level(rule, mode)
        rule["_by_tool"] = {}
        rule["_explicit_action"] = _level(rule.get("action"))
        raw = rule.get("pattern")
        pattern = raw.strip() if isinstance(raw, str) else ""
        if pattern.lower().startswith("re:"):
            rule["_kind"] = "regex"
            patterns = []
            expression = pattern[3:].strip()
            flags = re.IGNORECASE if sys.platform == "win32" else 0
            try:
                patterns.append(re.compile(expression, flags))
            except re.error:
                if "|" in expression:
                    for part in expression.split("|"):
                        if not part.strip():
                            continue
                        try:
                            patterns.append(re.compile(part.strip(), flags))
                        except re.error:
                            continue
                logger.warning("Invalid command rule regex: %r", pattern)
            rule["_patterns"] = tuple(patterns)
        elif any(char in pattern for char in "*?["):
            rule["_kind"] = "wildcard"
            rule["_wildcard"] = _compile_wildcard(pattern)
        else:
            rule["_kind"] = "exact"
            rule["_exact"] = pattern
        return rule

    @staticmethod
    def _result(level: PermissionLevel, matched_rule: str) -> PermissionResult:
        if level is PermissionLevel.DENY:
            reason = f"Denied by rule: {matched_rule}"
        elif level is PermissionLevel.ASK:
            reason = f"Requires approval: {matched_rule}"
        else:
            reason = matched_rule
        return PermissionResult(permission=level, matched_rule=matched_rule, reason=reason)


__all__ = ["TieredPolicyComponent"]
