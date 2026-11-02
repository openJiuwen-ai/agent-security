# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Shell structure analysis: one parse → leaves + one PermissionResult.

Framework calls this; it is not a PermissionComponent. TieredPolicy does not
import or call this module.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .models import PermissionLevel, PermissionResult
from .routing import CommandDialect, supports_posix_subcommand_split
from .toolguard.shell_ast import ShellAstParseResult, ShellSubcommand, parse_shell_for_permission

_PREFIX = "tiered_policy"  # keep matched_rule labels stable
_STRICTNESS = {
    PermissionLevel.DENY: 0,
    PermissionLevel.ASK: 1,
    PermissionLevel.UNDETERMINED: 2,
    PermissionLevel.ALLOW: 3,
}
_GUARD_IDS = (
    "too_complex",
    "parse_unavailable",
    "structure_guard",
    "interpreter_sink",
    "compound_chain",  # former builtin shell_compound_chain
)
_INTERPRETER_SINK_NAMES = frozenset({
    "bash", "sh", "zsh", "dash", "ash", "fish",
    "python", "python3", "pythonw", "py",
    "node", "nodejs", "ruby", "perl",
    "pwsh", "powershell", "cmd",
    "iex", "invoke-expression", "invoke-command",
})
# Former builtin shell_compound_chain pattern.
_COMPOUND_CHAIN_RE = re.compile(r"[;&|]|\$\{|\r?\n")
_COMPOUND_LABEL = f"{_PREFIX}:shell_structure:shell_compound_chain"


@dataclass(frozen=True, slots=True)
class ShellStructureOutcome:
    """Leaves to expand as SUBCOMMAND candidates, plus optional structure verdict."""

    leaf_texts: tuple[str, ...]
    verdict: PermissionResult | None


def _level(value: object) -> PermissionLevel | None:
    if not isinstance(value, str):
        return None
    try:
        return PermissionLevel(value.strip().lower())
    except ValueError:
        return None


def guard_actions_from_config(config: Mapping[str, object]) -> dict[str, PermissionLevel]:
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


def _floor_hits(
    parse: ShellAstParseResult, actions: Mapping[str, PermissionLevel]
) -> list[tuple[PermissionLevel, str]]:
    flags = parse.flags
    floors: list[tuple[PermissionLevel, str]] = []
    if parse.kind == "too_complex":
        reason = parse.reason or "unsupported_complex_structure"
        floors.append((actions["too_complex"], f"{_PREFIX}:shell_ast:too_complex:{reason}"))
    elif parse.kind == "parse_unavailable" and flags.has_risky_structure():
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
            floors.append(
                (actions["parse_unavailable"], f"{_PREFIX}:shell_ast:parse_unavailable:{reason}")
            )
    if flags.has_heredoc:
        floors.append((actions["structure_guard"], f"{_PREFIX}:shell_ast:structure_guard"))
    if parse.kind == "simple" and _has_interpreter_sink(parse):
        floors.append((actions["interpreter_sink"], f"{_PREFIX}:shell_guard:interpreter_sink"))
    return floors


def _compound_chain_proven_simple(parse: ShellAstParseResult) -> bool:
    """Tree-sitter only: quoted operators are not real compound (裁决 #9)."""
    if parse.backend != "tree-sitter" or parse.kind != "simple":
        return False
    if len(parse.subcommands) > 1:
        return False
    flags = parse.flags
    return not (
        flags.has_compound_operators
        or flags.has_pipeline
        or flags.has_parameter_expansion
    )


def _compound_chain_hit(parse: ShellAstParseResult, command: str) -> bool:
    if _compound_chain_proven_simple(parse):
        return False
    return _COMPOUND_CHAIN_RE.search(command) is not None


def _leaf_texts(parse: ShellAstParseResult, command: str) -> tuple[str, ...]:
    if parse.kind != "simple" or not any(s.text for s in parse.subcommands):
        return ()
    texts = [s.text for s in parse.subcommands if s.text]
    if len(texts) > 1 or (len(texts) == 1 and texts[0] != command):
        return tuple(texts)
    return ()


def _result_from_hits(hits: Sequence[tuple[PermissionLevel, str]]) -> PermissionResult | None:
    if not hits:
        return None
    level, label = hits[0]
    for floor, floor_label in hits[1:]:
        tie_with_label = floor is level and "interpreter_sink" in floor_label
        if _STRICTNESS[floor] < _STRICTNESS[level] or tie_with_label:
            level, label = floor, f"{floor_label}|{label}"
    if level is PermissionLevel.DENY:
        reason = f"Denied by rule: {label}"
    elif level is PermissionLevel.ASK:
        reason = f"Requires approval: {label}"
    else:
        reason = label
    return PermissionResult(permission=level, matched_rule=label, reason=reason)


def analyze_shell_for_permission(
    tool_name: str,
    command: str,
    *,
    dialect: CommandDialect | None,
    is_shell: bool,
    guard_actions: Mapping[str, PermissionLevel],
) -> ShellStructureOutcome:
    """Parse once when needed → leaf_texts + optional structure verdict.

    Leaves: Phase 1 via routing dialect (posix/unknown only).
    Verdict: any shell entry with non-empty command (``is_shell``); not SHELL_TOOLS.
    ``tool_name`` is reserved for call-site symmetry; gating does not use it.
    Compound-chain response is only ``guard_actions.compound_chain`` (allow = no lift).
    """

    _ = tool_name  # call-site symmetry; gating uses is_shell + dialect only
    text = (command or "").strip()
    dialect = dialect or CommandDialect.UNKNOWN
    want_leaves = bool(text) and supports_posix_subcommand_split(dialect)
    want_verdict = bool(text) and is_shell
    if not want_leaves and not want_verdict:
        return ShellStructureOutcome(leaf_texts=(), verdict=None)

    parse = parse_shell_for_permission(text)
    leaves = _leaf_texts(parse, text) if want_leaves else ()
    if not want_verdict:
        return ShellStructureOutcome(leaf_texts=leaves, verdict=None)

    hits = _floor_hits(parse, guard_actions)
    if _compound_chain_hit(parse, text):
        level = guard_actions.get("compound_chain", PermissionLevel.ASK)
        if level is not PermissionLevel.ALLOW:
            hits.append((level, _COMPOUND_LABEL))
    return ShellStructureOutcome(leaf_texts=leaves, verdict=_result_from_hits(hits))


__all__ = [
    "ShellStructureOutcome",
    "analyze_shell_for_permission",
    "guard_actions_from_config",
]
