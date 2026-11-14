# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Shell structure analysis: split once → analyses → optional PermissionResult.

Framework calls this; it is not a PermissionComponent. TieredPolicy does not
import or call this module.

Flow:
1. ``parse_shell_for_permission`` — leaves + edges only (no feature flags)
2. Independent analyses (each owns its detection → own conclusion):
   - parse_failed — kind != ok → ASK (fail-closed)
   - complex — scans command for heredoc / here-string → ASK
   - interpreter_sink — pipe/|& RHS stdin-as-commands (D1–D3) → ASK
3. Strictest hit wins
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from .models import PermissionLevel, PermissionResult
from .routing import CommandDialect, coerce_command_dialect, supports_ast_subcommand_split
from .toolguard.shell_ast import (  # noqa: F401 — re-exported for monkeypatch
    ShellAstParseResult,
    ShellSubcommand,
    parse_shell_for_permission,
)

_STRICTNESS = {
    PermissionLevel.DENY: 0,
    PermissionLevel.ASK: 1,
    PermissionLevel.UNDETERMINED: 2,
    PermissionLevel.ALLOW: 3,
}

# Active structure analyses (guard_actions keys). Legacy keys still accepted.
_GUARD_IDS = (
    "parse_failed",
    "complex",
    "interpreter_sink",
)
_SHELL_STDIN_INTERPRETERS = frozenset({
    "bash", "sh", "zsh", "dash", "ash", "fish", "ksh", "csh", "tcsh",
})
_PS_SHELL_STDIN_INTERPRETERS = frozenset({
    "powershell", "powershell.exe", "pwsh", "pwsh.exe", "pwsh-preview",
})
_CMD_STDIN_INTERPRETERS = frozenset({"cmd", "cmd.exe", "command", "command.com"})
_PYTHON_STDIN_INTERPRETERS = frozenset({"python", "python3", "pythonw", "py"})
_NODE_STDIN_INTERPRETERS = frozenset({
    "node", "nodejs", "deno", "bun", "ts-node",
})
_RUBY_STDIN_INTERPRETERS = frozenset({"ruby", "rb"})
_PERL_STDIN_INTERPRETERS = frozenset({"perl", "perl5", "perl6", "raku"})
_PHP_STDIN_INTERPRETERS = frozenset({"php", "php8", "php7"})
_LUA_STDIN_INTERPRETERS = frozenset({"lua", "luajit"})
_OTHER_STDIN_INTERPRETERS = frozenset({
    "osascript",  # macOS AppleScript — bare reads stdin
    "csi",        # C# interactive
    "dotnet-script",
})
_PS_EXPR_SINKS = frozenset({
    "iex", "invoke-expression",
    "icm", "invoke-command",  # can take piped scriptblocks / remote exec
})
_PIPE_OPS = frozenset({"|", "|&"})
_PS_CODE_FROM_ARG_FLAGS = frozenset({
    "-command", "-c", "-encodedcommand", "-ec", "-enc", "-e",
    "-file", "-f",
})
_CMD_CODE_FROM_ARG_FLAGS = frozenset({"/c", "/k", "/r"})

# Exec prefixes skipped inside ``is_stdin_command_sink`` only (not parse peel).
# Covers ``curl | sudo bash`` / ``env bash`` / Windows ``sudo pwsh`` etc.
_SUDO_VALUE_OPTS = frozenset({
    "-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
    "-C", "--close-from", "-D", "--chdir", "-R", "--chroot",
    "-T", "--command-timeout", "--other-user",
})
_ENV_VALUE_OPTS = frozenset({"-u", "--unset", "-C", "--chdir", "-S", "--split-string"})
# Pure flags (--preserve-status, --foreground, --verbose) must NOT be listed:
# _skip_leading_options would consume the following token as a value.
_TIMEOUT_VALUE_OPTS = frozenset({"-s", "--signal", "-k", "--kill-after"})
_NICE_VALUE_OPTS = frozenset({"-n", "--adjustment"})
_STDBUF_VALUE_OPTS = frozenset({"-i", "--input", "-o", "--output", "-e", "--error"})
# -t is a boolean flag (ignore failures), not a valued option.
_IONICE_VALUE_OPTS = frozenset({
    "-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid",
})
_COMMAND_VALUE_OPTS = frozenset({"-p"})  # rarely takes a value; -V/-v are flags

# bash short/long options that take a following operand (not -c / --command).
_BASH_VALUE_SHORT = frozenset({"-O", "+O", "-o", "+o"})
_BASH_VALUE_LONG = frozenset({"rcfile", "init-file"})


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
    """Response per structure check; active keys default ASK.

    Legacy keys still mapped for migration:
    - ``structure_guard`` → ``complex`` when ``complex`` is unset
    - ``parse_unavailable`` / ``too_complex`` → ``parse_failed`` when unset
    """
    actions = {guard: PermissionLevel.ASK for guard in _GUARD_IDS}
    legacy = config.get("shell_guard")
    if isinstance(legacy, Mapping):
        if legacy.get("interpreter_sink") is False:
            actions["interpreter_sink"] = PermissionLevel.ALLOW
        if legacy.get("unknown_structure") is False:
            actions["parse_failed"] = PermissionLevel.ALLOW
    configured = config.get("guard_actions")
    if isinstance(configured, Mapping):
        for guard in _GUARD_IDS:
            level = _level(configured.get(guard))
            if level is not None:
                actions[guard] = level
        if "complex" not in configured and "structure_guard" in configured:
            level = _level(configured.get("structure_guard"))
            if level is not None:
                actions["complex"] = level
        if "parse_failed" not in configured:
            for legacy_key in ("parse_unavailable", "too_complex"):
                level = _level(configured.get(legacy_key))
                if level is not None:
                    actions["parse_failed"] = level
                    break
    return actions


def _basename(token: str) -> str:
    base = token.strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _leaf_argv(leaf: ShellSubcommand) -> tuple[str, ...]:
    if leaf.argv:
        return leaf.argv
    parts = leaf.text.split()
    return tuple(parts)


def analyze_parse_failed(
    command: str,
    parse: ShellAstParseResult,
    actions: Mapping[str, PermissionLevel],
) -> tuple[PermissionLevel, str] | None:
    """Analysis: untrustworthy parse → ASK (fail-closed)."""
    _ = command
    if parse.kind == "ok":
        return None
    level = actions.get("parse_failed", PermissionLevel.ASK)
    if level is PermissionLevel.ALLOW:
        return None
    reason = (parse.reason or "untrusted").replace(" ", "_")[:80]
    return level, f"shell_structure:parse_failed:{reason}"


# Bash ``<<`` / ``<<-`` / ``<<<`` and PowerShell here-string openers, outside quotes.
_PS_HERE_STRING_OPEN_RE = re.compile(r"@['\"]\s*(?:\r?\n|$)")


def _has_heredoc_or_herestring(command: str) -> bool:
    """Detect heredoc / here-string markers in the command text (quote-aware)."""
    text = command or ""
    if not text:
        return False
    if _PS_HERE_STRING_OPEN_RE.search(text):
        return True
    i = 0
    n = len(text)
    in_single = False
    in_double = False
    while i < n:
        ch = text[i]
        if in_single:
            if ch == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if ch == "\\" and i + 1 < n:
                i += 2
                continue
            if ch == '"':
                in_double = False
            i += 1
            continue
        if ch == "'":
            in_single = True
            i += 1
            continue
        if ch == '"':
            in_double = True
            i += 1
            continue
        if ch == "<" and i + 1 < n and text[i + 1] == "<":
            return True
        i += 1
    return False


def analyze_complex(
    command: str,
    parse: ShellAstParseResult,
    actions: Mapping[str, PermissionLevel],
) -> tuple[PermissionLevel, str] | None:
    """Analysis: heredoc / here-string in the command text → ASK by default.

    Detects from ``command`` itself (does not use parse flags). Incomplete
    heredocs still match. Parameter expansion is not lifted.
    """
    _ = parse
    if not _has_heredoc_or_herestring(command):
        return None
    level = actions.get("complex", PermissionLevel.ASK)
    if level is PermissionLevel.ALLOW:
        return None
    return level, "shell_structure:complex:heredoc"


def _shell_reads_stdin_as_commands(argv: tuple[str, ...]) -> bool:
    """D1–D3 for bash-family: stdin is the command stream.

    Valued switches (``-O`` / ``-o`` / ``--rcfile`` / ``--init-file``) consume
    their operand so ``bash -O extdebug`` is still a bare stdin sink.
    """
    if not argv:
        return False
    tokens = list(argv[1:])
    saw_s = False
    script_operand: str | None = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok == "--":
            rest = tokens[i + 1:]
            if rest:
                script_operand = rest[0]
            break
        if tok in {"-c", "--command"}:
            return False  # code from -c argument (not classic pipe-sink)
        if tok.startswith("--"):
            name = tok[2:].split("=", 1)[0]
            if name == "command":
                return False
            if name in _BASH_VALUE_LONG:
                # ``--rcfile PATH`` or ``--rcfile=PATH``
                i += 1 if "=" in tok[2:] else 2
                continue
            i += 1
            continue
        if tok in _BASH_VALUE_SHORT:
            # ``-O extdebug`` / ``+O`` / ``-o errexit`` — never treat the value as a script.
            i += 2 if i + 1 < len(tokens) else 1
            continue
        if tok.startswith("-") and tok != "-":
            cluster = tok[1:]
            if "c" in cluster:
                return False
            if "s" in cluster:
                saw_s = True
            i += 1
            continue
        script_operand = tok
        break

    if saw_s:
        return True  # D2
    if script_operand is None:
        return True  # D1
    if script_operand in {"-", "/dev/stdin", "/dev/fd/0"}:
        return True  # D3
    return False


def _python_reads_stdin_as_commands(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    tokens = list(argv[1:])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in {"-c", "-m"}:
            return False
        if tok == "-":
            return True
        if tok.startswith("-"):
            i += 1
            continue
        return False  # script file
    return True  # bare python


def _node_reads_stdin_as_commands(argv: tuple[str, ...]) -> bool:
    if not argv:
        return False
    tokens = list(argv[1:])
    if not tokens:
        return True
    if tokens[0] == "-":
        return True
    if tokens[0] in {"-e", "--eval", "-p", "--print", "-c", "--command"}:
        return False
    if tokens[0].startswith("-"):
        for tok in tokens[1:]:
            if tok == "-":
                return True
            if not tok.startswith("-"):
                return False
        return True
    return False


def _ps_shell_reads_stdin_as_commands(argv: tuple[str, ...]) -> bool:
    """Bare pwsh/powershell reads stdin; -Command/-File/-EncodedCommand do not."""
    if not argv:
        return False
    tokens = list(argv[1:])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if low in _PS_CODE_FROM_ARG_FLAGS or low.lstrip("-") in {
            "command", "c", "encodedcommand", "ec", "enc", "e", "file", "f",
        }:
            # -Command/-c/-EncodedCommand/-File: code/path from following arg
            return False
        if tok == "-" or low in {"/dev/stdin", "stdin"}:
            return True
        if tok.startswith("-") or tok.startswith("/"):
            # switch that may take a value (-WorkingDirectory, -NoProfile, …)
            if "=" not in tok and i + 1 < len(tokens) and not tokens[i + 1].startswith(("-", "/")):
                nxt = tokens[i + 1].lower()
                # Don't skip a following -Command disguised as value.
                if nxt.lstrip("-") in {
                    "command", "c", "encodedcommand", "ec", "enc", "e", "file", "f",
                } or nxt in _PS_CODE_FROM_ARG_FLAGS:
                    i += 1
                    continue
                i += 2
                continue
            i += 1
            continue
        # Positional script path → not stdin sink.
        return False
    return True  # D1 bare / only switches


def _cmd_reads_stdin_as_commands(argv: tuple[str, ...]) -> bool:
    """Bare ``cmd`` can take piped input; ``/c`` ``/k`` take the command line arg."""
    if not argv:
        return False
    tokens = list(argv[1:])
    for tok in tokens:
        low = tok.lower()
        if low in _CMD_CODE_FROM_ARG_FLAGS or low.startswith("/c") or low.startswith("/k"):
            return False
    return True


def _script_lang_reads_stdin_as_commands(
    argv: tuple[str, ...],
    *,
    eval_flags: frozenset[str],
) -> bool:
    """ruby/perl/php/lua-style: bare or ``-`` → stdin; ``-e``/script file → not."""
    if not argv:
        return False
    tokens = list(argv[1:])
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in eval_flags:
            return False
        if tok == "-":
            return True
        if tok.startswith("-"):
            # clustered short opts may include e (perl -ne, ruby -e, …)
            if not tok.startswith("--") and any(ch in tok[1:] for ch in "eE"):
                return False
            i += 1
            continue
        return False  # script file
    return True


def _skip_leading_options(
    tokens: list[str],
    *,
    value_opts: frozenset[str],
    stop_at_double_dash: bool = True,
) -> list[str]:
    """Drop leading ``-`` options; return remaining tokens (command + args)."""
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if stop_at_double_dash and tok == "--":
            return tokens[i + 1:]
        if tok == "-" or not tok.startswith("-"):
            return tokens[i:]
        name = tok.split("=", 1)[0]
        takes_value = name in value_opts or (
            not tok.startswith("--") and len(tok) == 2 and f"-{tok[1]}" in value_opts
        )
        if takes_value and "=" not in tok:
            i += 2
            continue
        i += 1
    return []


def _strip_one_exec_wrapper(argv: tuple[str, ...]) -> tuple[str, ...] | None:
    """If argv0 is an exec wrapper, return the inner command argv; else None."""
    if not argv:
        return None
    base = _basename(argv[0])
    rest = list(argv[1:])

    if base in {"sudo", "sudo.exe", "doas", "pkexec"}:
        return tuple(_skip_leading_options(rest, value_opts=_SUDO_VALUE_OPTS)) or None

    if base in {"env", "env.exe"}:
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok == "--":
                return tuple(rest[i + 1:]) or None
            if tok.startswith("-"):
                name = tok.split("=", 1)[0]
                takes_value = name in _ENV_VALUE_OPTS or (
                    not tok.startswith("--") and len(tok) == 2 and f"-{tok[1]}" in _ENV_VALUE_OPTS
                )
                if takes_value and "=" not in tok:
                    i += 2
                    continue
                i += 1
                continue
            if "=" in tok:
                i += 1  # VAR=value
                continue
            return tuple(rest[i:]) or None
        return None

    if base in {"nohup", "nohup.exe"}:
        return tuple(_skip_leading_options(rest, value_opts=frozenset())) or None

    if base in {"nice", "nice.exe"}:
        return tuple(_skip_leading_options(rest, value_opts=_NICE_VALUE_OPTS)) or None

    if base in {"stdbuf", "stdbuf.exe"}:
        return tuple(_skip_leading_options(rest, value_opts=_STDBUF_VALUE_OPTS)) or None

    if base in {"ionice", "ionice.exe"}:
        return tuple(_skip_leading_options(rest, value_opts=_IONICE_VALUE_OPTS)) or None

    if base in {"timeout", "timeout.exe"}:
        after_opts = _skip_leading_options(rest, value_opts=_TIMEOUT_VALUE_OPTS)
        # timeout requires DURATION before COMMAND
        if not after_opts:
            return None
        return tuple(after_opts[1:]) or None

    if base == "command":
        return tuple(_skip_leading_options(rest, value_opts=_COMMAND_VALUE_OPTS)) or None

    # Windows / PS: runas is interactive and not a clean prefix; skip.
    return None


def _strip_exec_wrappers(argv: tuple[str, ...]) -> tuple[str, ...]:
    """Walk off sudo/env/timeout/… prefixes used before a real sink argv0."""
    current = argv
    seen: set[tuple[str, ...]] = set()
    while current and current not in seen:
        seen.add(current)
        inner = _strip_one_exec_wrapper(current)
        if inner is None:
            break
        current = inner
    return current


def is_stdin_command_sink(argv: tuple[str, ...]) -> bool:
    """True when argv is an interpreter that takes commands from stdin (D1–D3).

    Walks common exec wrappers (``sudo``, ``env``, ``timeout``, …) inside this
    check only — does not change parse / canonicalize peel.
    """
    if not argv:
        return False
    argv = _strip_exec_wrappers(argv)
    if not argv:
        return False
    base = _basename(argv[0])
    if base in _PS_EXPR_SINKS:
        return True
    if base in _SHELL_STDIN_INTERPRETERS:
        return _shell_reads_stdin_as_commands(argv)
    if base in _PS_SHELL_STDIN_INTERPRETERS:
        return _ps_shell_reads_stdin_as_commands(argv)
    if base in _CMD_STDIN_INTERPRETERS:
        return _cmd_reads_stdin_as_commands(argv)
    if base in _PYTHON_STDIN_INTERPRETERS:
        return _python_reads_stdin_as_commands(argv)
    if base in _NODE_STDIN_INTERPRETERS:
        return _node_reads_stdin_as_commands(argv)
    if base in _RUBY_STDIN_INTERPRETERS:
        return _script_lang_reads_stdin_as_commands(argv, eval_flags=frozenset({"-e", "-E"}))
    if base in _PERL_STDIN_INTERPRETERS:
        return _script_lang_reads_stdin_as_commands(argv, eval_flags=frozenset({"-e", "-E"}))
    if base in _PHP_STDIN_INTERPRETERS:
        return _script_lang_reads_stdin_as_commands(argv, eval_flags=frozenset({"-r", "-R"}))
    if base in _LUA_STDIN_INTERPRETERS:
        return _script_lang_reads_stdin_as_commands(argv, eval_flags=frozenset({"-e"}))
    if base in _OTHER_STDIN_INTERPRETERS:
        return _script_lang_reads_stdin_as_commands(argv, eval_flags=frozenset({"-e"}))
    return False


def analyze_interpreter_sink(
    command: str,
    parse: ShellAstParseResult,
    actions: Mapping[str, PermissionLevel],
) -> tuple[PermissionLevel, str] | None:
    """Analysis: pipe/|& RHS is a stdin-command interpreter → ASK.

    Uses only leaves + edges from the split (no feature flags).
    """
    _ = command
    if parse.kind != "ok" or not parse.subcommands:
        return None
    level = actions.get("interpreter_sink", PermissionLevel.ASK)
    if level is PermissionLevel.ALLOW:
        return None

    leaves = parse.subcommands
    edges = parse.edges
    if edges:
        for _left, op, right in edges:
            if op not in _PIPE_OPS:
                continue
            if 0 <= right < len(leaves) and is_stdin_command_sink(_leaf_argv(leaves[right])):
                return level, "shell_structure:shell_guard:interpreter_sink"
        return None

    # Compat when stubs omit edges: parent_operators on non-first leaves.
    for sub in leaves[1:]:
        ops = sub.parent_operators or ()
        if not any(op in _PIPE_OPS for op in ops):
            continue
        if is_stdin_command_sink(_leaf_argv(sub)):
            return level, "shell_structure:shell_guard:interpreter_sink"
    return None


def _leaf_texts(parse: ShellAstParseResult, command: str) -> tuple[str, ...]:
    if parse.kind != "ok" or not any(s.text for s in parse.subcommands):
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
    dialect: CommandDialect | str | None,
    is_shell: bool,
    guard_actions: Mapping[str, PermissionLevel],
) -> ShellStructureOutcome:
    """Parse once → leaf_texts + optional structure verdict from analyses.

    ``dialect`` may be a ``CommandDialect`` or a common string alias
    (``\"bash\"``, ``\"pwsh\"``, …); strings are coerced so structure is not
    silently skipped.
    """

    _ = tool_name
    text = (command or "").strip()
    dialect = coerce_command_dialect(dialect) or CommandDialect.UNKNOWN
    can_split = supports_ast_subcommand_split(dialect)
    want_leaves = bool(text) and can_split
    want_verdict = bool(text) and is_shell and can_split
    if not want_leaves and not want_verdict:
        return ShellStructureOutcome(leaf_texts=(), verdict=None)

    parse = parse_shell_for_permission(text, dialect=dialect)
    leaves = _leaf_texts(parse, text) if want_leaves else ()
    if not want_verdict:
        return ShellStructureOutcome(leaf_texts=leaves, verdict=None)

    hits: list[tuple[PermissionLevel, str]] = []
    for analyzer in (analyze_parse_failed, analyze_complex, analyze_interpreter_sink):
        hit = analyzer(text, parse, guard_actions)
        if hit is not None:
            hits.append(hit)
    return ShellStructureOutcome(leaf_texts=leaves, verdict=_result_from_hits(hits))


__all__ = [
    "ShellStructureOutcome",
    "analyze_shell_for_permission",
    "analyze_parse_failed",
    "analyze_complex",
    "analyze_interpreter_sink",
    "guard_actions_from_config",
    "is_stdin_command_sink",
    "parse_shell_for_permission",
]
