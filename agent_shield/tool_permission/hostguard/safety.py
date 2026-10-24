# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Host availability guards: block commands that would kill the Swarm runtime."""

from __future__ import annotations

import contextlib
import os
import re
import shlex
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover - optional dependency
    psutil = None  # type: ignore[assignment,misc]

_BASE_DANGEROUS_COMMAND_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\bpkill\b[^\n\r;|&]*jiuwenswarm", re.IGNORECASE),
        "blocked pattern: pkill targeting jiuwenswarm (includes user TUI)",
    ),
    (
        re.compile(r"\bkillall\b[^\n\r;|&]*jiuwenswarm", re.IGNORECASE),
        "blocked pattern: killall targeting jiuwenswarm (includes user TUI)",
    ),
    (
        re.compile(r"\bpkill\b[^\n\r;|&]*jiuwenclaw", re.IGNORECASE),
        "blocked pattern: pkill targeting jiuwenclaw backend",
    ),
    (
        re.compile(r"\bkillall\b[^\n\r;|&]*jiuwenclaw", re.IGNORECASE),
        "blocked pattern: killall targeting jiuwenclaw backend",
    ),
    (
        re.compile(r"\bkill\b[^\n\r;|&]*jiuwenswarm", re.IGNORECASE),
        "blocked pattern: kill targeting jiuwenswarm (includes user TUI)",
    ),
    (
        re.compile(
            r"jiuwenswarm[^\n\r;|&]{0,240}\|\s*xargs\s+kill\b",
            re.IGNORECASE,
        ),
        "blocked pattern: xargs kill pipeline targeting jiuwenswarm",
    ),
)

_KILL_FAMILY_BASES = frozenset({
    "pkill", "killall", "kill",
    "stop-process", "spps",
    "taskkill",
})
_PS_PROCESS_ENUM_BASES = frozenset({"get-process", "gps"})
_HOST_INTERPRETER_NAME_RE = re.compile(
    r"^\*?python[\d.]*w?(?:\.exe)?\*?$", re.IGNORECASE
)
_KILL_PID_FLAG_RE = re.compile(r"^(?:-+id|/pid)$", re.IGNORECASE)
_JOB_SPEC_RE = re.compile(r"%\d+$")
_CONTINUATION_RES = {
    "bash": re.compile(r"\\\r?\n"),
    "sh": re.compile(r"\\\r?\n"),
    "powershell": re.compile(r"`\r?\n"),
    "cmd": re.compile(r"\^\r?\n"),
}

_TASKKILL_SEGMENT_RE = re.compile(r"\btaskkill\b[^\n\r;|&]*", re.IGNORECASE)
_TASKKILL_PID_RE = re.compile(r"/pid\s+(\d+)", re.IGNORECASE)
_TASKKILL_FI_PID_RE = re.compile(r"\bpid\s+eq\s+(\d+)", re.IGNORECASE)
_STOP_PROCESS_IDS_RE = re.compile(
    r"\b(?:stop-process|spps)\b(?:[^\n\r;|&]*?\s-id[:\s]*|\s+)(\d+(?:\s*,\s*\d+)*)\b",
    re.IGNORECASE,
)
_GET_PROCESS_ID_PIPE_RE = re.compile(
    r"\b(?:get-process|gps)\s+-id\s+(\d+(?:\s*,\s*\d+)*)[^\n\r;|&]*"
    r"\|\s*(?:stop-process|spps|kill)\b",
    re.IGNORECASE,
)
_WMIC_TERMINATE_PID_RE = re.compile(
    r"\bwmic\b[^\n\r]*?\bprocessid\s*=\s*(\d+)[^\n\r]*?\b(?:terminate|delete)\b",
    re.IGNORECASE,
)
_CIM_PROCESSID_RE = re.compile(r"\bprocessid\s*=\s*'?(\d+)", re.IGNORECASE)
_SHELL_TOKEN_RE = re.compile(r"[^\s;&|]+|[;&|]")
_SIGSPEC_RE = re.compile(r"-(\d+)")
_MAX_SIGNAL_NUMBER = 64

_BACKEND_MODULES = (
    "jiuwenswarm.app",
    "jiuwenswarm.start_services",
    "jiuwenswarm.server.app_agentserver",
    "jiuwenswarm.gateway.app_gateway",
    "jiuwenswarm.channels.web.app_web",
)
_BACKEND_SCRIPT_SUFFIXES = tuple(module.replace(".", "/") + ".py" for module in _BACKEND_MODULES)
_BACKEND_ENTRY_POINTS = frozenset(
    {
        "jiuwenswarm-start",
        "jiuwenswarm-app",
        "jiuwenswarm-agentserver",
        "jiuwenswarm-gateway",
        "jiuwenswarm-web",
        "jiuwenswarm-desktop",
    }
)
_BACKEND_FLAGS = frozenset({"--desktop-run-agent", "--desktop-run-gateway"})

_WORKTREE_ADD_VALUE_OPTS = frozenset({"-b", "-B", "--branch", "--no-track"})
_WORKTREE_ADD_PRESCREEN = re.compile(r"\bworktree\s+add\b", re.IGNORECASE)
# Git options that take the next token as a value. ``--opt=value`` is one token.
_GIT_GLOBAL_VALUE_OPTS = frozenset({
    "-C", "-c",
    "--git-dir", "--work-tree", "--namespace", "--super-prefix",
    "--config-env", "--exec-path", "--list-cmds",
})
_SHELL_SEPARATORS = frozenset({"&&", "||", ";", "|"})


@dataclass(frozen=True, slots=True)
class HostGuardOptions:
    """Feature flags for :func:`evaluate_host_guard`.

    ``name_patterns`` replaces only the whole-text regex floor. Rule 1 still
    blocks a kill primitive that names jiuwenswarm or jiuwenclaw; those
    literals stay fixed, as in the original guard. Python-name and
    backend-PID checks stay off unless the caller turns them on.
    """

    python_name_kill: bool = False
    backend_pid_kill: bool = False
    worktree_guard: bool = True
    name_patterns: tuple[tuple[re.Pattern[str], str], ...] | None = None


def compile_name_patterns(raw: object) -> tuple[tuple[re.Pattern[str], str], ...]:
    """Compile caller-supplied regexes. ``None`` keeps the built-in floor.

    A list replaces that floor only. It does not remove the Rule 1 literals.
    """

    if raw is None:
        return _BASE_DANGEROUS_COMMAND_PATTERNS
    if not isinstance(raw, list):
        raise TypeError("host_guard.protected_patterns must be a list")
    compiled: list[tuple[re.Pattern[str], str]] = []
    for item in raw:
        if not isinstance(item, dict):
            raise TypeError("each protected pattern must be a mapping")
        pattern = item.get("pattern")
        reason = item.get("reason")
        if not isinstance(pattern, str) or not pattern.strip():
            raise TypeError("protected pattern requires a pattern string")
        if not isinstance(reason, str) or not reason.strip():
            raise TypeError("protected pattern requires a reason string")
        try:
            compiled.append((re.compile(pattern, re.IGNORECASE), reason))
        except re.error as exc:
            raise ValueError(f"invalid protected pattern: {pattern}") from exc
    return tuple(compiled)


def _normalize_continuations(command: str, shell_type: str) -> str:
    """Join the continuation form the shell will execute before matching."""

    pattern = _CONTINUATION_RES.get((shell_type or "").strip().lower())
    return pattern.sub("", command) if pattern is not None else command


def _strip_matching_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        if char in {'"', "'"}:
            quote = None if quote == char else char if quote is None else quote
        if quote is None and command.startswith(("&&", "||"), index):
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 2
            continue
        if quote is None and char in {"|", ";", "\n", "\r"}:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def _segment_base_command(segment: str) -> str:
    try:
        tokens = shlex.split(segment, posix=False)
    except ValueError:
        return ""
    if not tokens:
        return ""
    base = _strip_matching_quotes(tokens[0])
    base = base.rsplit("/", maxsplit=1)[-1].rsplit("\\", maxsplit=1)[-1].lower()
    return base.removesuffix(".exe")


def _segment_tokens(segment: str) -> list[str] | None:
    try:
        return shlex.split(segment, posix=False)
    except ValueError:
        return None


def _self_identity_literals() -> tuple[str, ...]:
    literals = {"jiuwenswarm", "jiuwenclaw"}
    exe = (sys.executable or "").strip().lower()
    if exe:
        literals.add(exe)
        base = os.path.basename(exe).removesuffix(".exe")
        if base and not base.startswith("python"):
            literals.add(base)
    return tuple(sorted(literals))


def _segment_has_interpreter_name(tokens: list[str]) -> bool:
    for token in tokens[1:]:
        if _HOST_INTERPRETER_NAME_RE.match(_strip_matching_quotes(token)):
            return True
    return False


def _kill_segment_is_pid_precise(base: str, tokens: list[str]) -> bool:
    if base in {"pkill", "killall"}:
        return False
    if base == "taskkill":
        return any(token.lower() == "/pid" for token in tokens)
    if any(_KILL_PID_FLAG_RE.match(token) for token in tokens):
        return True
    positionals = [token for token in tokens[1:] if not token.startswith("-")]
    return bool(positionals) and all(
        _strip_matching_quotes(token).lstrip("+-").isdigit() or _JOB_SPEC_RE.match(token)
        for token in positionals
    )


def _check_segment_safety(
    text: str,
    patterns: tuple[tuple[re.Pattern[str], str], ...],
    *,
    python_name_kill: bool,
) -> str | None:
    """Per-segment self-kill rules from the original host guard.

    Rule 1 always blocks a kill primitive that names the runtime. Rule 2, the
    interpreter-name kill, runs only when the caller turns that profile on.

    The command name is the first token of the segment. A wrapper prefix is a
    known gap shared with the original parser: ``sudo pkill python``,
    ``timeout 5 pkill python``, ``nohup pkill python``, ``env X=1 pkill
    python``, ``sleep 1 & pkill python``, ``(pkill python)`` and
    ``{ pkill python; }`` are not treated as python-name kills. The regex
    floor still sees a product-name kill anywhere in the text, so
    ``sudo pkill jiuwenswarm`` stays blocked.
    """

    segments = _split_shell_segments(text)
    parsed: list[tuple[str, str, list[str] | None]] = []
    enum_interpreter = False
    for segment in segments:
        base = _segment_base_command(segment)
        tokens = _segment_tokens(segment) if base else None
        parsed.append((segment, base, tokens))
        enumerates_processes = bool(tokens) and base in _PS_PROCESS_ENUM_BASES
        names_interpreter = bool(tokens) and _segment_has_interpreter_name(tokens)
        if python_name_kill and enumerates_processes:
            if names_interpreter:
                enum_interpreter = True
    literals = _self_identity_literals()
    for segment, base, tokens in parsed:
        if tokens is None:
            for pattern, message in patterns:
                if pattern.search(segment):
                    return message
            continue
        if python_name_kill and base == "wmic":
            lowered_tokens = [token.lower() for token in tokens]
            deletes_by_name = "process" in lowered_tokens and "delete" in lowered_tokens
            not_by_pid = "processid" not in segment.lower()
            if deletes_by_name and not_by_pid:
                if _segment_has_interpreter_name(tokens):
                    return (
                        "blocked pattern: wmic name-based kill of host python "
                        "interpreter (use PID-precise kill for own spawned processes)"
                    )
            continue
        if base not in _KILL_FAMILY_BASES:
            continue
        lowered_segment = segment.lower()
        for literal in literals:
            if literal and literal in lowered_segment:
                return (
                    f"blocked pattern: {base} targeting jiuwenswarm runtime "
                    "(self-kill guard)"
                )
        if _kill_segment_is_pid_precise(base, tokens):
            continue
        if python_name_kill and (_segment_has_interpreter_name(tokens) or enum_interpreter):
            return (
                f"blocked pattern: {base} name/wildcard kill of host python "
                "interpreter (use PID-precise kill for own spawned processes)"
            )
    return None


def evaluate_host_guard(
    command: str,
    *,
    project_root: Path | None,
    options: HostGuardOptions | None = None,
    shell_type: str = "",
) -> str | None:
    """Return a block reason when the command threatens host runtime availability."""
    if not command:
        return None
    opts = options or HostGuardOptions()
    text = _normalize_continuations(command, shell_type)
    name_patterns = (
        _BASE_DANGEROUS_COMMAND_PATTERNS
        if opts.name_patterns is None
        else opts.name_patterns
    )
    for pattern, message in name_patterns:
        if pattern.search(text):
            return message
    segment_reason = _check_segment_safety(
        text,
        name_patterns,
        python_name_kill=opts.python_name_kill,
    )
    if segment_reason is not None:
        return segment_reason
    if opts.backend_pid_kill:
        backend_reason = _check_backend_pid_kill(text)
        if backend_reason is not None:
            return backend_reason
    if opts.worktree_guard and project_root is not None:
        worktree_reason = _check_worktree_path_safety(command, project_root)
        if worktree_reason is not None:
            return worktree_reason
    return None


def _posix_kill_pids(command: str) -> set[int]:
    tokens = _SHELL_TOKEN_RE.findall(command)
    pids: set[int] = set()
    index = 0
    while index < len(tokens):
        word = tokens[index].strip("'\"")
        if word != "kill" and not word.endswith(("/kill", "\\kill")):
            index += 1
            continue
        index += 1
        found: set[int] = set()
        signal_is_zero = False
        options_done = False
        while index < len(tokens):
            token = tokens[index].strip("'\"")
            index += 1
            if token in (";", "|", "&"):
                break
            if not options_done:
                if token == "--":
                    options_done = True
                    continue
                if token == "-l":
                    found.clear()
                    break
                if token in ("-s", "-n"):
                    if index < len(tokens):
                        signal_is_zero = tokens[index].strip("'\"") == "0"
                        index += 1
                    continue
                sigspec = _SIGSPEC_RE.fullmatch(token)
                if sigspec and int(sigspec.group(1)) <= _MAX_SIGNAL_NUMBER:
                    signal_is_zero = sigspec.group(1) == "0"
                    continue
                if re.fullmatch(r"-[A-Za-z]+", token):
                    signal_is_zero = False
                    continue
            operand = re.fullmatch(r"-?(\d+)", token)
            if operand:
                found.add(int(operand.group(1)))
                continue
            break
        if found and not signal_is_zero:
            pids.update(found)
    return pids


def _kill_target_pids(command: str) -> set[int]:
    pids: set[int] = _posix_kill_pids(command)
    for segment in _TASKKILL_SEGMENT_RE.findall(command):
        pids.update(int(pid) for pid in _TASKKILL_PID_RE.findall(segment))
        pids.update(int(pid) for pid in _TASKKILL_FI_PID_RE.findall(segment))
    for pattern in (_STOP_PROCESS_IDS_RE, _GET_PROCESS_ID_PIPE_RE):
        for group in pattern.findall(command):
            pids.update(int(pid) for pid in re.split(r"\s*,\s*", group))
    pids.update(int(pid) for pid in _WMIC_TERMINATE_PID_RE.findall(command))
    lowered = command.lower()
    if "invoke-cimmethod" in lowered and "terminate" in lowered:
        pids.update(int(pid) for pid in _CIM_PROCESSID_RE.findall(command))
    return pids


def _is_backend_cmdline(cmdline: Sequence[str]) -> bool:
    for index, arg in enumerate(cmdline):
        if arg in _BACKEND_FLAGS:
            return True
        if arg == "-m" and index + 1 < len(cmdline) and cmdline[index + 1] in _BACKEND_MODULES:
            return True
    for index, arg in enumerate(cmdline[:3]):
        if index and (arg.startswith("-") or any(ch.isspace() for ch in arg)):
            continue
        normalized = arg.replace("\\", "/")
        if normalized.endswith(_BACKEND_SCRIPT_SUFFIXES):
            return True
        if normalized.rsplit("/", 1)[-1].lower().removesuffix(".exe") in _BACKEND_ENTRY_POINTS:
            return True
    return False


def _backend_pids() -> set[int]:
    pids = {os.getpid()}
    if psutil is None:
        return pids
    with contextlib.suppress(psutil.Error):
        pids.update(parent.pid for parent in psutil.Process().parents())
    for proc in psutil.process_iter(["pid", "cmdline"]):
        if _is_backend_cmdline(proc.info.get("cmdline") or ()):
            pids.add(proc.info["pid"])
    return pids


def _check_backend_pid_kill(command: str) -> str | None:
    targets = _kill_target_pids(command)
    if not targets:
        return None
    protected = sorted(targets & _backend_pids())
    if not protected:
        return None
    return (
        f"blocked: PID {', '.join(map(str, protected))} belongs to the JiuwenSwarm backend "
        "or its launcher; kill only the processes your command started"
    )


class _WorktreeUnparsed(Exception):
    """A real ``git worktree add`` was seen, but its target path could not be read."""


def _strip_wrapping_quotes(token: str) -> str:
    """Drop one pair of matching quotes left in place by ``posix=False`` shlex."""

    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _split_shell_tokens(command: str) -> list[str]:
    """Split a command without treating backslash as an escape.

    ``posix=False`` keeps Windows paths intact and also keeps the quote
    characters on each token. Those quotes are not part of the path.
    """

    return [_strip_wrapping_quotes(token) for token in shlex.split(command, posix=False)]


def _is_git_argv(token: str) -> bool:
    base = token.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base.removesuffix(".exe") == "git"


def _skip_git_global(tokens: list[str], index: int) -> int:
    token = tokens[index]
    if token.startswith("--") and "=" in token:
        return index + 1
    name = token.split("=", 1)[0]
    if name in _GIT_GLOBAL_VALUE_OPTS and index + 1 < len(tokens):
        return index + 2
    return index + 1


def _find_git_worktree_add(tokens: list[str]) -> int | None:
    """Return the ``add`` index only when some argv is ``git ... worktree add``."""

    index = 0
    while index < len(tokens):
        if not _is_git_argv(tokens[index]):
            index += 1
            continue
        cursor = index + 1
        while cursor < len(tokens):
            token = tokens[cursor]
            if token in _SHELL_SEPARATORS:
                break
            if (
                token.lower() == "worktree"
                and cursor + 1 < len(tokens)
                and tokens[cursor + 1].lower() == "add"
            ):
                return cursor + 1
            if token.startswith("-"):
                cursor = _skip_git_global(tokens, cursor)
                continue
            break
        index += 1
    return None


def _outside_quotes(command: str) -> str:
    """Drop quoted spans, including a trailing unclosed quote and its text."""

    kept: list[str] = []
    index = 0
    length = len(command)
    while index < length:
        if command[index] in "\"'":
            quote = command[index]
            end = command.find(quote, index + 1)
            if end < 0:
                break
            index = end + 1
            continue
        kept.append(command[index])
        index += 1
    return "".join(kept)


def _parse_worktree_add_target(command: str) -> str | None:
    """Return the path of a real ``git worktree add``, else None.

    Text that merely contains the words, such as a commit message or
    ``echo worktree add``, is not a worktree command. A real ``git worktree
    add`` whose path cannot be read is refused by the caller.
    """

    if not _WORKTREE_ADD_PRESCREEN.search(command):
        return None
    try:
        tokens = _split_shell_tokens(command)
    except ValueError as exc:
        bare = _outside_quotes(command)
        mentions_git = re.search(r"\bgit(?:\.exe)?\b", bare, re.IGNORECASE)
        if mentions_git and _WORKTREE_ADD_PRESCREEN.search(bare):
            raise _WorktreeUnparsed from exc
        return None
    add_idx = _find_git_worktree_add(tokens)
    if add_idx is None:
        return None
    index = add_idx + 1
    while index < len(tokens):
        tok = tokens[index]
        if tok in _SHELL_SEPARATORS:
            break
        if tok.startswith("--") and "=" in tok:
            index += 1
            continue
        if tok in _WORKTREE_ADD_VALUE_OPTS:
            index += 2
            continue
        if tok.startswith("-"):
            index += 1
            continue
        return tok
    raise _WorktreeUnparsed


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _check_worktree_path_safety(command: str, project_root: Path) -> str | None:
    """Refuse a ``git worktree add`` target that leaves the project directory.

    This is only a path bound. It does not replace a caller rule that denies
    ``worktree add/remove/prune`` outright.
    """

    try:
        target = _parse_worktree_add_target(command)
    except _WorktreeUnparsed:
        return "worktree add could not be parsed; refused"
    if target is None:
        return None
    try:
        root = project_root.resolve()
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = root / target_path
        target_path = target_path.resolve()
    except OSError:
        return f"worktree target could not be resolved; refused path: {target}"
    if _is_relative_to(target_path, root):
        return None
    return (
        "worktree target must stay inside the project directory "
        f"(for example .worktrees/<name>); refused path outside the project: {target}."
    )


__all__ = ["HostGuardOptions", "evaluate_host_guard"]
