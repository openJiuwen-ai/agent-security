"""Whole-line regex host checks.

Runs only when ``host_guard.whole_line_regex`` is true. Kill commands are
matched against the whole line. A pid is blocked only when it is the current
process or its parent. ``worktree add`` is checked by its first path.
Destructive ``rm`` / shutdown patterns stay with the caller.
"""

from __future__ import annotations

import os
import re
import shlex
from pathlib import Path

_WHOLE_LINE_REGEX_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
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
    (
        re.compile(
            r"(?:Get-Process[\s\S]{0,400}Stop-Process|Stop-Process[\s\S]{0,400}Get-Process)",
            re.IGNORECASE,
        ),
        "blocked pattern: Get-Process combined with Stop-Process",
    ),
    (
        re.compile(
            r"\bStop-Process\b[\s\S]{0,200}-Name\s+['\"]?(?:pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?"
            r"|node(?:\.exe)?|jiuwenswarm|jiuwenclaw)\b",
            re.IGNORECASE,
        ),
        "blocked pattern: Stop-Process -Name targeting agent/host runtime",
    ),
    (
        re.compile(
            r"\btaskkill\b[\s\S]*?/{1,2}im\b[\s\S]*?\b(?:pythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?"
            r"|node(?:\.exe)?|jiuwenswarm|jiuwenclaw)\b",
            re.IGNORECASE,
        ),
        "blocked pattern: taskkill /im targeting agent/host runtime",
    ),
    (
        re.compile(
            r"\b(?:pkill|killall)\b[^\n\r;|&]*\bpythonw?(?:\d+(?:\.\d+)*)?(?:\.exe)?\b",
            re.IGNORECASE,
        ),
        "blocked pattern: pkill/killall targeting python runtime",
    ),
)

_TASKKILL_PID_RE = re.compile(
    r"\btaskkill\b[\s\S]*?/{1,2}pid\b[\s:=]*(\d+)",
    re.IGNORECASE,
)
_STOP_PROCESS_ID_RE = re.compile(
    r"\bStop-Process\b[\s\S]{0,300}-Id\s*\(?([\d\s,]+)\)?",
    re.IGNORECASE,
)
_WORKTREE_ADD_VALUE_OPTS = frozenset({"-b", "-B", "--branch", "--no-track"})
_WORKTREE_ADD_PRESCREEN = re.compile(r"\bworktree\s+add\b", re.IGNORECASE)


def _protected_runtime_pids() -> set[str]:
    pids = {str(os.getpid())}
    try:
        ppid = os.getppid()
    except OSError:
        return pids
    if ppid > 1:
        pids.add(str(ppid))
    return pids


def _check_self_pid_kill(
    command: str,
    protected_pids: set[str] | None = None,
) -> str | None:
    protected = _protected_runtime_pids() if protected_pids is None else protected_pids
    for match in _TASKKILL_PID_RE.finditer(command):
        if match.group(1) in protected:
            return "blocked pattern: taskkill targeting current agent/host process"
    for match in _STOP_PROCESS_ID_RE.finditer(command):
        for pid in re.findall(r"\d+", match.group(1)):
            if pid in protected:
                return "blocked pattern: Stop-Process targeting current agent/host process"
    return None


def _find_worktree_add_index(tokens: list[str]) -> int:
    lowered = [token.lower() for token in tokens]
    for index in range(len(lowered) - 1):
        if lowered[index] == "worktree" and lowered[index + 1] == "add":
            return index + 1
    raise ValueError("not a git worktree add command")


def _parse_worktree_add_target(command: str) -> str | None:
    """Return the first positional after ``worktree add``, or None to allow."""

    if not _WORKTREE_ADD_PRESCREEN.search(command):
        return None
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None
    try:
        add_index = _find_worktree_add_index(tokens)
    except ValueError:
        return None
    index = add_index + 1
    while index < len(tokens):
        token = tokens[index]
        if token.startswith("--") and "=" in token:
            index += 1
            continue
        if token in _WORKTREE_ADD_VALUE_OPTS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token
    return None


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _check_first_worktree_add_path(command: str, project_root: Path) -> str | None:
    target = _parse_worktree_add_target(command)
    if target is None:
        return None
    try:
        root = project_root.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    try:
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = root / target_path
        target_path = target_path.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if _is_relative_to(target_path, root):
        return None
    return (
        "worktree target must live under the project dir at "
        ".worktrees/<name> (e.g. `git worktree add .worktrees/<name> "
        f"-b <branch> HEAD`); refused path outside the project: {target}. "
        "Do NOT use `../` or sibling directories."
    )


def check_first_worktree_add_path(command: str, project_root: Path | None) -> str | None:
    """First path after ``worktree add``. A missing project root allows the command."""

    if project_root is None:
        return None
    return _check_first_worktree_add_path(command, project_root)


def evaluate_whole_line_regex(
    command: str,
    *,
    project_root: Path | None,
    worktree_guard: bool,
    protected_pids: set[str] | None = None,
) -> str | None:
    """Whole-line kill regexes, current and parent pid, and the first worktree path.

    ``protected_pids`` lets the caller supply the current process and parent
    process. When omitted, those ids are read here.
    """

    if not command:
        return None
    for pattern, message in _WHOLE_LINE_REGEX_PATTERNS:
        if pattern.search(command):
            return message
    pid_reason = _check_self_pid_kill(command, protected_pids)
    if pid_reason is not None:
        return pid_reason
    if worktree_guard and project_root is not None:
        return _check_first_worktree_add_path(command, project_root)
    return None


__all__ = ["check_first_worktree_add_path", "evaluate_whole_line_regex"]
