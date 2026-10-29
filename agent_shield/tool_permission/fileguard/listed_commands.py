"""Path extraction for bash, mcp_exec_command and create_terminal.

The default extractor in ``path_extract`` stays unchanged. This module is
used only when ``file_guard.read_deny_only`` is true. Paths come from a fixed
list of command names.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from ..toolguard.shell_ast import (
    ShellAstParseResult,
    _get_tree_sitter_bash_parser,
    _parse_with_conservative_fallback,
    _parse_with_tree_sitter,
)
from .path_policy import _PATH_TOOLS, _iter_path_strings
from .unix_bash_literal import is_script_interpreter, parse_literal_shell

logger = logging.getLogger(__name__)

FileAction = Literal["read", "write", "exec"]

_CHAIN_SPLIT_RE = re.compile(r"\s+(?:&&|\|\|)\s+")
_LISTED_SHELL_TOOLS = frozenset({"mcp_exec_command", "bash", "create_terminal"})
_PATH_AWARE_COMMANDS = frozenset({
    "cd", "rm", "cp", "mv", "mkdir", "touch", "chmod", "chown", "cat",
    "ls", "dir", "type", "del", "rd", "copy", "move", "md",
    "head", "tail", "more", "less", "vim", "nano", "gedit", "notepad",
})
_INTERPRETER_BASENAMES = frozenset({
    "python", "python3", "pythonw", "py",
    "node", "nodejs", "bash", "sh", "dash", "zsh", "fish",
    "pwsh", "powershell",
})
_WRITE_PATH_TOOLS = frozenset({
    "write_file", "edit_file", "write_text_file", "write", "search_replace",
})
_NT_CMD_SWITCH_BODY = re.compile(r"^[A-Za-z]{1,2}(?::[^\s/\\]+)?$")
_READ_CMDS = frozenset({
    "cat", "ls", "dir", "type", "head", "tail", "more", "less",
})
_WRITE_CMDS = frozenset({
    "rm", "mkdir", "touch", "chmod", "chown", "del", "rd", "md",
})
_TRANSFER_CMDS = frozenset({"cp", "copy", "mv", "move"})
_LEGACY_PATH_AWARE_COMMANDS = _PATH_AWARE_COMMANDS
_FILE_SPECS: dict[str, tuple[tuple[str, FileAction], ...]] = {
    "read_file": (("file_path", "read"), ("path", "read")),
    "write_file": (("file_path", "write"), ("path", "write")),
    "edit_file": (("file_path", "write"),),
    "read_text_file": (("file_path", "read"),),
    "write_text_file": (("file_path", "write"),),
    "write": (("file_path", "write"),),
    "read": (("file_path", "read"),),
    "search_replace": (("file_path", "write"), ("path", "write"), ("target_file", "write")),
    "grep": (("path", "read"), ("file_path", "read")),
    "glob_file_search": (("glob_pattern", "read"),),
    "glob": (("pattern", "read"),),
    "list_dir": (("path", "read"),),
    "list_files": (("path", "read"),),
}


def _nt_cmd_exe_switch_token(stripped: str) -> bool:
    if os.name != "nt" or not stripped.startswith("/") or stripped.startswith("//"):
        return False
    if "\\" in stripped or stripped.count("/") != 1:
        return False
    return bool(_NT_CMD_SWITCH_BODY.match(stripped[1:]))


def _looks_like_path(token: str) -> bool:
    text = token.strip().strip('"').strip("'")
    if _nt_cmd_exe_switch_token(text):
        return False
    if text in (".", ".."):
        return True
    if text.startswith(("\\\\", "./", "../")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return True
    return "\\" in text or "/" in text


def _legacy_looks_like_path(token: str) -> bool:
    if token.startswith(("\\\\", "./", "../")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", token):
        return True
    return "\\" in token or "/" in token


def _is_shell_flag_token(token: str) -> bool:
    text = token.strip().strip('"').strip("'")
    if not text or text.startswith("-"):
        return True
    return _nt_cmd_exe_switch_token(text)


def _basename_lower(command: str) -> str:
    base = Path(command.replace("\\", "/")).name.lower()
    return base.removesuffix(".exe")


def _parse_shell_without_launcher_unwrap(command: str) -> ShellAstParseResult:
    text = (command or "").strip()
    if not text:
        return ShellAstParseResult(kind="simple", backend="fallback")
    parser = _get_tree_sitter_bash_parser()
    if parser is not None:
        try:
            return _parse_with_tree_sitter(text, parser)
        except (OSError, RuntimeError, ValueError):
            logger.warning("permission.shell_ast.parse_failed fallback=true", exc_info=True)
    return _parse_with_conservative_fallback(text)


def _segments_for_extract(command: str) -> list[str]:
    text = (command or "").strip()
    if not text:
        return []
    parsed = _parse_shell_without_launcher_unwrap(text)
    invocations = [
        item.text.strip() for item in (parsed.subcommands or ()) if item.text and item.text.strip()
    ]
    heuristic = [part.strip() for part in _CHAIN_SPLIT_RE.split(text) if part.strip()]
    if len(invocations) >= 2:
        return invocations
    if len(heuristic) >= 2:
        return heuristic
    if len(invocations) == 1:
        return invocations
    return [text]


def _path_aware_one_segment(
    segment: str, cwd: Path,
) -> tuple[list[tuple[Path, FileAction]], Path | None]:
    try:
        tokens = shlex.split(segment.strip(), posix=False)
    except ValueError:
        tokens = segment.strip().split()
    if not tokens:
        return [], None
    command_name = _basename_lower(tokens[0])
    if command_name not in _PATH_AWARE_COMMANDS:
        return [], None
    base = cwd.resolve()
    path_tokens: list[Path] = []
    for token in tokens[1:]:
        token = token.strip().strip('"').strip("'")
        if not token or _is_shell_flag_token(token) or not _looks_like_path(token):
            continue
        path = Path(token)
        if not path.is_absolute():
            path = base / token
        try:
            path_tokens.append(path.resolve())
        except (OSError, RuntimeError):
            continue

    results: list[tuple[Path, FileAction]] = []
    new_cwd: Path | None = None
    if command_name in _TRANSFER_CMDS and len(path_tokens) >= 2:
        results.append((path_tokens[0], "read"))
        results.extend((path, "write") for path in path_tokens[1:])
    elif command_name in _WRITE_CMDS:
        results.extend((path, "write") for path in path_tokens)
    elif command_name in _READ_CMDS:
        if not path_tokens and command_name in {"dir", "ls"}:
            try:
                results.append((base.resolve(), "read"))
            except (OSError, RuntimeError):
                pass
        else:
            results.extend((path, "read") for path in path_tokens)
    elif command_name == "cd":
        if path_tokens:
            results.extend((path, "read") for path in path_tokens)
            new_cwd = path_tokens[-1]
        else:
            try:
                home = Path.home().resolve()
                results.append((home, "read"))
                new_cwd = home
            except (OSError, RuntimeError):
                pass
    else:
        results.extend((path, "write") for path in path_tokens)
    return results, new_cwd


def extract_shell_path_accesses(
    command: str,
    workdir: str | Path,
) -> list[tuple[Path, FileAction]]:
    if not command or not isinstance(command, str):
        return []
    base = Path(workdir).resolve()
    results: list[tuple[Path, FileAction]] = []
    literal = parse_literal_shell(command)
    if literal is not None:
        for call in literal.commands:
            executable = _basename_lower(call.argv[0])
            if executable == "cd":
                target = Path(call.argv[-1])
                base = (target if target.is_absolute() else base / target).resolve()
                results.append((base, "read"))
                continue
            accesses, _new_cwd = _path_aware_one_segment(call.text, base)
            results.extend(accesses)
            if is_script_interpreter(executable):
                target = Path(call.argv[1])
                target = (target if target.is_absolute() else base / target).resolve()
                results.append((target, "exec"))
        return results

    def _resolve(token: str) -> Path | None:
        token = token.strip().strip('"').strip("'")
        if not token or not _looks_like_path(token):
            return None
        path = Path(token)
        if not path.is_absolute():
            path = base / token
        try:
            return path.resolve()
        except (OSError, RuntimeError):
            return None

    cwd = base
    for segment in _segments_for_extract(command):
        part, new_cwd = _path_aware_one_segment(segment, cwd)
        results.extend(part)
        if new_cwd is not None:
            cwd = new_cwd

    for match in re.finditer(r"(?:^|[\s;|&])(\d*>>?|\d*<|&>)\s*([^\s;|&<>]+)", command):
        operator, target = match.group(1), match.group(2)
        resolved = _resolve(target)
        if resolved is None:
            continue
        if "<" in operator and ">" not in operator:
            results.append((resolved, "read"))
        else:
            results.append((resolved, "write"))

    try:
        tokens = shlex.split(command.strip(), posix=False)
    except ValueError:
        tokens = command.strip().split()
    if len(tokens) >= 2:
        command_name = _basename_lower(tokens[0])
        if command_name in _INTERPRETER_BASENAMES:
            script_token = tokens[1].strip('"').strip("'")
            if script_token and not script_token.startswith("-"):
                resolved = _resolve(script_token)
                if resolved is not None:
                    results.append((resolved, "exec"))
    return results


def _resolve_path_str(raw: str, workspace: Path) -> Path | None:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return None
    try:
        path = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not path.is_absolute():
            path = (workspace / path).resolve()
        else:
            path = path.resolve()
        return path
    except (OSError, RuntimeError):
        return None


def extract_accesses_native(
    tool_name: str,
    tool_args: Mapping[str, Any],
    workspace: Path,
) -> list[tuple[Path, FileAction, str]]:
    """Native accesses for the listed shell tools and the ``glob`` pattern arg."""

    out: list[tuple[Path, FileAction, str]] = []
    if tool_name in _LISTED_SHELL_TOOLS:
        workdir = tool_args.get("workdir", "")
        try:
            workdir_resolved = (workspace / str(workdir)).resolve() if workdir else workspace
        except (OSError, RuntimeError):
            workdir_resolved = workspace
        raw_workdir = tool_args.get("workdir")
        if isinstance(raw_workdir, str) and raw_workdir.strip():
            try:
                workdir_path = Path(raw_workdir)
                if workdir_path.is_absolute():
                    workdir_resolved = workdir_path.resolve()
            except (OSError, RuntimeError):
                pass
        command = str(tool_args.get("command", "") or tool_args.get("cmd", ""))
        for path, action in extract_shell_path_accesses(command, workdir_resolved):
            out.append((path, action, "shlex"))
        return out

    specs = _FILE_SPECS.get(tool_name)
    if specs:
        for arg_name, action in specs:
            raw = tool_args.get(arg_name)
            if not isinstance(raw, str) or not raw.strip():
                continue
            resolved = _resolve_path_str(raw, workspace)
            if resolved is None:
                continue
            out.append((resolved, action, "tool_arg"))
        return out

    if tool_name in _PATH_TOOLS:
        action: FileAction = "write" if tool_name in _WRITE_PATH_TOOLS else "read"
        for raw_path in _iter_path_strings(tool_name, tool_args):
            resolved = _resolve_path_str(raw_path, workspace)
            if resolved is None:
                continue
            out.append((resolved, action, "tool_arg"))
    return out


def _extract_paths_from_command(command: str, workdir: str | Path) -> list[Path]:
    if not command or not isinstance(command, str):
        return []
    try:
        tokens = shlex.split(command.strip(), posix=False)
    except ValueError:
        tokens = command.strip().split()
    if not tokens:
        return []
    command_name = tokens[0].lower()
    if command_name not in _LEGACY_PATH_AWARE_COMMANDS:
        return []
    base = Path(workdir).resolve()
    paths: list[Path] = []
    for token in tokens[1:]:
        token = token.strip().strip('"').strip("'")
        if not token or token.startswith("-") or not _legacy_looks_like_path(token):
            continue
        path = Path(token)
        if not path.is_absolute():
            path = base / token
        try:
            paths.append(path.resolve())
        except (OSError, RuntimeError):
            continue
    return paths


def extract_paths_legacy(
    tool_name: str,
    tool_args: Mapping[str, Any],
    workspace: Path,
) -> list[Path]:
    """Legacy path list for the listed shell tools."""

    if tool_name in _LISTED_SHELL_TOOLS:
        workdir = tool_args.get("workdir", "")
        try:
            workdir_resolved = (workspace / str(workdir)).resolve()
        except (OSError, RuntimeError):
            workdir_resolved = workspace
        command = str(tool_args.get("command", "") or tool_args.get("cmd", ""))
        paths = _extract_paths_from_command(command, workdir_resolved)
        if parse_literal_shell(command) is not None:
            paths.extend(
                path for path, _action in extract_shell_path_accesses(command, workdir_resolved)
            )
        return paths
    if tool_name not in _PATH_TOOLS:
        return []
    paths: list[Path] = []
    for raw_path in _iter_path_strings(tool_name, tool_args):
        raw = raw_path.strip().strip('"').strip("'")
        if not raw:
            continue
        try:
            path = Path(raw)
            if not path.is_absolute():
                path = (workspace / path).resolve()
            else:
                path = path.resolve()
            paths.append(path)
        except (OSError, RuntimeError):
            continue
    return paths


__all__ = ["extract_accesses_native", "extract_paths_legacy"]
