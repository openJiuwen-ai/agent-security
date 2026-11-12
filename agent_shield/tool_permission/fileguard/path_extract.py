# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Native L1 path extraction：registry 通道 + shell（分段 / redirect / 解释器）。

Literal resource analysis is bounded and independent of host execution.
Relative paths require an explicit working directory.
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..delguard.del_count import split_shell_operands
from ..toolguard.command_canonicalize import (
    canonicalize_shell_command_for_permission,
)
from .file_tool_specs import (
    FileToolSpec,
    lookup_file_tool_specs,
)
from .outbound_paths import (
    is_public_file_url,
    normalize_file_path_list,
    resolve_outbound_path,
)
from .path_policy import _PATH_TOOLS, _iter_path_strings

logger = logging.getLogger(__name__)

FileAction = Literal["read", "write", "exec"]

_MSYS_DRIVE_RE = re.compile(r"^/([A-Za-z])(?:/|$)")
_SHELL_WORD_RE = re.compile(r'''(?:"[^"]*"|'[^']*'|[^\s<>"']+)+|>>?|<''')
_POSIX_WORD_RE = re.compile(r'''(?:"(?:\\.|[^"\\])*"|'[^']*'|\\.|[^\s<>"'\\])+|>>?|<''')
_CMD_WORD_RE = re.compile(r'''(?:"[^"]*"|\^.|[^\s<>"^])+|>>?|<''')
_MAX_CWD_CANDIDATES = 128
_MAX_EXTRACTION_STEPS = 1024
_MAX_INLINE_DEPTH = 4

_PATH_AWARE_COMMANDS = frozenset({
    "cd", "rm", "cp", "mv", "mkdir", "touch", "chmod", "chown", "cat",
    "ls", "dir", "type", "del", "erase", "rd", "rmdir", "copy", "move", "md",
    "head", "tail", "more", "less", "vim", "nano", "gedit", "notepad",
    "get-content", "gc",
    "set-content", "add-content", "out-file", "tee", "tee-object", "sc",
    "remove-item", "ri", "new-item", "ni",
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
_NT_CMD_SWITCH_COMMANDS = frozenset({
    "cd", "dir", "del", "erase", "copy", "move", "rd", "rmdir", "md",
    "type", "ren", "rename", "xcopy", "attrib", "cmd", "notepad",
})

_READ_CMDS = frozenset({
    "cat", "ls", "dir", "type", "head", "tail", "more", "less",
    "get-content", "gc",
})
_WRITE_CMDS = frozenset({
    "mkdir", "touch", "chmod", "chown", "md",
    "set-content", "add-content", "out-file", "tee", "tee-object", "sc",
    "new-item", "ni",
})
# Keep deletions on the existing SDK write axis.
_DELETE_CMDS = frozenset({
    "rm", "del", "erase", "rd", "rmdir", "remove-item", "ri",
})
_PS_PATH_FLAGS = frozenset({"-path", "-literalpath", "-filepath"})
_FD_ALIAS_RE = re.compile(r"^&\d+$")
_UNEXPANDED_VAR_RE = re.compile(r"(?i)\$(\w+|\{[^}]+\}|env:\w+)")
_TRANSFER_CMDS = frozenset({"cp", "copy", "mv", "move"})
_WIN_ABS_RE = re.compile(r"^[A-Za-z]:[\\/]")


def _is_windows_abs_text(text: str) -> bool:
    return bool(_WIN_ABS_RE.match(str(text).strip().strip('"').strip("'")))


def _resolve_extract_path(path: Path) -> Path:
    """Resolve local paths; keep Windows drive paths intact on POSIX."""
    if os.name != "nt" and _is_windows_abs_text(str(path)):
        return path
    return path.resolve()


def _nt_cmd_exe_switch_token(stripped: str, *, cmd0: str = "") -> bool:
    """True for cmd.exe switches such as ``/b``, ``/d``, ``/s/q``.

    Linux still sees Windows ``dir /b`` / ``cd /d`` (via ``cmd //c``). Treat
    those tokens as switches for cmd builtins even when ``os.name != "nt"``.
    POSIX tools like ``ls /b`` or ``cat /tmp`` keep the token as a path.
    """
    if not stripped.startswith("/") or stripped.startswith("//"):
        return False
    if "\\" in stripped:
        return False
    parts = [part for part in stripped.split("/") if part]
    if not parts or not all(_NT_CMD_SWITCH_BODY.match(part) for part in parts):
        return False
    if os.name == "nt":
        return True
    return cmd0 in _NT_CMD_SWITCH_COMMANDS


def _looks_like_path(token: str) -> bool:
    t = token.strip().strip('"').strip("'")
    if _nt_cmd_exe_switch_token(t):
        return False
    if t in (".", ".."):
        return True
    if t.startswith(("\\\\", "./", "../")):
        return True
    if re.match(r"^[A-Za-z]:[\\/]", t):
        return True
    return "\\" in t or "/" in t


def _looks_like_redirect_target(token: str) -> bool:
    t = token.strip().strip('"').strip("'")
    if not t or _FD_ALIAS_RE.match(t):
        return False
    if t.startswith("$") or _UNEXPANDED_VAR_RE.search(t):
        return False
    return True


def _collect_ps_path_tokens(tokens: list[str]) -> list[str]:
    """返回仍带引号的原始词，方便后续按引号外逗号拆 PowerShell 列表。"""
    out: list[str] = []
    first_positional = True
    idx = 1
    while idx < len(tokens):
        raw = tokens[idx].strip()
        bare = raw.strip('"').strip("'")
        flag = bare.lower().split(":")[0]
        if flag in _PS_PATH_FLAGS:
            if idx + 1 < len(tokens):
                out.append(tokens[idx + 1].strip())
                idx += 2
                continue
        if bare.startswith("-"):
            idx += 1
            continue
        if first_positional and raw:
            out.append(raw)
            first_positional = False
        idx += 1
    return out


def _is_shell_flag_token(tok: str, *, cmd0: str = "", shell_type: str = "auto") -> bool:
    s = tok.strip().strip('"').strip("'")
    if not s:
        return True
    if s.startswith("-"):
        return True
    if os.name == "nt" and shell_type in {"bash", "sh"} and _MSYS_DRIVE_RE.match(s):
        return False
    return _nt_cmd_exe_switch_token(s, cmd0=cmd0)


def _basename_lower(cmd: str) -> str:
    base = Path(cmd.replace("\\", "/")).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _shell_segments(text: str, shell_type: str, *, check_scope: bool = False) -> list[tuple[str, str]]:
    """Keep literal redirects and the connector after each quoted shell segment."""
    parts: list[tuple[str, str]] = []
    buf: list[str] = []
    quote = ""
    i = 0
    while i < len(text):
        ch = text[i]
        escape = "\\" if shell_type in {"bash", "sh"} else "`" if shell_type == "powershell" else "^"
        quoted_cmd = shell_type == "cmd" and bool(quote)
        can_escape = ch == escape and quote != "'" and not quoted_cmd
        if can_escape and i + 1 < len(text):
            buf.extend(text[i:i + 2])
            i += 2
            continue
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch == '"' or (ch == "'" and shell_type != "cmd"):
            quote = ch
            buf.append(ch)
            i += 1
            continue
        powershell_brace = shell_type == "powershell" and ch in "{}"
        group_scope = ch in "()" or powershell_brace
        if check_scope and group_scope:
            raise ShellPathUnresolvedShellError("Unsupported shell group or expression scope")
        separators = "\r\n|&" if shell_type == "cmd" else ";\r\n|&"
        if ch in separators and not (
            ch == "&" and (text.startswith("&>", i) or (i > 0 and text[i - 1] in "><"))
        ):
            connector = next((op for op in ("&&", "||", "|&") if text.startswith(op, i)), ch)
            i += len(connector)
            part = "".join(buf).strip()
            if part:
                parts.append((part, connector))
            buf = []
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append((tail, ""))
    return parts


def _decode_cmd_word(word: str) -> str:
    """CMD quotes are double quotes; apostrophes belong to the filename."""
    out: list[str] = []
    quoted = False
    index = 0
    while index < len(word):
        char = word[index]
        if char == '"':
            quoted = not quoted
        elif char == "^" and not quoted and index + 1 < len(word):
            index += 1
            out.append(word[index])
        else:
            out.append(char)
        index += 1
    return "".join(out)


def _execution_tokens(tokens: list[str], shell_type: str) -> list[str]:
    """Recognize literal POSIX builtin prefixes without treating queries as calls."""
    if shell_type not in {"bash", "sh"} or not tokens or tokens[0] not in {"command", "builtin"}:
        return tokens
    for _ in range(_MAX_INLINE_DEPTH):
        if not tokens or tokens[0] not in {"command", "builtin"}:
            return tokens
        prefix = tokens[0]
        index = 1
        while index < len(tokens) and tokens[index].startswith("-"):
            option = tokens[index]
            index += 1
            if option == "--":
                break
            if prefix == "command" and option in {"-v", "-V"}:
                return []
            if prefix != "command" or option != "-p":
                raise ShellPathUnresolvedShellError("Unsupported shell builtin prefix options")
        tokens = tokens[index:]
    if not tokens or tokens[0] not in {"command", "builtin"}:
        return tokens
    _raise_analysis_limit("nested shell builtin prefix limit")
    return []  # Unreachable; keeps the token return contract explicit.


def _redirect_glued_to_previous(words: list[re.Match[str]], idx: int) -> bool:
    """True when a redirect operator is written against the preceding word."""
    if not idx:
        return False
    return words[idx - 1].end() == words[idx].start()


def _token_is_fd_alias(token: str) -> bool:
    """True for a glued descriptor such as ``2>`` or ``&>``."""
    return token.isdigit() or token == "&"


def _segment_tokens(segment: str, shell_type: str = "auto") -> tuple[list[str], list[tuple[str, FileAction]]]:
    """Separate redirects without mistaking quoted text or fd aliases for files."""
    _shell_segments(segment, shell_type, check_scope=True)
    pattern = _CMD_WORD_RE if shell_type == "cmd" else (
        _POSIX_WORD_RE if shell_type in {"bash", "sh"} else _SHELL_WORD_RE
    )
    words = list(pattern.finditer(segment))
    end = 0
    for match in words:
        if segment[end:match.start()].strip():
            raise ShellPathUnresolvedShellError("Incomplete shell word analysis")
        end = match.end()
    if segment[end:].strip():
        raise ShellPathUnresolvedShellError("Incomplete shell word analysis")
    tokens: list[str] = []
    redirects: list[tuple[str, FileAction]] = []
    idx = 0
    while idx < len(words):
        word = words[idx].group()
        if word in {">", ">>", "<"}:
            glued = bool(tokens) and _redirect_glued_to_previous(words, idx)
            if glued and _token_is_fd_alias(tokens[-1]):
                tokens.pop()
            if idx + 1 < len(words):
                target = words[idx + 1].group()
                if _looks_like_redirect_target(target):
                    redirects.append((target, "read" if word == "<" else "write"))
                idx += 1
        else:
            tokens.append(word)
        idx += 1
    return tokens, redirects


def _resolve_shell_operand(
    tok: str, cwd: Path | None, shell_type: str, *, bare: bool = False,
    resolve_path: Callable[[Path], Path] | None = None,
) -> Path | None:
    quoted = tok.startswith(('"', "'"))
    if shell_type in {"bash", "sh"} and not _is_windows_abs_text(tok):
        try:
            tok = shlex.split(tok, posix=True)[0]
        except (ValueError, IndexError):
            return None
    tok = _decode_cmd_word(tok.strip()) if shell_type == "cmd" else tok.strip().strip('"').strip("'")
    if not tok or _UNEXPANDED_VAR_RE.search(tok):
        return None
    if shell_type == "cmd" and re.search(r"%[^%\r\n]+%", tok):
        return None
    expands_home = not quoted and shell_type in {"bash", "sh"}
    home_token = tok == "~" or tok.startswith("~/")
    if expands_home and home_token:
        tok = str(Path(os.environ.get("HOME") or Path.home()) / tok[2:])
    msys = _MSYS_DRIVE_RE.match(tok) if os.name == "nt" and shell_type in {"bash", "sh"} else None
    if not bare and not msys and not _looks_like_path(tok):
        return None
    if msys:
        tok = f"{msys.group(1).upper()}:/{tok[msys.end():]}"
    path = Path(tok)
    if not path.is_absolute() and not (os.name != "nt" and _is_windows_abs_text(tok)):
        if cwd is None:
            return None
        path = cwd / path
    try:
        return (resolve_path or _resolve_extract_path)(path)
    except (OSError, RuntimeError):
        return None


def _interpreter_options(cmd: str) -> tuple[set[str], set[str], set[str], set[str], str] | None:
    """Return value, preload, inline and flag options for literal script calls."""
    if re.fullmatch(r"python(?:w|\d+(?:\.\d+)*)?", cmd) or cmd == "py":
        return (
            {"-W", "-X", "--check-hash-based-pycs"}, set(), {"-c", "-m"}, {"--version", "--help"},
            r"-[bBdEhiIOPqRsSuvVx?]+|-\d+(?:\.\d+)*|-V:.+",
        )
    if cmd in {"node", "nodejs"}:
        return (
            {"--title", "--stack-trace-limit", "--max-old-space-size", "--conditions", "-C"},
            {"-r", "--require", "--loader", "--experimental-loader", "--import"},
            {"-e", "--eval", "-p", "--print"},
            {"--trace-warnings", "--no-warnings", "--enable-source-maps", "--inspect", "--inspect-brk"}, r"-[iv]+",
        )
    if cmd in {"pwsh", "powershell"}:
        return (
            {"-executionpolicy", "-inputformat", "-outputformat", "-windowstyle"}, set(),
            {"-command", "-c", "-encodedcommand", "-enc"},
            {"-noprofile", "-noninteractive", "-nologo", "-noexit", "-file", "-f"}, r"(?!)",
        )
    if cmd in _INTERPRETER_BASENAMES:
        return (
            {"-o", "-O", "+o", "+O"}, {"--rcfile", "--init-file"}, {"-c"},
            {"--noprofile", "--norc", "--posix", "--login", "--help", "--version"},
            r"[-+][abefhkmnptuvxBCEHPT]+",
        )
    return None


def _interpreter_operands(tokens: list[str]) -> list[str]:
    """Find main/preload files; unknown option arity keeps all possible operands."""
    if not tokens:
        return []
    cmd = _basename_lower(tokens[0].strip('"').strip("'"))
    options = _interpreter_options(cmd)
    if options is None:
        return []
    values, loads, inline, flags, short = options
    out: list[str] = []
    uncertain = False
    idx = 1
    while idx < len(tokens):
        tok = tokens[idx]
        if len(tok) >= 2 and tok[0] == tok[-1] and tok[0] in "\"'":
            tok = tok[1:-1]
        if tok in {"--", "-"}:
            if tok == "--" and idx + 1 < len(tokens):
                out.append(tokens[idx + 1])
            break
        option, equals, value = tok.partition("=")
        if cmd in {"powershell", "pwsh"}:
            option = option.lower()
        inline_shell = (
            cmd in {"bash", "sh", "dash", "zsh", "fish"}
            and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", tok)
        )
        inline_python = cmd.startswith("py") and re.fullmatch(r"-[bBdEhiIOPqRsSuvVx]*[cm].*", tok)
        if option in inline or inline_shell or inline_python:
            break  # Code strings / modules are not literal script paths.
        if option in values | loads:
            if not equals:
                idx += 1
                value = tokens[idx] if idx < len(tokens) else ""
            if option in loads and value:
                out.append(value)
        elif cmd in {"python", "python3", "pythonw", "py"} and tok[:2] in {"-W", "-X"}:
            pass  # Attached option value, e.g. -Wignore or -Xutf8.
        elif cmd in {"node", "nodejs"} and tok.startswith("-r") and len(tok) > 2:
            out.append(tok[2:])
        elif option in flags or re.fullmatch(short, tok):
            pass
        elif tok.startswith("-") or ("-o" in values and tok.startswith("+")):
            uncertain = True
        else:
            out.append(tokens[idx])
            if not uncertain:
                break
        idx += 1
    return out


def _cd_has_dynamic_glob(operand: str, shell_type: str, *, literal_path: bool) -> bool:
    """Do not treat a directory selected by wildcard expansion as a literal."""
    if shell_type == "powershell":
        return not literal_path and any(char in operand for char in "*?[")
    if shell_type == "cmd":
        return any(char in operand for char in "*?")
    quote = ""
    escaped = False
    for char in operand:
        if escaped:
            escaped = False
        elif char == "\\" and quote != "'":
            escaped = True
        elif quote:
            if char == quote:
                quote = ""
        elif char in "\"'":
            quote = char
        elif char in "*?[":
            return True
    return False


@dataclass(frozen=True)
class _CdTarget:
    kind: Literal["unchanged", "home", "literal", "unknown"]
    operand: str = ""
    literal_path: bool = False
    change_drive: bool = False


def _cd_option_value(token: str) -> str:
    if len(token) >= 2 and token[0] == token[-1] and token[0] in "\"'":
        return token[1:-1]
    return token


def _posix_cd_target(tokens: list[str], shell_type: str) -> _CdTarget:
    index = 1
    options = "LPe" if shell_type == "bash" else "LP"
    while index < len(tokens):
        option = _cd_option_value(tokens[index])
        if option == "--":
            index += 1
            break
        if option == "--help" and shell_type == "bash":
            return _CdTarget("unchanged")
        if not option.startswith("-") or option == "-":
            break
        if len(option) < 2 or any(char not in options for char in option[1:]):
            return _CdTarget("unknown")
        index += 1
    operands = tokens[index:]
    if not operands:
        return _CdTarget("home")
    if len(operands) != 1 or _cd_option_value(operands[0]) == "-":
        # OLDPWD belongs to the actual shell session, not this SDK process.
        return _CdTarget("unknown")
    return _CdTarget("literal", operands[0])


def _cmd_cd_target(tokens: list[str]) -> _CdTarget:
    args = tokens[1:]
    if not args or (len(args) == 1 and _decode_cmd_word(args[0]).lower() in {"/?", "/d"}):
        # Bare cd and /? are queries; /d without its target fails without
        # changing cwd. This does not model the command's exit status.
        return _CdTarget("unchanged")
    change_drive = _decode_cmd_word(args[0]).lower() == "/d"
    operand = " ".join(args[1:] if change_drive else args)
    raw = _decode_cmd_word(operand)
    if re.fullmatch(r"[A-Za-z]:", raw):
        return _CdTarget("unknown" if change_drive else "unchanged")
    if re.match(r"^[A-Za-z]:(?![\\/])", raw):
        return _CdTarget("unknown")  # No trusted per-drive current-directory state.
    return _CdTarget("literal", operand, change_drive=change_drive)


def _powershell_cd_target(tokens: list[str]) -> _CdTarget:
    operand = None
    literal_path = False
    index = 1
    while index < len(tokens):
        option = _cd_option_value(tokens[index]).lower()
        if option in {"-passthru", "-verbose", "-debug"}:
            index += 1
            continue
        if option in {"-path", "-literalpath"}:
            index += 1
            if index == len(tokens):
                return _CdTarget("unknown")
            literal_path = option == "-literalpath"
        elif option.startswith("-"):
            return _CdTarget("unknown")
        if operand is not None:
            return _CdTarget("unknown")
        operand = tokens[index]
        index += 1
    if operand is None:
        return _CdTarget("home")
    if _cd_option_value(operand) == "-":
        return _CdTarget("unknown")
    return _CdTarget("literal", operand, literal_path=literal_path)


def _cd_accesses(
    tokens: list[str], cwd: Path | None, *, include_cd_reads: bool, shell_type: str,
    resolve_path: Callable[[Path], Path] | None = None,
) -> tuple[list[tuple[Path, FileAction]], Path | None]:
    if shell_type in {"bash", "sh"}:
        target = _posix_cd_target(tokens, shell_type)
    elif shell_type == "cmd":
        target = _cmd_cd_target(tokens)
    elif shell_type == "powershell":
        target = _powershell_cd_target(tokens)
    else:
        target = _CdTarget("unknown")
    if target.kind == "unchanged":
        return [], None
    directory = None
    if target.kind == "home":
        try:
            directory = (resolve_path or _resolve_extract_path)(Path.home())
        except (OSError, RuntimeError) as exc:
            raise ShellPathUnresolvedCwdError("Shell working directory could not be resolved") from exc
    elif target.kind == "literal" and not _cd_has_dynamic_glob(
        target.operand, shell_type, literal_path=target.literal_path,
    ):
        directory = _resolve_shell_operand(target.operand, cwd, shell_type, bare=True, resolve_path=resolve_path)
    if directory is None:
        raise ShellPathUnresolvedCwdError("Shell working directory requires a literal cd target")
    cmd_on_windows = shell_type == "cmd" and os.name == "nt"
    unknown_active_drive = cwd is None and not target.change_drive
    if cmd_on_windows and unknown_active_drive:
        raise ShellPathUnresolvedCwdError("Shell working directory requires a known active drive")
    accesses: list[tuple[Path, FileAction]] = [(directory, "read")] if include_cd_reads else []
    other_drive = (
        shell_type == "cmd" and os.name == "nt" and cwd is not None
        and directory.drive.lower() != cwd.drive.lower()
    )
    if other_drive and not target.change_drive:
        return accesses, None
    return accesses, directory


def _directory_command(tokens: list[str], shell_type: str) -> bool:
    """Recognize cwd builtins once for every resource-analysis consumer."""
    if not tokens:
        return False
    cmd0 = _basename_lower(_decode_cmd_word(tokens[0]) if shell_type == "cmd" else tokens[0].strip('"').strip("'"))
    if cmd0 in {"pushd", "popd", "push-location", "pop-location"}:
        raise ShellPathUnresolvedCwdError("Shell working directory stack is unknown")
    aliases = {"cd", "set-location", "sl", "chdir"} if shell_type == "powershell" else (
        {"cd", "chdir"} if shell_type == "cmd" else {"cd"}
    )
    return cmd0 in aliases


def _path_aware_one_segment(
    segment: str, cwd: Path | None, *, include_cd_reads: bool = True, shell_type: str = "auto",
) -> tuple[list[tuple[Path, FileAction]], Path | None]:
    tokens, _ = _segment_tokens(segment, shell_type)
    tokens = _execution_tokens(tokens, shell_type)
    if not tokens:
        return [], None
    cmd0 = _basename_lower(_decode_cmd_word(tokens[0]) if shell_type == "cmd" else tokens[0].strip('"').strip("'"))
    if _directory_command(tokens, shell_type):
        return _cd_accesses(tokens, cwd, include_cd_reads=include_cd_reads, shell_type=shell_type)
    if cmd0 not in _PATH_AWARE_COMMANDS:
        return [], None
    base = _resolve_extract_path(cwd) if cwd is not None else None
    path_tokens: list[tuple[Path, int]] = []

    def _append_path_token(tok: str, idx: int, *, require_path_shape: bool) -> None:
        path = _resolve_shell_operand(tok, base, shell_type, bare=not require_path_shape)
        if path is not None:
            path_tokens.append((path, idx))

    for idx, tok in enumerate(tokens[1:]):
        if cmd0 in {"dir", "ls"} and any(ch in tok for ch in "*?") and not any(ch in tok for ch in "/\\"):
            continue  # A bare listing glob reads cwd, not a fictitious literal file.
        bare_read_operand = shell_type in {"cmd", "powershell"} and cmd0 in _READ_CMDS
        # tee / Tee-Object 的目标经常是裸文件名，不要求带斜杠。
        loose_operand = bare_read_operand or cmd0 in {"cd", "tee", "tee-object"}
        pieces = [tok] if shell_type == "cmd" else split_shell_operands(
            tok, shell_type=shell_type, cmd0=cmd0,
        )
        for piece in pieces:
            if _is_shell_flag_token(piece, cmd0=cmd0, shell_type=shell_type):
                continue
            _append_path_token(piece, idx, require_path_shape=not loose_operand)

    if cmd0 in (
        "get-content", "gc", "set-content", "add-content", "out-file",
        "tee-object", "sc", "remove-item", "ri", "new-item", "ni",
    ):
        for extra in _collect_ps_path_tokens(tokens):
            for piece in split_shell_operands(extra, shell_type=shell_type, cmd0=cmd0):
                if _is_shell_flag_token(piece, cmd0=cmd0, shell_type=shell_type):
                    continue
                _append_path_token(piece, len(path_tokens), require_path_shape=False)

    results: list[tuple[Path, FileAction]] = []
    new_cwd: Path | None = None

    if cmd0 in _TRANSFER_CMDS and len(path_tokens) >= 2:
        for p, _ in path_tokens[:-1]:
            results.append((p, "read"))
            if cmd0 in {"mv", "move"}:
                # Moving removes each source; policy checks delete on the write axis.
                results.append((p, "write"))
        results.append((path_tokens[-1][0], "write"))
    elif cmd0 in _DELETE_CMDS or cmd0 in _WRITE_CMDS:
        for p, _ in path_tokens:
            results.append((p, "write"))
    elif cmd0 in _READ_CMDS:
        if not path_tokens and cmd0 in ("dir", "ls") and base is not None:
            try:
                results.append((_resolve_extract_path(base), "read"))
            except (OSError, RuntimeError):
                pass
        else:
            for p, _ in path_tokens:
                results.append((p, "read"))
    else:
        for p, _ in path_tokens:
            results.append((p, "write"))
    return results, new_cwd


def _shell_segment_accesses(
    segment: str, cwd: Path | None, *, include_cd_reads: bool, shell_type: str, shell_extras: bool,
) -> tuple[list[tuple[Path, FileAction]], Path | None]:
    """Use one entry cwd for file operands, interpreter scripts and redirects."""
    part, new_cwd = _path_aware_one_segment(
        segment, cwd, include_cd_reads=include_cd_reads, shell_type=shell_type,
    )
    tokens, redirects = _segment_tokens(segment, shell_type)
    tokens = _execution_tokens(tokens, shell_type)
    if shell_extras:
        for tok, action in [(tok, "exec") for tok in _interpreter_operands(tokens)] + redirects:
            path = _resolve_shell_operand(tok, cwd, shell_type, bare=True)
            if path is not None:
                part.append((path, action))
    return part, new_cwd


def _inline_shell_command(segment: str, tokens: list[str], shell_type: str) -> tuple[str | None, str]:
    inline = _literal_shell_inline(tokens, shell_type)
    child_shell = "bash" if tokens and _basename_lower(tokens[0]) == "bash" else "sh"
    if inline is None and tokens:
        launcher = _basename_lower(tokens[0].strip('"').strip("'"))
        if launcher in {"cmd", "powershell", "pwsh"}:
            peeled = canonicalize_shell_command_for_permission(segment)
            if peeled != segment:
                inline = peeled
                child_shell = "cmd" if launcher == "cmd" else "powershell"
    return inline, child_shell


def _literal_shell_inline(tokens: list[str], shell_type: str) -> str | None:
    """Read only literal Bash/Sh -c bodies; the child cwd never escapes."""
    if not tokens or _basename_lower(tokens[0].strip('"').strip("'")) not in {"bash", "sh", "dash", "zsh"}:
        return None
    index = 1
    while index < len(tokens):
        token = _cd_option_value(tokens[index])
        if re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", token):
            if index + 1 == len(tokens):
                raise ShellPathUnresolvedShellError("Inline shell command requires a literal body")
            raw = tokens[index + 1]
            # A single-quoted body is literal in the parent shell; variables
            # inside it are handled per operand by the recursive extractor.
            single_quoted = shell_type != "cmd" and re.fullmatch(r"'[^']*'", raw) is not None
            cmd_percent = shell_type == "cmd" and "%" in raw
            parent_expansion = "$" in raw or "`" in raw or cmd_percent
            if not single_quoted and parent_expansion:
                raise ShellPathUnresolvedShellError("Inline shell body contains unresolved parent-shell expansion")
            try:
                return _decode_cmd_word(raw) if shell_type == "cmd" else shlex.split(raw, posix=True)[0]
            except (ValueError, IndexError) as exc:
                raise ShellPathUnresolvedShellError("Inline shell body could not be decoded") from exc
        if token in {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}:
            index += 2  # Named options take a value before the -c command.
            continue
        if token == "--" or not token.startswith(("-", "+")):
            break
        if not re.fullmatch(r"[-+][a-zA-Z]+", token) and token not in {
            "--noprofile", "--norc", "--posix", "--login", "--help", "--version",
        }:
            raise ShellPathUnresolvedShellError("Unknown shell option arity prevents inline command analysis")
        index += 1
    return None


class ShellPathAnalysisLimitError(ValueError):
    """Literal resource analysis exhausted its bounded work budget."""


class ShellPathUnresolvedCwdError(ValueError):
    """A cd target is unknown, so resource analysis cannot produce a complete view."""


class ShellPathUnresolvedShellError(ValueError):
    """A shell body or scope cannot provide a complete literal resource view."""


def _raise_analysis_limit(reason: str) -> None:
    raise ShellPathAnalysisLimitError(reason)


def _shell_profiles(command: str, shell_type: str) -> tuple[str, ...]:
    """An unknown host shell requires conservative views, never host imports."""
    del command
    shell_type = {"pwsh": "powershell", "ps": "powershell", "dos": "cmd"}.get(shell_type, shell_type)
    if shell_type == "auto":
        return ("cmd", "powershell", "sh") if os.name == "nt" else ("sh",)
    return (shell_type,)


def _walk_shell_segments(
    command: str, workdir: str | Path | None, *, shell_type: str,
    resolve_path: Callable[[Path], Path] | None = None, depth: int = 0, budget: list[int] | None = None,
) -> Iterator[tuple[str, Path | None, str]]:
    """Share literal control flow, cwd candidates and budgets without resolving operands.

    File access resolves cwd aliases for policy matching; deletion counting can
    supply lexical normalization to retain the identity of links being deleted.
    Inline shells inherit entry cwd, but never change their parent's cwd.
    """
    if budget is None:
        budget = [_MAX_EXTRACTION_STEPS]
    for profile in _shell_profiles(command, shell_type):
        segments = _shell_segments(command, profile)
        # A later ; / || can resume after an earlier && chain was skipped.
        # Keep its failure cwd candidates across the whole chain. A pipeline
        # alone cannot resume a skipped && branch; its cwd uncertainty is local.
        may_resume = any(op not in {"", "&&", "|", "|&"} for _, op in segments)
        cwds = {(resolve_path or _resolve_extract_path)(Path(workdir)) if workdir is not None else None}
        previous_op = ""
        for segment, connector in segments:
            next_cwds: set[Path | None] = set()
            for cwd in sorted(cwds, key=str):
                budget[0] -= 1
                if budget[0] < 0:
                    _raise_analysis_limit("shell path analysis work limit")
                tokens, _ = _segment_tokens(segment, profile)
                tokens = _execution_tokens(tokens, profile)
                new_cwd = None
                if _directory_command(tokens, profile):
                    _, new_cwd = _cd_accesses(
                        tokens, cwd, include_cd_reads=False, shell_type=profile, resolve_path=resolve_path,
                    )
                yield segment, cwd, profile
                inline, child_shell = _inline_shell_command(segment, tokens, profile)
                if inline is not None:
                    if depth >= _MAX_INLINE_DEPTH:
                        _raise_analysis_limit("inline shell depth limit")
                    yield from _walk_shell_segments(
                        inline, cwd, shell_type=child_shell, resolve_path=resolve_path, depth=depth + 1, budget=budget,
                    )
                    new_cwd = None
                if new_cwd is not None:
                    next_cwds.add(new_cwd)
                else:
                    next_cwds.add(cwd)
            # Pipeline cd commands may run in child processes. Retain the
            # pipeline entry cwd through its last stage for later parent work.
            uncertain_cwd = may_resume or connector in {"|", "|&"} or previous_op in {"|", "|&"}
            cwds = cwds | next_cwds if uncertain_cwd else next_cwds
            previous_op = connector
            if len(cwds) > _MAX_CWD_CANDIDATES:
                _raise_analysis_limit("shell path extraction exceeded the cwd candidate limit")


def _extract_segment_accesses(
    command: str, workdir: str | Path | None, *, include_cd_reads: bool, shell_type: str, shell_extras: bool,
    depth: int = 0, budget: list[int] | None = None,
) -> list[tuple[Path, FileAction]]:
    results: list[tuple[Path, FileAction]] = []
    for segment, cwd, profile in _walk_shell_segments(
        command, workdir, shell_type=shell_type, depth=depth, budget=budget,
    ):
        part, _ = _shell_segment_accesses(
            segment, cwd, include_cd_reads=include_cd_reads, shell_type=profile, shell_extras=shell_extras,
        )
        results.extend(part)
    return list(dict.fromkeys(results))


def extract_path_aware_command_accesses(
    command: str,
    workdir: str | Path | None,
    *,
    include_cd_reads: bool = True,
    shell_type: str = "auto",
) -> list[tuple[Path, FileAction]]:
    if not command or not isinstance(command, str):
        return []
    return _extract_segment_accesses(
        command, workdir, include_cd_reads=include_cd_reads, shell_type=shell_type, shell_extras=False,
    )


def extract_shell_path_accesses(
    command: str,
    workdir: str | Path | None,
    *,
    include_cd_reads: bool = True,
    shell_type: str = "auto",
) -> list[tuple[Path, FileAction]]:
    if not command or not isinstance(command, str):
        return []
    if shell_type == "cmd":
        # Match cmd /s /c: remove the first and last double quotes when the
        # command starts with a quote. This is a permission-view copy only.
        command = command.strip()
        last_quote = command.rfind('"')
        if command.startswith('"') and last_quote > 0:
            command = command[1:last_quote] + command[last_quote + 1:]
    return _extract_segment_accesses(
        command, workdir, include_cd_reads=include_cd_reads, shell_type=shell_type, shell_extras=True,
    )


def _resolve_path_str(raw: str, workspace: Path | None) -> Path | None:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return None
    try:
        p = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not p.is_absolute():
            if workspace is None:
                return None
            p = (workspace / p).resolve()
        else:
            p = p.resolve()
        return p
    except (OSError, RuntimeError):
        return None


def _specs_for_tool(tool_name: str) -> list[FileToolSpec] | None:
    return lookup_file_tool_specs(tool_name)


def shell_type_for_file_access(tool_name: str, tool_args: Mapping[str, Any]) -> str:
    if tool_name in {"powershell", "core.powershell"}:
        return "powershell"
    return str(tool_args.get("shell_type") or "auto").strip().lower()


def _outbound_or_skip(value: str, base: Path | None) -> Path | None:
    if base is None and not Path(value).is_absolute():
        return None
    return resolve_outbound_path(value, base)


def extract_accesses_native(
    tool_name: str,
    tool_args: Mapping[str, Any],
    workspace: Path | None,
    permission_config: Mapping[str, Any] | None = None,
    *,
    agent_cwd: Path | None = None,
) -> list[tuple[Path, FileAction, str]]:
    """Native 抽取：``(path, action, source)``；source 为 ``tool_arg`` / ``shlex``。

    ``workspace is None`` keeps absolute paths and drops relative ones. It does
    not fall back to the process working directory. Glob search roots and
    outbound file tools use ``agent_cwd`` (the old process cwd) when the
    caller passes it, and the workspace otherwise.
    """
    out: list[tuple[Path, FileAction, str]] = []
    outbound_base = agent_cwd if agent_cwd is not None else workspace

    if tool_name == "send_file_to_user":
        resolved = []
        for raw in normalize_file_path_list(tool_args.get("abs_file_path_list")):
            path = _outbound_or_skip(raw, outbound_base)
            if path is not None:
                resolved.append((path, "read", "tool_arg"))
        return resolved
    if tool_name in {"save_media_to_gallery", "save_file_to_file_manager"}:
        raw = tool_args.get("url")
        if isinstance(raw, str) and raw.strip() and not is_public_file_url(raw):
            path = _outbound_or_skip(raw, outbound_base)
            return [(path, "read", "tool_arg")] if path is not None else []
        return []

    from .tool_categories import (
        is_shell_tool,
        shell_tools_from_config,
    )

    if is_shell_tool(tool_name, shell_tools_from_config(permission_config)):
        raw_wd = tool_args.get("workdir")
        workdir_resolved: Path | None
        absolute_wd = (
            isinstance(raw_wd, str)
            and bool(raw_wd.strip())
            and Path(raw_wd).is_absolute()
        )
        if absolute_wd and isinstance(raw_wd, str):
            try:
                workdir_resolved = Path(raw_wd).resolve()
            except (OSError, RuntimeError):
                workdir_resolved = workspace
        elif workspace is None:
            workdir_resolved = None
        else:
            try:
                workdir_resolved = (
                    (workspace / str(raw_wd)).resolve() if raw_wd else workspace
                )
            except (OSError, RuntimeError):
                workdir_resolved = workspace
        cmd = str(tool_args.get("command", "") or tool_args.get("cmd", ""))
        for p, act in extract_shell_path_accesses(
            cmd, workdir_resolved, shell_type=shell_type_for_file_access(tool_name, tool_args),
        ):
            out.append((p, act, "shlex"))
        return out

    specs = _specs_for_tool(tool_name)
    if specs:
        for spec in specs:
            raw = tool_args.get(spec.arg_name)
            if tool_name == "glob" and spec.arg_name == "path":
                # GlobTool resolves omitted and relative paths against the agent
                # cwd, not the workspace. Callers pass that cwd as runtime.cwd.
                search_root = agent_cwd if agent_cwd is not None else workspace
                if search_root is None:
                    continue
                raw = raw or "."
                if isinstance(raw, str):
                    try:
                        root = search_root.expanduser().resolve()
                        out.append(((root / Path(raw).expanduser()).resolve(), spec.action, "tool_arg"))
                    except (OSError, RuntimeError):
                        pass
                continue
            if not isinstance(raw, str) or not raw.strip():
                continue
            rp = _resolve_path_str(raw, workspace)
            if rp is None:
                continue
            out.append((rp, spec.action, "tool_arg"))
        return out

    if tool_name in _PATH_TOOLS:
        action: FileAction = "write" if tool_name in _WRITE_PATH_TOOLS else "read"
        for s in _iter_path_strings(tool_name, tool_args):
            rp = _resolve_path_str(s, workspace)
            if rp is None:
                continue
            out.append((rp, action, "tool_arg"))
    return out
