# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Segment-level peer analyzer for Windows destructive FS forms cmd0 lists miss.

Registered beside path-aware cmd0 extraction (one call per shell segment).
These are not ordinary ``cmd0 + path operands`` shapes:

- COM / recycle-bin verbs and cmdlets
- .NET ``System.IO`` delete/move/copy/write APIs
- P/Invoke / ``SHFileOperation`` wipe helpers
- ``cipher /w`` and ``fsutil file setZeroData``
- ``rimraf`` / ``deltree`` style wipers
- ``robocopy`` destructive switches (flag helper used by path extract)

When a literal path can be recovered, return write accesses. Opaque destruction
raises :class:`ShellPathUnresolvedShellError` so an enabled FileGuard fail-closes
instead of abstaining on an empty path list.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .command_sets import WIPE_CMDS as _WIPE_CMDS

_RECYCLE_CMDS = frozenset({
    "clear-recyclebin",
    "sendtorecyclebin",
})

_COM_INVOKE_VERB_RE = re.compile(
    r"""(?ix)\.InvokeVerb\s*\(\s*(['"])\s*(delete|remove)\s*\1\s*\)"""
)

_COM_SHELL_APPLICATION_RE = re.compile(
    r"""(?ix)
    New-Object\b[^\n;|&]*\bShell\.Application\b
    |
    -ComObject\s+(['"])Shell\.Application\1
    """
)

# Methods that destroy/overwrite the first path argument.
_DOTNET_WRITE_METHODS = (
    "Delete",
    "WriteAll(?:Text|Bytes|Lines)",
    "AppendAll(?:Text|Lines)",
)
# Methods with source[, ...] destination — last quoted path is the write target.
_DOTNET_TRANSFER_METHODS = (
    "Copy",
    "Move",
    "Replace",
)

_DOTNET_IO_CALL_RE = re.compile(
    r"""(?ix)
    \[\s*(?:System\.)?IO\.(?:File|Directory)\s*\]\s*::\s*
    (?P<method>Delete|Copy|Move|Replace|WriteAll(?:Text|Bytes|Lines)|AppendAll(?:Text|Lines))
    \s*\((?P<args>[^)]*)\)
    """
)

_VB_FILESYSTEM_RE = re.compile(
    r"""(?ix)
    (?:Microsoft\.)?VisualBasic\.FileIO\.FileSystem\s*::\s*
    (?P<method>DeleteFile|DeleteDirectory|MoveFile|MoveDirectory|CopyFile|WriteAllText)
    \s*\((?P<args>[^)]*)\)
    """
)

_DOTNET_INFO_DELETE_RE = re.compile(
    r"""(?ix)
    \[\s*(?:System\.)?IO\.(?:FileInfo|DirectoryInfo)\s*\]\s*::\s*new\s*\(\s*
    (['"])(?P<path>(?:\\.|(?!\1).)*)\1\s*\)\s*\.\s*Delete\s*\(
    """
)

_OPAQUE_INSTANCE_DELETE_RE = re.compile(
    r"""(?ix)
    (?:
        \$\w+\s*\.\s*Delete\s*\(
      | \[\s*(?:System\.)?IO\.(?:File|Directory)\s*\]\s*::\s*Delete\s*\(\s*\$
      | \[\s*(?:System\.)?IO\.(?:File|Directory)\s*\]\s*::\s*Delete\s*\(\s*\)
    )
    """
)

# Add-Type / DllImport of Win32 delete or shell-file wipe APIs without a bound path.
_PINVOKE_WIPE_RE = re.compile(
    r"""(?ix)
    (?:
        \bAdd-Type\b[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
      | \bDllImport\b[^\n;]*\b(?:kernel32|shell32)\b[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
      | \[\s*DllImport\s*\([^\)]*(?:kernel32|shell32)[^\)]*\)[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
      | \bSHFileOperation\s*\(
      | \bDeleteFile\s*\(\s*(?:\$|(['"])[^'"]*\1)
    )
    """
)

_CIPHER_WIPE_RE = re.compile(
    r"""(?ix)
    (?:^|[\s;&|()])cipher(?:\.exe)?\b[^;\n|&]*/w\s*:?\s*
    (?P<path>"[^"]+"|'[^']+'|[^\s;&|]+)
    """
)

_FSUTIL_ZERO_RE = re.compile(
    r"""(?ix)
    (?:^|[\s;&|()])fsutil(?:\.exe)?\b\s+file\b\s+setzerodata\b[^;\n|&]*?
    (?:offset\s*=\s*\S+\s+)?(?:length\s*=\s*\S+\s+)?
    (?P<path>"[^"]+"|'[^']+'|[^\s;&|=]+)
    """
)

_QUOTED_OR_BARE_PATH_RE = re.compile(
    r"""(?x)
    (['"])(?P<quoted>(?:\\.|(?!\1).)*)\1
    |
    (?P<bare>[^\s,'"]+)
    """
)

_ROBOCOPY_SOURCE_DELETE_FLAGS = frozenset({"/move", "/mov"})
_ROBOCOPY_DEST_PURGE_FLAGS = frozenset({"/mir", "/purge"})

_VB_TRANSFER = frozenset({"movefile", "movedirectory", "copyfile"})


def _resolve_literal_path(raw: str, workdir: Path | None) -> Path | None:
    from .path_extract import is_windows_abs_text, resolve_extract_path

    text = raw.strip().strip('"').strip("'")
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute() and not is_windows_abs_text(text):
        if workdir is None:
            return None
        path = workdir / path
    try:
        if os.name != "nt" and is_windows_abs_text(str(path)):
            return path
        return resolve_extract_path(path)
    except (OSError, RuntimeError):
        return None


def _cmd0(segment: str) -> str:
    from .path_extract import _basename_lower

    token = segment.strip().split(None, 1)[0] if segment.strip() else ""
    return _basename_lower(token.strip('"').strip("'"))


def _string_args(arg_blob: str) -> list[str]:
    out: list[str] = []
    for match in _QUOTED_OR_BARE_PATH_RE.finditer(arg_blob or ""):
        raw = match.group("quoted")
        if raw is not None:
            out.append(raw.replace("\\\"", '"').replace("\\'", "'"))
            continue
        bare = (match.group("bare") or "").strip()
        if not bare or bare.startswith("$") or bare.lower() in {"true", "false"}:
            continue
        if re.fullmatch(r"-?\d+", bare):
            continue
        out.append(bare)
    return out


def _append_write(accesses: list[tuple[Path, str]], raw: str, cwd: Path | None) -> None:
    from .path_extract import ShellPathUnresolvedShellError

    path = _resolve_literal_path(raw, cwd)
    if path is None:
        raise ShellPathUnresolvedShellError(
            "Windows destructive filesystem path could not be resolved"
        )
    accesses.append((path, "write"))


def robocopy_flag_effects(tokens: list[str]) -> tuple[bool, bool]:
    """Return ``(removes_source, purges_destination)`` for robocopy switches."""
    removes_source = False
    purges_destination = False
    for token in tokens[1:]:
        flag = token.strip().strip('"').strip("'").lower()
        if flag in _ROBOCOPY_SOURCE_DELETE_FLAGS:
            removes_source = True
        if flag in _ROBOCOPY_DEST_PURGE_FLAGS:
            purges_destination = True
    return removes_source, purges_destination


def _collect_dotnet_accesses(
    text: str, cwd: Path | None, accesses: list[tuple[Path, str]],
) -> None:
    for match in _DOTNET_IO_CALL_RE.finditer(text):
        method = match.group("method").lower()
        args = _string_args(match.group("args"))
        if not args:
            continue
        if method in {"copy", "move", "replace"}:
            if len(args) >= 2:
                if method == "move":
                    _append_write(accesses, args[0], cwd)
                _append_write(accesses, args[-1], cwd)
            else:
                _append_write(accesses, args[0], cwd)
        else:
            _append_write(accesses, args[0], cwd)

    for match in _VB_FILESYSTEM_RE.finditer(text):
        method = match.group("method").lower()
        args = _string_args(match.group("args"))
        if not args:
            continue
        if method in _VB_TRANSFER:
            if len(args) >= 2:
                if method.startswith("move"):
                    _append_write(accesses, args[0], cwd)
                _append_write(accesses, args[-1], cwd)
            else:
                _append_write(accesses, args[0], cwd)
        else:
            _append_write(accesses, args[0], cwd)

    for match in _DOTNET_INFO_DELETE_RE.finditer(text):
        _append_write(accesses, match.group("path"), cwd)


def _collect_tool_accesses(
    text: str, cwd: Path | None, accesses: list[tuple[Path, str]],
) -> None:
    for match in _CIPHER_WIPE_RE.finditer(text):
        _append_write(accesses, match.group("path"), cwd)
    for match in _FSUTIL_ZERO_RE.finditer(text):
        _append_write(accesses, match.group("path"), cwd)

    for piece in re.split(r"[;\n|&]+", text):
        name = _cmd0(piece)
        if name not in _WIPE_CMDS and not (
            name in {"npx", "npm"} and re.search(r"(?i)\brimraf\b", piece)
        ):
            continue
        # rimraf ./a , npx rimraf ./a , deltree C:\a
        body = piece.strip()
        if name in {"npx", "npm"}:
            body = re.sub(r"(?i)^\s*(?:npx|npm(?:\s+exec)?)\s+", "", body)
            body = re.sub(r"(?i)^\s*rimraf\b", "", body)
        else:
            body = re.sub(rf"(?i)^\s*{re.escape(name)}(?:\.exe)?\b", "", body)
        for raw in _string_args(body):
            if raw.startswith("-"):
                continue
            _append_write(accesses, raw, cwd)


def analyze_windows_destructive_accesses(
    segment: str,
    workdir: str | Path | None,
) -> list[tuple[Path, str]]:
    """Segment-level peer to cmd0 whitelist analysis for non-cmd0 destroy forms.

    Call once per shell segment (same level as path-aware cmd0 extraction).
    Raises ``ShellPathUnresolvedShellError`` when destruction is detected but no
    literal path can be bound (recycle-bin cmdlets, COM InvokeVerb, opaque
    ``.Delete()`` / P/Invoke wipe helpers). Opaque hits always fail-close, even
    if another literal path was recovered in the same segment.
    """
    from .path_extract import ShellPathUnresolvedShellError

    text = (segment or "").strip()
    if not text:
        return []

    try:
        cwd = Path(workdir) if workdir is not None else None
    except (TypeError, ValueError):
        cwd = None

    if _cmd0(text) in _RECYCLE_CMDS:
        raise ShellPathUnresolvedShellError(
            "Windows recycle-bin destruction is opaque to path analysis"
        )

    if _COM_INVOKE_VERB_RE.search(text):
        raise ShellPathUnresolvedShellError(
            "COM InvokeVerb delete/remove is opaque to path analysis"
        )

    if _COM_SHELL_APPLICATION_RE.search(text) and re.search(
        r"(?i)\b(?:Namespace|ParseName|InvokeVerb)\b", text,
    ):
        # Shell.Application delete flows are dynamic; fail closed without a path.
        raise ShellPathUnresolvedShellError(
            "COM Shell.Application filesystem destruction is opaque to path analysis"
        )

    if _PINVOKE_WIPE_RE.search(text):
        raise ShellPathUnresolvedShellError(
            "Win32/PInvoke filesystem wipe helpers are opaque to path analysis"
        )

    if _OPAQUE_INSTANCE_DELETE_RE.search(text):
        raise ShellPathUnresolvedShellError(
            "Windows .NET Delete without a literal path is opaque to path analysis"
        )

    accesses: list[tuple[Path, str]] = []
    _collect_dotnet_accesses(text, cwd, accesses)
    _collect_tool_accesses(text, cwd, accesses)
    return list(dict.fromkeys(accesses))


__all__ = [
    "analyze_windows_destructive_accesses",
    "robocopy_flag_effects",
]
