# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Segment-level peer analyzer for Windows FS forms outside plain cmd0 lists.

Dispatch: identify form → argument style → signature-aware path binding.

Argument styles:

- ``call_args``: ``Type::Method(a, b, …)`` with balanced parentheses
- ``ctor_member``: ``[FileInfo]::new("path").Delete()``
- ``switch_value``: ``cipher /w:path``, ``fsutil … path``
- ``positional``: ``rimraf`` / ``deltree`` operands (also on cmd0; kept for npx)
- ``opaque``: destruction with no bindable literal path → fail-closed

cmd0 whitelist extraction stays in ``path_extract``; ``robocopy_flag_effects``
is a small helper for that path only.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from pathlib import Path

from .command_sets import WIPE_CMDS as _WIPE_CMDS

FileAction = str  # "read" | "write"

_RECYCLE_CMDS = frozenset({
    "clear-recyclebin",
    "sendtorecyclebin",
})

# method → ordered (arg_index, action); only those slots are paths.
_DOTNET_IO_SIGNATURES: dict[str, tuple[tuple[int, FileAction], ...]] = {
    "delete": ((0, "write"),),
    "writealltext": ((0, "write"),),
    "writeallbytes": ((0, "write"),),
    "writealllines": ((0, "write"),),
    "appendalltext": ((0, "write"),),
    "appendalllines": ((0, "write"),),
    "copy": ((0, "read"), (1, "write")),
    "move": ((0, "write"), (1, "write")),
    "replace": ((0, "read"), (1, "write")),
}

_VB_SIGNATURES: dict[str, tuple[tuple[int, FileAction], ...]] = {
    "deletefile": ((0, "write"),),
    "deletedirectory": ((0, "write"),),
    "writealltext": ((0, "write"),),
    "copyfile": ((0, "read"), (1, "write")),
    "movefile": ((0, "write"), (1, "write")),
    "movedirectory": ((0, "write"), (1, "write")),
}

_DOTNET_IO_HEAD_RE = re.compile(
    r"""(?ix)
    \[\s*(?:System\.)?IO\.(?:File|Directory)\s*\]\s*::\s*
    (?P<method>Delete|Copy|Move|Replace|WriteAll(?:Text|Bytes|Lines)|AppendAll(?:Text|Lines))
    \s*\(
    """
)

_VB_HEAD_RE = re.compile(
    r"""(?ix)
    \[\s*(?:Microsoft\.)?VisualBasic\.FileIO\.FileSystem\s*\]\s*::\s*
    (?P<method>DeleteFile|DeleteDirectory|MoveFile|MoveDirectory|CopyFile|WriteAllText)
    \s*\(
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

# Declarations often live inside Add-Type / attribute string bodies — scan raw text.
_PINVOKE_DECL_RE = re.compile(
    r"""(?ix)
    (?:
        \bAdd-Type\b[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
      | \bDllImport\b[^\n;]*\b(?:kernel32|shell32)\b[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
      | \[\s*DllImport\s*\([^\)]*(?:kernel32|shell32)[^\)]*\)[^\n;]*\b(?:DeleteFile|SHFileOperation|RemoveDirectory)\b
    )
    """
)

# Bare wipe calls: scan quote-masked text so echoed API names do not fail-closed.
_PINVOKE_CALL_RE = re.compile(
    r"""(?ix)
    (?:
        \bSHFileOperation\s*\(
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

_ROBOCOPY_SOURCE_DELETE_FLAGS = frozenset({"/move", "/mov"})
_ROBOCOPY_DEST_PURGE_FLAGS = frozenset({"/mir", "/purge"})

_DRIVE_ROOT_RE = re.compile(r"^[A-Za-z]:\\?$")
_OPAQUE_VALUE_RE = re.compile(r"""(?x) \$ | ` | \( | \) """)


def _raise_opaque(message: str) -> None:
    from .path_extract import ShellPathUnresolvedShellError

    raise ShellPathUnresolvedShellError(message)


def _mask_quoted_spans(text: str) -> str:
    """Replace quoted string bodies so opaque scans ignore string literals."""
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in {"'", '"'}:
            quote = ch
            out.append(" ")
            i += 1
            while i < len(text):
                if text[i] == "`" and i + 1 < len(text):
                    out.append("  ")
                    i += 2
                    continue
                if text[i] == quote:
                    out.append(" ")
                    i += 1
                    break
                out.append(" ")
                i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def _balanced_paren_args(text: str, open_paren_index: int) -> str | None:
    """Return inside of ``(…)`` starting at ``open_paren_index``, or None if unbalanced."""
    if open_paren_index < 0 or open_paren_index >= len(text) or text[open_paren_index] != "(":
        return None
    depth = 0
    quote = ""
    i = open_paren_index
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "`" and i + 1 < len(text):
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            i += 1
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren_index + 1:i]
        i += 1
    return None


def _split_call_args(arg_blob: str) -> list[str]:
    """Split a call-arg list on top-level commas (quote / paren aware)."""
    args: list[str] = []
    buf: list[str] = []
    depth = 0
    quote = ""
    i = 0
    while i < len(arg_blob):
        ch = arg_blob[i]
        if quote:
            buf.append(ch)
            if ch == "`" and i + 1 < len(arg_blob):
                buf.append(arg_blob[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in {"'", '"'}:
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "(":
            depth += 1
            buf.append(ch)
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
            i += 1
            continue
        if ch == "," and depth == 0:
            args.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        args.append(tail)
    return args


def _unwrap_one_paren_group(value: str) -> str:
    text = value.strip()
    while text.startswith("(") and text.endswith(")"):
        inner = _balanced_paren_args(text, 0)
        if inner is None or f"({inner})" != text:
            break
        text = inner.strip()
    return text


def _literal_path_text(value: str) -> str | None:
    """Return a bindable path literal, or None if the value is opaque / non-path."""
    text = _unwrap_one_paren_group(value)
    if not text:
        return None
    if (text[0] in {"'", '"'}) and text[-1] == text[0] and len(text) >= 2:
        body = text[1:-1].replace("\\'", "'").replace('\\"', '"')
        if _OPAQUE_VALUE_RE.search(body):
            return None
        return body
    if text.lower() in {"true", "false"} or re.fullmatch(r"-?\d+", text):
        return None
    if text.startswith("$") or _OPAQUE_VALUE_RE.search(text):
        return None
    return text


def _resolve_literal_path(raw: str, workdir: Path | None) -> Path | None:
    from .path_extract import is_windows_abs_text, resolve_extract_path

    text = raw.strip().strip('"').strip("'")
    if not text:
        return None
    if _DRIVE_ROOT_RE.match(text):
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


def _append_access(
    accesses: list[tuple[Path, FileAction]],
    raw: str,
    cwd: Path | None,
    action: FileAction,
    *,
    opaque_message: str,
) -> None:
    literal = _literal_path_text(raw)
    if literal is None:
        _raise_opaque(opaque_message)
    path = _resolve_literal_path(literal, cwd)
    if path is None:
        _raise_opaque(opaque_message)
    accesses.append((path, action))


def _cmd0(segment: str) -> str:
    from .path_extract import _basename_lower

    token = segment.strip().split(None, 1)[0] if segment.strip() else ""
    return _basename_lower(token.strip('"').strip("'"))


def _apply_signature(
    args: list[str],
    signature: tuple[tuple[int, FileAction], ...],
    cwd: Path | None,
    accesses: list[tuple[Path, FileAction]],
    *,
    opaque_message: str,
) -> None:
    if not signature:
        return
    needed = max(index for index, _action in signature) + 1
    if len(args) < needed:
        _raise_opaque(opaque_message)
    for index, action in signature:
        _append_access(accesses, args[index], cwd, action, opaque_message=opaque_message)


def _extract_call_args_form(
    text: str,
    cwd: Path | None,
    accesses: list[tuple[Path, FileAction]],
    *,
    head_re: re.Pattern[str],
    signatures: dict[str, tuple[tuple[int, FileAction], ...]],
    opaque_message: str,
) -> None:
    for match in head_re.finditer(text):
        method = match.group("method").lower()
        signature = signatures.get(method)
        if signature is None:
            continue
        open_at = match.end() - 1
        blob = _balanced_paren_args(text, open_at)
        if blob is None:
            _raise_opaque(opaque_message)
        args = _split_call_args(blob)
        # Presence of the call with zero bindable path slots still needs a path.
        if not args and signature:
            _raise_opaque(opaque_message)
        _apply_signature(args, signature, cwd, accesses, opaque_message=opaque_message)


def _extract_ctor_member(text: str, cwd: Path | None, accesses: list[tuple[Path, FileAction]]) -> None:
    for match in _DOTNET_INFO_DELETE_RE.finditer(text):
        _append_access(
            accesses,
            match.group("path"),
            cwd,
            "write",
            opaque_message="Windows .NET FileInfo/DirectoryInfo Delete path is opaque",
        )


def _extract_switch_tools(text: str, cwd: Path | None, accesses: list[tuple[Path, FileAction]]) -> None:
    for match in _CIPHER_WIPE_RE.finditer(text):
        raw = match.group("path")
        literal = _literal_path_text(raw) or raw.strip().strip('"').strip("'")
        if literal is None or _DRIVE_ROOT_RE.match(literal):
            _raise_opaque("cipher /w target is opaque to path analysis")
        _append_access(
            accesses, raw, cwd, "write",
            opaque_message="cipher /w target is opaque to path analysis",
        )
    for match in _FSUTIL_ZERO_RE.finditer(text):
        _append_access(
            accesses,
            match.group("path"),
            cwd,
            "write",
            opaque_message="fsutil setZeroData path is opaque to path analysis",
        )


def _extract_positional_wipers(text: str, cwd: Path | None, accesses: list[tuple[Path, FileAction]]) -> None:
    name = _cmd0(text)
    body = text.strip()
    if name in {"npx", "npm"} and re.search(r"(?i)\brimraf\b", text):
        body = re.sub(r"(?i)^\s*(?:npx|npm(?:\s+exec)?)\s+", "", body)
        body = re.sub(r"(?i)^\s*rimraf\b", "", body)
    elif name in _WIPE_CMDS:
        body = re.sub(rf"(?i)^\s*{re.escape(name)}(?:\.exe)?\b", "", body)
    else:
        return
    for match in re.finditer(r"""(['"])(?:\\.|(?!\1).)*\1|[^\s]+""", body):
        raw = match.group(0)
        if raw.startswith("-"):
            continue
        _append_access(
            accesses, raw, cwd, "write",
            opaque_message="Windows wipe command path is opaque to path analysis",
        )


def _check_opaque_forms(text: str) -> None:
    if _cmd0(text) in _RECYCLE_CMDS:
        _raise_opaque("Windows recycle-bin destruction is opaque to path analysis")

    # Raw text: Delete("$path") / Delete() / $f.Delete() — quote masking would
    # collapse Delete("C:\x") into Delete(   ) and false-positive as empty args.
    if _OPAQUE_INSTANCE_DELETE_RE.search(text):
        _raise_opaque("Windows .NET Delete without a literal path is opaque to path analysis")
    # Raw text: Add-Type / DllImport bodies are string literals by design.
    if _PINVOKE_DECL_RE.search(text):
        _raise_opaque("Win32/PInvoke filesystem wipe helpers are opaque to path analysis")

    masked = _mask_quoted_spans(text)
    if _COM_INVOKE_VERB_RE.search(masked):
        _raise_opaque("COM InvokeVerb delete/remove is opaque to path analysis")
    if _COM_SHELL_APPLICATION_RE.search(masked) and re.search(
        r"(?i)\b(?:Namespace|ParseName|InvokeVerb)\b", masked,
    ):
        _raise_opaque("COM Shell.Application filesystem destruction is opaque to path analysis")
    if _PINVOKE_CALL_RE.search(masked):
        _raise_opaque("Win32/PInvoke filesystem wipe helpers are opaque to path analysis")


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


_FORM_EXTRACTORS: tuple[
    Callable[[str, Path | None, list[tuple[Path, FileAction]]], None],
    ...,
] = (
    # call_args
    lambda text, cwd, acc: _extract_call_args_form(
        text, cwd, acc,
        head_re=_DOTNET_IO_HEAD_RE,
        signatures=_DOTNET_IO_SIGNATURES,
        opaque_message="Windows .NET filesystem call path is opaque to path analysis",
    ),
    lambda text, cwd, acc: _extract_call_args_form(
        text, cwd, acc,
        head_re=_VB_HEAD_RE,
        signatures=_VB_SIGNATURES,
        opaque_message="VisualBasic.FileSystem call path is opaque to path analysis",
    ),
    # ctor_member
    _extract_ctor_member,
    # switch_value
    _extract_switch_tools,
    # positional wipers (npx rimraf / rimraf / deltree)
    _extract_positional_wipers,
)


def analyze_windows_destructive_accesses(
    segment: str,
    workdir: str | Path | None,
) -> list[tuple[Path, str]]:
    """Segment-level peer to cmd0 whitelist analysis for non-cmd0 destroy forms.

    Raises ``ShellPathUnresolvedShellError`` when destruction is detected but no
    literal path can be bound.
    """
    text = (segment or "").strip()
    if not text:
        return []

    try:
        cwd = Path(workdir) if workdir is not None else None
    except (TypeError, ValueError):
        cwd = None

    _check_opaque_forms(text)

    accesses: list[tuple[Path, FileAction]] = []
    for extract in _FORM_EXTRACTORS:
        extract(text, cwd, accesses)
    return list(dict.fromkeys(accesses))


__all__ = [
    "analyze_windows_destructive_accesses",
    "robocopy_flag_effects",
]
