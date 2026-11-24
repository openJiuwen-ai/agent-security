# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Detect PowerShell syntax routed to the bash tool."""

from __future__ import annotations

import re
import shlex

_PS_CMDLET_NAMES = frozenset({
    "get-childitem",
    "set-location",
    "remove-item",
    "move-item",
    "copy-item",
    "rename-item",
    "new-item",
    "get-item",
    "set-content",
    "add-content",
    "test-path",
    "join-path",
    "select-object",
    "where-object",
    "foreach-object",
    "invoke-webrequest",
    "invoke-restmethod",
    "out-file",
    "start-process",
})
_PS_SHELL_PREFIXES = frozenset({"powershell", "pwsh"})
_PS_VARIABLE_RE = re.compile(r"\$(?:env:|null\b|true\b|false\b|psversiontable\b)")


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
    raw = _strip_matching_quotes(tokens[0])
    base = raw.rsplit("/", maxsplit=1)[-1].rsplit("\\", maxsplit=1)[-1].lower()
    return base.removesuffix(".exe")


def is_powershell_command(command: str) -> bool:
    """Strict PowerShell detection for hard-block decisions."""
    text = (command or "").strip()
    if not text:
        return False
    if "@'" in text or '@"' in text:
        return True
    if _PS_VARIABLE_RE.search(text):
        return True
    for segment in _split_shell_segments(text):
        base = _segment_base_command(segment)
        if base in _PS_SHELL_PREFIXES or base in _PS_CMDLET_NAMES:
            return True
    return False


def shell_mismatch(tool_name: str, command: str) -> str | None:
    """Reject commands whose syntax belongs to a different shell tool."""
    if tool_name != "bash":
        return None
    if is_powershell_command(command):
        return (
            "PowerShell syntax was sent to the bash tool; retry with the "
            'powershell tool (or mcp_exec_command with shell_type="powershell").'
        )
    return None


__all__ = ["is_powershell_command", "shell_mismatch"]
