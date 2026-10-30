# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Candidate context shared with permission components.

The engine expands one tool call into candidates (original / unwrapped /
subcommands) and passes each candidate to every component.  Components decide
themselves whether they have an opinion; the engine does not filter by
security-object category.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class CandidateKind(StrEnum):
    """Which command view a candidate represents."""

    ORIGINAL = "original"
    UNWRAPPED = "unwrapped"
    SUBCOMMAND = "subcommand"


class CommandDialect(StrEnum):
    """Command language used by a shell tool, when known."""

    POSIX_SHELL = "posix_shell"
    POWERSHELL = "powershell"
    CMD = "cmd"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RouteContext:
    """Facts about one candidate shared with permission components."""

    kind: CandidateKind = CandidateKind.ORIGINAL
    command_dialect: CommandDialect | None = None
    is_shell: bool = False


# Dialect names: used to resolve CommandDialect from tool_name or args
# (shell / executable / interpreter). Not the peel-launcher table.
_POSIX_TOOLS = frozenset({"bash", "sh", "zsh", "ksh", "dash", "ash", "fish"})
_POWERSHELL_TOOLS = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_CMD_TOOLS = frozenset({"cmd", "cmd.exe"})

# Table A — command *entry* tool_name values that enter peel/expand.
# Product cards plus dialect-named cards that may appear as tool_name.
# Peel launchers (bash -c / cmd /c / …) live in command_canonicalize, not here.
_COMMAND_ENTRY_TOOLS = (
    _POSIX_TOOLS
    | _POWERSHELL_TOOLS
    | _CMD_TOOLS
    | frozenset({"core.powershell", "mcp_exec_command", "create_terminal"})
)
# Back-compat alias for older imports / tests.
_COMMAND_TOOLS = _COMMAND_ENTRY_TOOLS
_FILE_TOOLS = frozenset(
    {
        "read_file",
        "write_file",
        "edit_file",
        "read_text_file",
        "write_text_file",
        "write",
        "read",
        "glob_file_search",
        "glob",
        "list_dir",
        "list_files",
        "grep",
        "search_replace",
        "send_file_to_user",
        "save_media_to_gallery",
        "save_file_to_file_manager",
    }
)
_NETWORK_TOOLS = frozenset(
    {
        "fetch",
        "mcp_fetch_webpage",
        "fetch_webpage",
        "web_fetch_webpage",
        "mcp_free_search",
        "mcp_paid_search",
        "network_connect",
    }
)


def _tool_basename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return os.path.basename(value.strip().replace("\\", "/")).lower()


def _dialect_from_args(tool_args: Mapping[str, Any]) -> CommandDialect | None:
    for key in ("shell", "shell_type", "executable", "interpreter"):
        value = _tool_basename(tool_args.get(key))
        if value in _POSIX_TOOLS:
            return CommandDialect.POSIX_SHELL
        if value in _POWERSHELL_TOOLS or value == "core.powershell":
            return CommandDialect.POWERSHELL
        if value in _CMD_TOOLS:
            return CommandDialect.CMD
    return None


def is_shell_tool(tool_name: str) -> bool:
    """Return whether ``tool_name`` is a known command-entry tool (Table A)."""

    return _tool_basename(tool_name) in _COMMAND_ENTRY_TOOLS


def supports_posix_subcommand_split(dialect: CommandDialect | None) -> bool:
    """Phase-1 subcommand split uses the bash AST only.

    POSIX is in scope. UNKNOWN (e.g. mcp_exec_command without shell args) also
    uses the bash AST as a best-effort view. PowerShell / CMD wait for Phase 2.
    """

    return dialect in (CommandDialect.POSIX_SHELL, CommandDialect.UNKNOWN)


def resolve_dialect(tool_name: str, tool_args: Mapping[str, Any]) -> CommandDialect | None:
    """Resolve shell dialect for a tool call; ``None`` when not a command entry."""

    name = _tool_basename(tool_name)
    if name in _POSIX_TOOLS:
        return CommandDialect.POSIX_SHELL
    if name in _POWERSHELL_TOOLS or name == "core.powershell":
        return CommandDialect.POWERSHELL
    if name in _CMD_TOOLS:
        return CommandDialect.CMD
    if name in _COMMAND_ENTRY_TOOLS:
        return _dialect_from_args(tool_args) or CommandDialect.UNKNOWN
    return None


def resolve_route(tool_name: str, tool_args: Mapping[str, Any]) -> RouteContext:
    """Build an ORIGINAL candidate context for one tool call.

    Kept for components that fall back when the engine did not pass ``route``.
    """

    dialect = resolve_dialect(tool_name, tool_args)
    return RouteContext(
        kind=CandidateKind.ORIGINAL,
        command_dialect=dialect,
        is_shell=dialect is not None,
    )


def is_network_tool(tool_name: str) -> bool:
    return _tool_basename(tool_name) in _NETWORK_TOOLS


def is_file_tool(tool_name: str) -> bool:
    return _tool_basename(tool_name) in _FILE_TOOLS


# --- Compatibility aliases (deprecated; remove after callers migrate) ---


class SecurityTarget(StrEnum):
    """Deprecated: category routing has been removed."""

    ALL = "all"
    COMMAND = "command"
    FILE = "file"
    NETWORK = "network"
    OTHER = "other"


@dataclass(frozen=True, slots=True)
class RouteInterest:
    """Deprecated: components are no longer filtered by subscription."""

    target: SecurityTarget
    command_dialect: CommandDialect | None = None

    @staticmethod
    def matches(route: RouteContext) -> bool:
        del route
        return True


def route_matches(route: RouteContext, interests: object) -> bool:
    """Deprecated: always True (engine invokes every component)."""

    del route, interests
    return True


__all__ = [
    "CandidateKind",
    "CommandDialect",
    "RouteContext",
    "RouteInterest",
    "SecurityTarget",
    "is_file_tool",
    "is_network_tool",
    "is_shell_tool",
    "resolve_dialect",
    "resolve_route",
    "route_matches",
    "supports_posix_subcommand_split",
]
