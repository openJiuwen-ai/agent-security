"""Shared routing contracts for permission components.

The router describes facts about one tool call.  It deliberately does not
know concrete security components; components declare the facts they care
about and the engine matches them.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import StrEnum
import os
from typing import Any, cast


class SecurityTarget(StrEnum):
    """Primary security object exposed by a tool call."""

    COMMAND = "command"
    FILE = "file"
    NETWORK = "network"
    OTHER = "other"


class CommandDialect(StrEnum):
    """Command language used by a command tool, when known."""

    POSIX_SHELL = "posix_shell"
    POWERSHELL = "powershell"
    CMD = "cmd"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class RouteContext:
    """Routing facts shared with matching permission components."""

    target: SecurityTarget
    command_dialect: CommandDialect | None = None


@dataclass(frozen=True, slots=True)
class RouteInterest:
    """A component's routing subscription.

    ``command_dialect=None`` means any dialect for the given target.
    """

    target: SecurityTarget
    command_dialect: CommandDialect | None = None

    def matches(self, route: RouteContext) -> bool:
        return (
            self.target is route.target
            and (
                self.command_dialect is None
                or self.command_dialect is route.command_dialect
            )
        )


_POSIX_TOOLS = frozenset({"bash", "sh", "zsh", "ksh", "dash", "ash", "fish"})
_POWERSHELL_TOOLS = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_CMD_TOOLS = frozenset({"cmd", "cmd.exe"})
_COMMAND_TOOLS = _POSIX_TOOLS | _POWERSHELL_TOOLS | _CMD_TOOLS | frozenset(
    {"core.powershell", "mcp_exec_command", "create_terminal"}
)
_FILE_TOOLS = frozenset(
    {
        "read_file", "write_file", "edit_file", "read_text_file", "write_text_file",
        "write", "read", "glob_file_search", "glob", "list_dir", "list_files",
        "grep", "search_replace",
    }
)
_NETWORK_TOOLS = frozenset({"fetch", "mcp_fetch_webpage", "mcp_free_search", "mcp_paid_search"})


def _tool_basename(value: object) -> str:
    if not isinstance(value, str):
        return ""
    return os.path.basename(value.strip().replace("\\", "/")).lower()


def _dialect_from_args(tool_args: Mapping[str, Any]) -> CommandDialect | None:
    """Read an optional explicit dialect without requiring it from callers."""

    for key in ("shell", "executable", "interpreter"):
        value = _tool_basename(tool_args.get(key))
        if value in _POSIX_TOOLS:
            return CommandDialect.POSIX_SHELL
        if value in _POWERSHELL_TOOLS or value == "core.powershell":
            return CommandDialect.POWERSHELL
        if value in _CMD_TOOLS:
            return CommandDialect.CMD
    return None


def resolve_route(tool_name: str, tool_args: Mapping[str, Any]) -> RouteContext:
    """Resolve shared routing facts for one tool call.

    Named command tools get a known dialect where the name is sufficient.
    Generic command tools remain ``UNKNOWN`` unless the call explicitly
    supplies ``shell``, ``executable`` or ``interpreter``.
    """

    name = _tool_basename(tool_name)
    if name in _POSIX_TOOLS:
        return RouteContext(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL)
    if name in _POWERSHELL_TOOLS or name == "core.powershell":
        return RouteContext(SecurityTarget.COMMAND, CommandDialect.POWERSHELL)
    if name in _CMD_TOOLS:
        return RouteContext(SecurityTarget.COMMAND, CommandDialect.CMD)
    if name in _COMMAND_TOOLS:
        return RouteContext(SecurityTarget.COMMAND, _dialect_from_args(tool_args) or CommandDialect.UNKNOWN)
    if name in _FILE_TOOLS:
        return RouteContext(SecurityTarget.FILE)
    if name in _NETWORK_TOOLS:
        return RouteContext(SecurityTarget.NETWORK)
    return RouteContext(SecurityTarget.OTHER)


def route_matches(route: RouteContext, interests: object) -> bool:
    """Return whether a component subscription matches a route."""

    if interests is None:
        return True
    if isinstance(interests, RouteInterest):
        interests = (interests,)
    try:
        interests_iter = cast(Iterable[object], interests)
        return any(
            isinstance(interest, RouteInterest) and interest.matches(route)
            for interest in interests_iter
        )
    except TypeError:
        return False


__all__ = [
    "CommandDialect",
    "RouteContext",
    "RouteInterest",
    "SecurityTarget",
    "resolve_route",
    "route_matches",
]
