# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Non-blocking warnings for destructive shell commands.

The rule tables are migrated from the Bash and PowerShell tool ``_security``
modules in agent-core. Patterns, flags, messages and ordering are unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
import re

from ..models import PermissionResult
from ..routing import CommandDialect, RouteContext, RouteInterest, SecurityTarget


_BASH_RULES = (
    (
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "May discard uncommitted changes",
    ),
    (
        re.compile(r"\bgit\s+push\b[^\n]*(?:--force|-f)\b"),
        "May overwrite remote history",
    ),
    (
        re.compile(r"\bgit\s+clean\s+-[a-zA-Z]*f"),
        "May permanently delete untracked files",
    ),
    (
        re.compile(r"\bgit\s+checkout\s+--\s+\."),
        "May discard all unstaged changes",
    ),
    (
        re.compile(r"\bgit\s+stash\s+(?:drop|clear)\b"),
        "May permanently discard stashed changes",
    ),
    (
        re.compile(r"\bgit\s+branch\s+-D\b"),
        "May force-delete a branch",
    ),
    (
        re.compile(r"\bgit\s+commit\s+--amend\b"),
        "May rewrite the last commit",
    ),
    (
        re.compile(r"\bgit\s+(?:push|commit|merge)\b[^\n]*--no-verify\b"),
        "May skip safety hooks",
    ),
    (
        re.compile(r"\bDROP\s+(?:TABLE|DATABASE)\b", re.IGNORECASE),
        "May drop database objects",
    ),
    (
        re.compile(r"\bTRUNCATE\s+TABLE\b", re.IGNORECASE),
        "May truncate database table",
    ),
    (
        re.compile(r"\bkubectl\s+delete\b"),
        "May delete Kubernetes resources",
    ),
    (
        re.compile(r"\bterraform\s+destroy\b"),
        "May destroy Terraform infrastructure",
    ),
    (
        re.compile(r"\bsudo\b"),
        "sudo may require a password in non-interactive mode; configure NOPASSWD or run as root",
    ),
)

_POWERSHELL_RULES = (
    (
        re.compile(r"(?i)\bremove-item\b[^\n]*-(?:recurse|force)\b"),
        "May permanently remove files or directories",
    ),
    (
        re.compile(r"(?i)\bclear-content\b"),
        "May remove file contents",
    ),
    (
        re.compile(r"(?i)\bset-content\b"),
        "May overwrite file contents",
    ),
    (
        re.compile(r"(?i)\brename-item\b"),
        "May rename or replace files",
    ),
    (
        re.compile(r"(?i)\bmove-item\b"),
        "May move or overwrite files",
    ),
    (
        re.compile(r"\bgit\s+reset\s+--hard\b"),
        "May discard uncommitted changes",
    ),
    (
        re.compile(r"\bgit\s+push\b[^\n]*(?:--force|-f)\b"),
        "May overwrite remote history",
    ),
    (
        re.compile(r"\bgit\s+commit\s+--amend\b"),
        "May rewrite the last commit",
    ),
)


class DestructiveWarningComponent:
    """Attach a warning to matching shell calls without deciding permission."""

    interests: tuple[RouteInterest, ...] | None = (
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL),
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POWERSHELL),
    )

    def configure(self, config: Mapping[str, object]) -> None:
        """Patterns are code-owned; there are no configuration fields."""
        del config

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        """Return the first matching warning for a supported shell dialect."""
        del tool_name  # The engine's resolved route is authoritative.
        if route is None or route.target is not SecurityTarget.COMMAND:
            return None

        if route.command_dialect is CommandDialect.POSIX_SHELL:
            rules = _BASH_RULES
        elif route.command_dialect is CommandDialect.POWERSHELL:
            rules = _POWERSHELL_RULES
        else:
            return None

        command = tool_args.get("command")
        if not isinstance(command, str):
            return None

        for pattern, warning in rules:
            if pattern.search(command):
                return PermissionResult(warnings=[warning])
        return PermissionResult()


__all__ = ["DestructiveWarningComponent"]
