"""Command-injection detection for POSIX shell and PowerShell tools.

The patterns, labels and first-hit semantics are carried over unchanged from the
original ``check_injection`` of the bash and PowerShell tools (identical on every
branch); only the call shape is adapted to the permission component protocol.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import ClassVar

from ..models import PermissionLevel, PermissionResult
from ..routing import CommandDialect, RouteContext, RouteInterest, SecurityTarget

Rule = tuple[re.Pattern[str], str]

_BACKTICK_RE = re.compile(r"(?<!')`[^`]+`")
_DOLLAR_PAREN_RE = re.compile(r"\$\(")
_PROC_SUBST_RE = re.compile(r"[<>]\(")

_POSIX_RULES: tuple[Rule, ...] = (
    (_BACKTICK_RE, "backtick command substitution"),
    (_DOLLAR_PAREN_RE, "$() command substitution"),
    (_PROC_SUBST_RE, "process substitution <() or >()"),
)
_POWERSHELL_RULES: tuple[Rule, ...] = (
    (re.compile(r"(?i)\b(?:invoke-expression|iex)\b"), "Invoke-Expression"),
    (
        re.compile(r"(?i)\b(?:powershell|powershell\.exe|pwsh|pwsh\.exe)\b[^\n]*-encodedcommand\b"),
        "nested encoded command",
    ),
    (re.compile(r"(^|[\s;(])&\s*(?:\(|\$)"), "dynamic call operator"),
    (re.compile(r"(?i)\[scriptblock\]::create\s*\("), "dynamic ScriptBlock creation"),
)


class InjectionComponent:
    """Block shell syntax that hides a command from static inspection."""

    interests: ClassVar[tuple[RouteInterest, ...]] = (
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL),
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POWERSHELL),
    )

    def configure(self, config: Mapping[str, object]) -> None:
        """Accept the complete engine config; the patterns are code-defined."""
        del config

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult:
        """Evaluate the command with the pattern table selected by ``route``."""
        del tool_name
        if route is None or route.target is not SecurityTarget.COMMAND:
            return PermissionResult(permission=PermissionLevel.ALLOW)
        raw = tool_args.get("command")
        command = raw if isinstance(raw, str) else ""
        if route.command_dialect is CommandDialect.POSIX_SHELL:
            rules, kind = _POSIX_RULES, "Shell"
        elif route.command_dialect is CommandDialect.POWERSHELL:
            rules, kind = _POWERSHELL_RULES, "PowerShell"
        else:
            return PermissionResult(permission=PermissionLevel.ALLOW)
        for pattern, label in rules:
            if pattern.search(command):
                return PermissionResult(
                    permission=PermissionLevel.DENY,
                    matched_rule=label,
                    reason=f"{kind} injection detected: {label}",
                )
        return PermissionResult(permission=PermissionLevel.ALLOW)


__all__ = ["InjectionComponent"]
