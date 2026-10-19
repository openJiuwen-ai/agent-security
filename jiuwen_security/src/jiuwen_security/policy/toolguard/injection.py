"""R02 command-injection detection for POSIX shell and PowerShell tools."""

from __future__ import annotations

from collections.abc import Mapping
import re
from typing import ClassVar

from ..models import PermissionLevel, PermissionResult
from ..routing import CommandDialect, RouteContext, RouteInterest, SecurityTarget

Rule = tuple[str, re.Pattern[str], str]

_POSIX_RULES: tuple[Rule, ...] = (
    ("backtick-command-substitution", re.compile(r"(?<!')`[^`\n]+`"), "Shell backtick command substitution is not allowed"),
    ("dollar-command-substitution", re.compile(r"\$\([^\n()]+\)"), "Shell $() command substitution is not allowed"),
    ("process-substitution", re.compile(r"(?:<|>)\([^\n()]+\)"), "Shell process substitution is not allowed"),
)
_POWERSHELL_RULES: tuple[Rule, ...] = (
    ("invoke-expression", re.compile(r"(?i)(?<![\w-])(?:invoke-expression|iex)(?![\w-])"), "PowerShell dynamic expression evaluation is not allowed"),
    ("encoded-command", re.compile(r"(?i)(?<![\w-])(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\b"), "Nested encoded PowerShell commands are not allowed"),
    ("dynamic-call-operator", re.compile(r"&\s*(?:\(|\$)"), "PowerShell dynamic call operators are not allowed"),
    ("scriptblock-create", re.compile(r"(?i)\[scriptblock\]\s*::\s*create\s*\("), "Dynamic PowerShell script blocks are not allowed"),
)


class InjectionComponent:
    """Block shell syntax that hides a command from static inspection."""

    interests: ClassVar[tuple[RouteInterest, ...]] = (
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POSIX_SHELL),
        RouteInterest(SecurityTarget.COMMAND, CommandDialect.POWERSHELL),
    )

    def configure(self, config: Mapping[str, object]) -> None:
        """Accept the complete engine config; R02 rules are code-defined."""
        del config

    async def evaluate(self, tool_name: str, tool_args: Mapping[str, object], *, route: RouteContext | None = None) -> PermissionResult:
        """Evaluate the command using the detector selected by ``route``."""
        del tool_name
        if route is None or route.target is not SecurityTarget.COMMAND:
            return PermissionResult(permission=PermissionLevel.ALLOW)
        command = tool_args.get("command")
        if not isinstance(command, str):
            return PermissionResult(permission=PermissionLevel.ASK, reason="Command injection detection requires a string command")
        rules: tuple[Rule, ...] = ()
        if route.command_dialect is CommandDialect.POSIX_SHELL:
            rules = _POSIX_RULES
        elif route.command_dialect is CommandDialect.POWERSHELL:
            rules = _POWERSHELL_RULES
        for rule_name, pattern, reason in rules:
            if pattern.search(command):
                return PermissionResult(permission=PermissionLevel.DENY, matched_rule=rule_name, reason=reason)
        return PermissionResult(permission=PermissionLevel.ALLOW)


__all__ = ["InjectionComponent"]
