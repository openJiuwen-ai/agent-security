"""R05 command allowlist component."""

from __future__ import annotations

from collections.abc import Mapping
import os

from ..models import PermissionLevel, PermissionResult
from ..routing import CommandDialect, RouteContext, RouteInterest, SecurityTarget


_DEFAULT_ALLOWLIST = (
    "echo", "rg", "ls", "dir", "cd", "pwd", "python", "python3", "pip", "pip3",
    "npm", "node", "git", "cat", "type", "mkdir", "md", "rm", "rd", "cp", "copy",
    "mv", "move", "grep", "find", "curl", "wget", "ps", "df", "ping",
)
_MISSING = object()


class CommandAllowlistComponent:
    """Check the first command token against the configured allowlist."""

    interests: tuple[RouteInterest, ...] = tuple(
        RouteInterest(SecurityTarget.COMMAND, dialect)
        for dialect in CommandDialect
    )

    def __init__(self) -> None:
        self._allowlist: tuple[str, ...] | None = _DEFAULT_ALLOWLIST

    def configure(self, config: Mapping[str, object]) -> None:
        """Read the engine-owned ``shell_allowlist`` configuration field."""

        value = config.get("shell_allowlist", _MISSING)
        if value is _MISSING:
            allowlist: tuple[str, ...] | None = _DEFAULT_ALLOWLIST
        elif value is None:
            allowlist = None
        elif isinstance(value, (list, tuple)):
            if any(not isinstance(item, str) or not item for item in value):
                raise ValueError("shell_allowlist must contain non-empty strings")
            allowlist = tuple(value) or None
        else:
            raise TypeError("shell_allowlist must be a list of strings or None")

        self._allowlist = allowlist

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        """Dispatch by route dialect, then return the allowlist decision."""

        del tool_name  # The engine has already resolved the tool route.
        if route is None or route.target is not SecurityTarget.COMMAND:
            return None

        # R05 currently applies the same prefix rule to each shell dialect.
        # Keep dialect dispatch explicit so future dialect-specific behavior
        # does not leak into routing or the shared PermissionEngine.
        if route.command_dialect not in (
            CommandDialect.POSIX_SHELL,
            CommandDialect.POWERSHELL,
            CommandDialect.CMD,
            CommandDialect.UNKNOWN,
        ):
            return None

        if self._allowlist is None:
            return self._result(PermissionLevel.ALLOW, "disabled", "Allowlist is disabled")

        command = tool_args.get("command")
        if not isinstance(command, str):
            return None

        prefix = command.split()[0] if command.strip() else ""
        matched = any(
            prefix == allowed or prefix.endswith(os.sep + allowed)
            for allowed in self._allowlist
        )
        if matched:
            return self._result(
                PermissionLevel.ALLOW,
                "matched",
                f"Command prefix '{prefix}' is in the allowlist",
            )
        return self._result(
            PermissionLevel.DENY,
            "not_allowed",
            f"Command prefix '{prefix}' is not in the allowlist",
        )

    @staticmethod
    def _result(level: PermissionLevel, outcome: str, reason: str) -> PermissionResult:
        return PermissionResult(
            permission=level,
            matched_rule=f"shell_allowlist:{outcome}",
            reason=reason,
        )


__all__ = ["CommandAllowlistComponent"]
