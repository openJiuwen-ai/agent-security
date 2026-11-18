# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Mark high-risk shell commands from caller-configured patterns."""

from __future__ import annotations

from collections.abc import Mapping
import re

from ..models import PermissionLevel, PermissionResult, RiskLevel
from ..routing import RouteContext


class HighRiskCommandComponent:
    """Optional high-risk mark for shell commands. Default off.

    Patterns come only from config ``high_risk_command.patterns`` (no builtins).
    Matching is case-insensitive. Miss → ``ALLOW`` + ``none``; hit → ``ASK`` + ``high``.
    """

    def __init__(self) -> None:
        self._enabled = False
        self._patterns: tuple[re.Pattern[str], ...] = ()

    def configure(self, config: Mapping[str, object]) -> None:
        section = config.get("high_risk_command")
        if not isinstance(section, Mapping):
            self._enabled = False
            self._patterns = ()
            return
        enabled = section.get("enabled", False)
        if not isinstance(enabled, bool):
            raise ValueError("high_risk_command.enabled must be a boolean")
        self._enabled = enabled
        raw_patterns = section.get("patterns")
        compiled: list[re.Pattern[str]] = []
        if isinstance(raw_patterns, list):
            for item in raw_patterns:
                if isinstance(item, str) and item:
                    try:
                        compiled.append(re.compile(item, re.IGNORECASE))
                    except re.error as exc:
                        raise ValueError(
                            f"high_risk_command.patterns invalid regex: {item!r}"
                        ) from exc
        self._patterns = tuple(compiled)

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        del tool_name
        if not self._enabled:
            return None
        if route is None or not route.is_shell:
            return None
        command = tool_args.get("command")
        if not isinstance(command, str) or not command:
            return None
        if not self._patterns:
            return PermissionResult(
                permission=PermissionLevel.ALLOW,
                risk_level=RiskLevel.NONE,
            )
        for pattern in self._patterns:
            if pattern.search(command):
                return PermissionResult(
                    permission=PermissionLevel.ASK,
                    risk_level=RiskLevel.HIGH,
                )
        return PermissionResult(
            permission=PermissionLevel.ALLOW,
            risk_level=RiskLevel.NONE,
        )


__all__ = ["HighRiskCommandComponent"]
