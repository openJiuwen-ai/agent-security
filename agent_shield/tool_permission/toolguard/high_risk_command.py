# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Mark high-risk shell commands without changing allow / ask / deny."""

from __future__ import annotations

from collections.abc import Mapping
import re

from ..models import PermissionLevel, PermissionResult, RiskLevel
from ..routing import RouteContext

_BUILTIN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b"),
    re.compile(r"\brm\s+-[a-zA-Z]*f[a-zA-Z]*r\b"),
)


class HighRiskCommandComponent:
    """Optional high-risk mark for shell commands. Default off.

    Miss → ``ALLOW`` + ``risk_level=none``; hit → ``ASK`` + ``risk_level=high``.
    """

    def __init__(self) -> None:
        self._enabled = False
        self._patterns: tuple[re.Pattern[str], ...] = _BUILTIN_PATTERNS

    def configure(self, config: Mapping[str, object]) -> None:
        section = config.get("high_risk_command")
        if not isinstance(section, Mapping):
            self._enabled = False
            self._patterns = _BUILTIN_PATTERNS
            return
        self._enabled = section.get("enabled", False) is True
        raw_patterns = section.get("patterns")
        if isinstance(raw_patterns, list) and raw_patterns:
            compiled: list[re.Pattern[str]] = []
            for item in raw_patterns:
                if isinstance(item, str) and item:
                    compiled.append(re.compile(item))
            self._patterns = tuple(compiled) if compiled else _BUILTIN_PATTERNS
        else:
            self._patterns = _BUILTIN_PATTERNS

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
