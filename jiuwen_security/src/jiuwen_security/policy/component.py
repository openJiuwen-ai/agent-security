"""Component contract used by :class:`PermissionEngine`."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol

from .models import PermissionResult


class PermissionComponent(Protocol):
    """A security capability owned and configured by the permission engine."""

    def configure(self, config: Mapping[str, object]) -> None:
        """Prepare component state from the complete engine configuration."""

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
    ) -> PermissionResult | None:
        """Evaluate one tool call using state prepared by ``configure``."""
