"""What a host must provide. The security package does not import a framework."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class VersionedRules:
    """Host cache. The same version means these items have not changed."""

    version: str | int
    items: list[dict]


class Host(Protocol):
    """Task context and the approval window. Skipping a tool is the host PEP's job."""

    def user_intent(self) -> dict | None:
        """Original user words for this task. Model plans are not intent."""

    def workspace(self) -> dict:
        """root, trusted_dirs, and os."""

    def capabilities(self) -> dict:
        """hitl and auto_intent."""

    def request_approval(self, decision: dict, event: dict) -> bool:
        """Open the approval window. True allows the call, False denies it."""

    def user_rules(self) -> list[dict] | VersionedRules:
        """This subject's custom rules. Empty when the host has none."""

    def grants(self) -> list[dict] | VersionedRules:
        """This subject's exact grants. Empty when the host has none."""
