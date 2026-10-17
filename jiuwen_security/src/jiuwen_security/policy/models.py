"""Common data models for security permission decisions."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class PermissionLevel(StrEnum):
    """Permission levels produced by security components."""

    ALLOW = "allow"
    ASK = "ask"
    UNDETERMINED = "undetermined"
    DENY = "deny"


@dataclass(slots=True)
class PermissionResult:
    """A component result or the final result returned by the engine.

    A component may return a partial result, so ``permission`` is optional at
    that stage.  The engine always returns a result with a permission level.
    """

    permission: PermissionLevel | None = None
    matched_rule: str | None = None
    reason: str | None = None
    warnings: list[str] = field(default_factory=list)
    external_paths: list[str] = field(default_factory=list)
