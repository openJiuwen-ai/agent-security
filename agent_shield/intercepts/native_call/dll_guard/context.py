"""Host-owned execution lifetime and temporary resource grants for DLL Guard.

This module does not authenticate IPC clients. The bridge must authenticate the
peer and process-tree membership before accessing a context. All methods run on
the host event-loop thread; no decision cache is maintained here.
"""

from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, field, replace
from secrets import token_urlsafe
from typing import Any

from .contracts import ApprovalGrant
from .policy import resource_grant_matches


@dataclass(frozen=True)
class _TemporaryGrant:
    source_tool: str
    grant: ApprovalGrant
    policy_version: str


@dataclass
class RuntimeGuardContext:
    """One execution, including descendants and background work, of a tool call.

    Only trusted host code may add already-confirmed resource grants. Checking a
    grant never replaces evaluating the current policy (especially DENY).
    """

    session_id: str
    tool_call_id: str
    policy_version: str
    execution_id: str = field(default_factory=lambda: token_urlsafe(24), init=False)
    _active: bool = field(default=True, init=False, repr=False)
    _revoke_cache: Callable | None = field(default=None, init=False, repr=False, compare=False)
    _grants: list[_TemporaryGrant] = field(default_factory=list, init=False, repr=False)

    def __post_init__(self) -> None:
        for name in ("session_id", "tool_call_id", "policy_version"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

    @property
    def active(self) -> bool:
        return self._active

    def bind_cache_revoker(self, revoke: Callable) -> None:
        self._revoke_cache = revoke

    def remember(self, source_tool: str, grant: ApprovalGrant, *, policy_version: str) -> None:
        """Store a host-confirmed resource grant, never a caller-supplied tool identity."""
        if not self._active or policy_version != self.policy_version:
            raise ValueError("Execution ended or approval policy version is stale")
        if (
            not isinstance(source_tool, str)
            or not source_tool.strip()
            or grant.get("tools") != [source_tool]
        ):
            raise ValueError("Approval source tool does not match its grant")
        item = _TemporaryGrant(source_tool, deepcopy(grant), policy_version)
        if item not in self._grants:
            self._grants.append(item)

    def matches(
        self, subject: dict[str, Any], *, execution_id: str, policy_version: str, exact_only=False
    ) -> bool:
        """Match only within this active execution and the current policy version."""
        if (
            not self._active
            or execution_id != self.execution_id
            or policy_version != self.policy_version
        ):
            return False
        return any(
            item.policy_version == policy_version
            and resource_grant_matches(item.grant, subject, exact_only=exact_only)
            for item in self._grants
        )

    def update_policy_version(self, version: str, *, preserve_grants=False) -> None:
        """Invalidate grants unless the host verified its own approval-only save."""
        if not isinstance(version, str) or not version.strip():
            raise ValueError("policy_version must be a non-empty string")
        if version != self.policy_version:
            if preserve_grants and self._active:
                self._grants = [replace(item, policy_version=version) for item in self._grants]
            else:
                self._grants.clear()
            self.policy_version = version

    def finish(self) -> None:
        """Release temporary grants when the execution tree ends or is cancelled."""
        try:
            if self._revoke_cache is not None:
                self._revoke_cache()
        finally:
            self._revoke_cache = None
            self._active = False
            self._grants.clear()
