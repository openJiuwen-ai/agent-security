# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Framework-independent runtime decision and approval contracts."""

from dataclasses import dataclass

from ..models import PermissionLevel
from ..models import PermissionResult as SDKResult


@dataclass
class PermissionResult(SDKResult):
    @property
    def is_allowed(self):
        return self.permission == PermissionLevel.ALLOW

    @property
    def is_denied(self):
        return self.permission == PermissionLevel.DENY

    @property
    def needs_approval(self):
        return self.permission == PermissionLevel.ASK

    @property
    def is_undetermined(self):
        return self.permission == PermissionLevel.UNDETERMINED


@dataclass(frozen=True)
class PermissionConfirmResponse:
    approved: bool
    feedback: str = ""
    auto_confirm: bool = False
    persist_allow: bool | None = None
    authorization_mode: str | None = None
    authorization_scope: str | None = None

    def __post_init__(self):
        if not isinstance(self.approved, bool) or not isinstance(self.auto_confirm, bool):
            raise TypeError("Approval flags must be booleans")
        if self.persist_allow is not None and not isinstance(self.persist_allow, bool):
            raise TypeError("Persistence flag must be boolean or None")

    def wants_permanent_persist(self):
        return bool(self.approved and self.auto_confirm and self.persist_allow is not False)

    def wants_session_persist(self):
        return bool(self.approved and self.auto_confirm and self.persist_allow is False)

    @classmethod
    def from_host(cls, answer):
        """Normalize a trusted host reply without accepting truthy strings."""
        if isinstance(answer, cls):
            return answer
        approved = getattr(answer, "approved", None)
        remember = getattr(answer, "auto_confirm", False)
        permanent = getattr(answer, "persist_allow", None)
        if not isinstance(approved, bool) or not isinstance(remember, bool):
            raise TypeError("Approval flags must be booleans")
        if permanent is not None and not isinstance(permanent, bool):
            raise TypeError("Persistence flag must be boolean or None")
        return cls(
            approved=approved,
            auto_confirm=remember,
            persist_allow=permanent,
            feedback=getattr(answer, "feedback", ""),
            authorization_mode=getattr(answer, "authorization_mode", None),
            authorization_scope=getattr(answer, "authorization_scope", None),
        )
