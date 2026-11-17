# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Optional Windows user-mode protection layer with DLL hooks and runtime approvals."""

from agent_shield.tool_permission.runtime.engine import HostPolicyAdapter
from agent_shield.tool_permission.runtime.engine import PermissionEngine as RuntimePermissionEngine
from agent_shield.tool_permission.runtime.grants import scope_options
from agent_shield.tool_permission.runtime.models import (
    PermissionConfirmResponse,
    PermissionLevel,
    PermissionResult,
)

from .bridge import RuntimeApprovalRequests
from .bundle import locate_guard_dll, validate_guard_bundle, validate_guard_platform
from .contracts import (
    ApprovalGrant,
    ApprovalReceipt,
    ConfirmationFields,
    PersistApproval,
    PolicyRevision,
    ProgramDecision,
    ProgramSubject,
    RuntimeApprovalEvent,
    RuntimePersistenceEvent,
    TakeApproval,
)
from .errors import (
    GuardBundleError,
    GuardBundleMissingError,
    GuardError,
    GuardInjectionError,
    GuardPipeError,
    GuardPlatformError,
    GuardPolicyDenied,
    GuardStartupError,
    GuardTargetArchitectureError,
)

__all__ = [
    "ApprovalGrant",
    "ApprovalReceipt",
    "ConfirmationFields",
    "GuardBundleError",
    "GuardBundleMissingError",
    "GuardError",
    "GuardInjectionError",
    "GuardPipeError",
    "GuardPlatformError",
    "GuardPolicyDenied",
    "GuardStartupError",
    "GuardTargetArchitectureError",
    "HostPolicyAdapter",
    "PermissionConfirmResponse",
    "PermissionLevel",
    "PermissionResult",
    "PersistApproval",
    "PolicyRevision",
    "ProgramDecision",
    "ProgramSubject",
    "RuntimeApprovalEvent",
    "RuntimeApprovalRequests",
    "RuntimePermissionEngine",
    "RuntimePersistenceEvent",
    "TakeApproval",
    "locate_guard_dll",
    "scope_options",
    "validate_guard_bundle",
    "validate_guard_platform",
]
