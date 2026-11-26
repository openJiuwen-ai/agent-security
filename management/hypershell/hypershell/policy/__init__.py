"""Hypershell policy core.

Public API::

    from hypershell.policy import compile_plan, CompileContext, LaunchRequest
"""

from .compiler import COMPILER_VERSION, CompileContext, compile_plan, effective_permissions
from .errors import (
    IncompatibleProfile,
    InvalidQuota,
    InvalidRequest,
    PermissionExceedsBoundary,
    PolicyError,
    UnknownResource,
    UnsupportedCapability,
)
from .model import (
    AccessMode,
    LaunchPlan,
    LaunchRequest,
    Layer,
    Mount,
    NetworkRule,
    Resource,
)

__all__ = [
    "AccessMode",
    "COMPILER_VERSION",
    "CompileContext",
    "IncompatibleProfile",
    "InvalidQuota",
    "InvalidRequest",
    "LaunchPlan",
    "LaunchRequest",
    "Layer",
    "Mount",
    "NetworkRule",
    "PermissionExceedsBoundary",
    "PolicyError",
    "Resource",
    "UnknownResource",
    "UnsupportedCapability",
    "compile_plan",
    "effective_permissions",
]
