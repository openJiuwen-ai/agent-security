# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
"""Runtime adapter layer (registry, capabilities, base contract).

Exposes the runtime selection API and the capability model so callers do
not need to import the platform-specific adapter modules directly.
"""

from jiuwenbox.server.runtime.base import (
    RuntimeAdapter,
    RuntimeBackgroundExecRequest,
    RuntimeExecRequest,
    RuntimeFileOpResult,
    RuntimeInstance,
)
from jiuwenbox.server.runtime.capabilities import (
    RuntimeCapabilities,
    SECURITY_CAPABILITIES,
)
from jiuwenbox.server.runtime.registry import (
    RUNTIME_PROFILE_ENV,
    RuntimeResolutionError,
    available_runtime_names,
    get_runtime,
    load_runtime_class,
    platform_default_runtime,
    reset_registry,
    resolve_runtime_name,
    verify_runtime_available,
)

__all__ = [
    "RuntimeAdapter",
    "RuntimeBackgroundExecRequest",
    "RuntimeExecRequest",
    "RuntimeFileOpResult",
    "RuntimeInstance",
    "RuntimeCapabilities",
    "SECURITY_CAPABILITIES",
    "RUNTIME_PROFILE_ENV",
    "RuntimeResolutionError",
    "available_runtime_names",
    "get_runtime",
    "load_runtime_class",
    "platform_default_runtime",
    "reset_registry",
    "resolve_runtime_name",
    "verify_runtime_available",
]
