# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""W2 path protection: file_guard rules and the immutable control plane.

``file_guard`` is a top-level engine key, as it was inside the old permissions
mapping. Builtin sensitive paths arrive on ``config["builtin"]["sensitive_paths"]``.
"""

from .component import (
    FileGuardComponent,
    ImmutableControlPlaneComponent,
)

__all__ = ["FileGuardComponent", "ImmutableControlPlaneComponent"]
