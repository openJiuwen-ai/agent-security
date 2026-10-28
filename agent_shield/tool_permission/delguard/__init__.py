# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""删除数量防护（Pipeline D）。"""

from .component import DeletionGuardComponent
from .del_count import count_deletion_targets
from .deletion_guard import (
    DeletionGuard,
    SoftDeleteEnabledProvider,
    build_deletion_guard,
    default_soft_delete_enabled,
)

__all__ = [
    "DeletionGuard",
    "DeletionGuardComponent",
    "SoftDeleteEnabledProvider",
    "build_deletion_guard",
    "count_deletion_targets",
    "default_soft_delete_enabled",
]
