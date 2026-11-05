# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""F1 动作决策：对工具调用输出确定性结论（allow / ask / deny）。

本子模块的公开接口只有下面 ``__all__`` 列出的名字；调用方只从这里导入，
``toolguard`` / ``fileguard`` / ``netguard`` / ``hostguard`` 以及 ``engine``、
``routing`` 等内部模块不对外承诺稳定。``PermissionEngine`` 是内部实现，
调用方一律通过 :func:`get_permission_manager` 做权限判定；需要与进程级单例
隔离的实例（主要供测试）用 :func:`new_permission_manager` 构造。
"""

from .component import PermissionComponent
from .manager import PermissionManager, get_permission_manager, new_permission_manager
from .models import PermissionLevel, PermissionResult
from .routing import (
    CandidateKind,
    CommandDialect,
    RouteContext,
    RouteInterest,
    SecurityTarget,
)
from .sandbox_projection import (
    SandboxPolicyProjection,
    SkippedSandboxRule,
    project_sandbox_policy,
)

__all__ = [
    "CandidateKind",
    "CommandDialect",
    "PermissionComponent",
    "PermissionLevel",
    "PermissionManager",
    "PermissionResult",
    "RouteContext",
    "RouteInterest",
    "SandboxPolicyProjection",
    "SecurityTarget",
    "SkippedSandboxRule",
    "get_permission_manager",
    "new_permission_manager",
    "project_sandbox_policy",
]
