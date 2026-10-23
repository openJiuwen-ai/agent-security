"""F1 动作决策：对工具调用输出确定性结论（allow / ask / deny）。

本子模块的公开接口只有下面 ``__all__`` 列出的名字；调用方只从这里导入，
``toolguard`` / ``fileguard`` / ``netguard`` / ``hostguard`` 以及 ``engine``、
``routing`` 等内部模块不对外承诺稳定。
"""

from .component import PermissionComponent
from .engine import PermissionEngine
from .models import PermissionLevel, PermissionResult
from .routing import (
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
    "PermissionComponent",
    "PermissionEngine",
    "PermissionLevel",
    "PermissionResult",
    "CommandDialect",
    "RouteContext",
    "RouteInterest",
    "SecurityTarget",
    "SandboxPolicyProjection",
    "SkippedSandboxRule",
    "project_sandbox_policy",
]
