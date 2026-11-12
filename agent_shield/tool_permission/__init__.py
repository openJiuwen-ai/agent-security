# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""F1 动作决策：唯一对外入口是 :class:`PermissionManager`。

调用方只通过 :func:`get_permission_manager` 做权限判定，并把完整的
``permissions`` 配置交给管理器的 ``key`` 或一次性 ``config`` 参数；需要与
进程级单例隔离的实例（主要供测试）用 :func:`new_permission_manager` 构造。
``PermissionEngine``、组件契约、路由与 sandbox 投影都是引擎内部实现，
不在门面导出。
"""

from .manager import PermissionManager, get_permission_manager, new_permission_manager
from .models import PermissionLevel, PermissionResult

__all__ = [
    "PermissionLevel",
    "PermissionManager",
    "PermissionResult",
    "get_permission_manager",
    "new_permission_manager",
]
