# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""F1 工具调用决策由 :class:`PermissionManager` 统一提供。

调用方只通过 :func:`get_permission_manager` 做权限判定，并把完整的
``permissions`` 配置交给管理器的 ``key`` 或一次性 ``config`` 参数；需要与
进程级单例隔离的实例（主要供测试）用 :func:`new_permission_manager` 构造。
``PermissionEngine``、组件契约、路由与 sandbox 投影都是引擎内部实现，
不在门面导出。
可选 ``runtime_policy`` 为原生适配层提供实际资源、授权和配置支持，
不改变既有工具调用入口、组件可见性或默认策略。
"""

from typing import TYPE_CHECKING

from .manager import PermissionManager, get_permission_manager, new_permission_manager
from .models import PermissionLevel, PermissionResult

if TYPE_CHECKING:
    from . import runtime_policy as runtime_policy


def __getattr__(name: str):
    if name == "runtime_policy":
        from importlib import import_module

        return import_module(".runtime_policy", __name__)
    raise AttributeError(name)


__all__ = [
    "PermissionLevel",
    "PermissionManager",
    "PermissionResult",
    "get_permission_manager",
    "new_permission_manager",
    "runtime_policy",
]
