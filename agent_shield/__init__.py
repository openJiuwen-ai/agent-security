# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Agent 安全组件集合。

各子模块相互独立，调用方从子模块导入。权限判定通过
``from agent_shield.tool_permission import get_permission_manager`` 获取进程级
管理器；需要隔离实例（主要供测试）时用 ``new_permission_manager``。
``agent_shield.tool_permission.engine.PermissionEngine`` 仅供内部使用，不从
门面导出。会话级 ProcessGuard 按需加载。
"""


def __getattr__(name):
    if name == "ProcessGuard":
        from .intercepts.native_call.dll_guard.process_guard import ProcessGuard
        return ProcessGuard
    raise AttributeError(name)
