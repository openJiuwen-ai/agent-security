# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Agent 安全组件集合。

各子模块相互独立，调用方从子模块导入。权限判定通过
``from agent_shield.tool_permission import get_permission_manager`` 获取进程级
管理器；需要隔离实例（主要供测试）时用 ``new_permission_manager``。
``agent_shield.tool_permission.engine.PermissionEngine`` 仅供内部使用，不从
门面导出。本包根不导出任何名字，也不在导入时加载子模块。
"""
