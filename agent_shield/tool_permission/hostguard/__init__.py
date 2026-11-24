# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""W1b 主机护栏：阻止杀死 Swarm 运行时及 shell 工具误路由。"""

from .component import HostGuardComponent

__all__ = ["HostGuardComponent"]
