# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""F1 转发类 meta-tool 的展开注册表：外层信封按内层真实调用一并判定。

转发类 meta-tool（如 jiuwenswarm 的 ``invoke_tool(tool_name, arguments)``）把
目标工具调用包在外层参数里。权限判定只看外层时组件对内层命令失明——外层
工具名通常不在 ``tools`` 配置里、走 ``defaults`` 放行，内层命令携带完整载荷
穿透（issue jiuwenswarm#6499 的绕过路径）。

机制（注册表、递归深度封顶、内外结果合并取最严）归引擎；契约（哪个工具是
转发器、如何从外层参数取内层 ``(tool_name, tool_args)``）归宿主，经
:func:`register_meta_tool` 注册。未注册任何转发器的进程行为不变。
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable, Mapping
from typing import Any

logger = logging.getLogger(__name__)

# 展开深度封顶。宿主的功能门控（如拒绝转发常驻工具）不属于安全边界，引擎
# 不信任宿主自律；转发器套转发器最多展开到第二层，封顶处若外层仍是注册
# 转发器，引擎并入不可静默放行的 ASK 交用户裁决（见 engine._evaluate_expanded），
# 不按信封原样判定——否则深层嵌套会重新打开外层 defaults 放行的绕过。
META_TOOL_MAX_DEPTH = 2

# extractor 契约：外层 tool_args -> (内层 tool_name, 内层 tool_args)；
# 参数形状不符（非转发形态）返回 None 弃权，等价于只按外层判定。
MetaToolExtractor = Callable[[Mapping[str, Any]], "tuple[str, Mapping[str, Any]] | None"]

_lock = threading.Lock()
_extractors: dict[str, MetaToolExtractor] = {}


def register_meta_tool(tool_name: str, extractor: MetaToolExtractor) -> None:
    """注册（或替换）一个转发类 meta-tool 的展开契约。

    幂等：同名重复注册原地替换 extractor，宿主 rail 每次装配调用都安全。
    """
    if not isinstance(tool_name, str) or not tool_name.strip():
        raise ValueError("tool_name must be a non-empty string")
    if not callable(extractor):
        raise TypeError("extractor must be callable")
    with _lock:
        _extractors[tool_name] = extractor
    logger.info("permission.meta_tools.register tool=%s", tool_name)


def unregister_meta_tool(tool_name: str) -> None:
    """移除注册；供测试恢复进程级全局状态。"""
    with _lock:
        _extractors.pop(tool_name, None)


def registered_meta_tools() -> tuple[str, ...]:
    """返回当前注册的转发器名单（快照）。"""
    with _lock:
        return tuple(_extractors)


def resolve_meta_tool_expansion(
    tool_name: str,
    tool_args: Mapping[str, Any],
) -> tuple[str, Mapping[str, Any]] | None:
    """返回注册转发器携带的内层调用；未注册 / 形状不符返回 None。

    注册写只发生在装配期且 extractor 在注册前构造完整，读侧无锁快照即可。
    extractor 异常原样传播：与组件异常语义一致，由宿主 rail 边界的
    fail-closed 包装收口，不在判定路径上静默吞掉。返回值校验为宿主契约 bug
    兜底，同样抛出而非静默弃权。
    """
    extractor = _extractors.get(tool_name)
    if extractor is None:
        return None
    expansion = extractor(tool_args)
    if expansion is None:
        return None
    if not isinstance(expansion, tuple) or len(expansion) != 2:
        raise TypeError(
            "meta tool extractor must return (tool_name, tool_args) or None; "
            f"got {type(expansion).__name__}"
        )
    inner_name, inner_args = expansion
    if not isinstance(inner_name, str) or not inner_name.strip():
        raise TypeError(
            f"meta tool extractor returned invalid tool_name: {inner_name!r}"
        )
    if not isinstance(inner_args, Mapping):
        raise TypeError(
            "meta tool extractor returned non-mapping tool_args: "
            f"{type(inner_args).__name__}"
        )
    return inner_name, inner_args
