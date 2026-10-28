# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""删除数量防护判定器（Pipeline D）。

仅在软删除开关打开时才参与权限判定：一次 shell 调用删除的文件/符号链接数
达到阈值时，把本次调用抬升为 ASK（``del_guard:batch_delete``）。

- 未达阈值 / 非删除命令 / 软删除关闭 → 返回 ``None``（不改变既有判定）。
- 解析失败 / 目标不可访问 → fail-open，返回 ``None`` 只告警，由既有规则兜底。
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from typing import Any, Callable

from ..fileguard.tool_categories import is_shell_tool, shell_tools_from_config
from ..models import PermissionLevel, PermissionResult
from .del_count import count_deletion_targets

logger = logging.getLogger(__name__)

# 软删除开关解析器签名：config -> bool。
SoftDeleteEnabledProvider = Callable[[Mapping[str, Any] | None], bool]


def _permissions_section(config: Mapping[str, Any] | None) -> Mapping[str, Any]:
    """归一化配置形态。

    生产路径下 :class:`PermissionEngine` 传入的是「权限段本身」（不含 ``permissions``
    外层键）；单测/某些宿主亦可能传入带 ``permissions`` 外层的全量配置。这里统一
    返回权限段，供 :func:`_default_soft_delete_enabled` 与 ``threshold()`` 复用。
    """
    if not isinstance(config, Mapping):
        return {}
    inner = config.get("permissions")
    if isinstance(inner, Mapping):
        return inner
    return config


def _default_soft_delete_enabled(config: Mapping[str, Any] | None) -> bool:
    """缺省解析：读权限段内 ``soft_delete.enabled``。"""
    section = _permissions_section(config).get("soft_delete")
    if not isinstance(section, Mapping):
        return False
    return section.get("enabled") is True


def _shell_type_for_delete(tool_name: str, args: Mapping[str, Any]) -> str:
    """powershell 工具没有 shell_type 参数，计数仍按 PowerShell 语法拆逗号列表。"""
    if tool_name in {"powershell", "core.powershell"}:
        return "powershell"
    explicit = str(args.get("shell_type") or "").strip().lower()
    return explicit or "auto"


def _fixed_soft_delete_enabled(enabled: bool) -> SoftDeleteEnabledProvider:
    """把布尔开关包成与配置无关的解析器。"""

    def _provider(_config: Mapping[str, Any] | None) -> bool:
        return enabled

    return _provider


class DeletionGuard:
    """批量删除审批判定器。"""

    def __init__(
        self,
        *,
        soft_delete_enabled: SoftDeleteEnabledProvider | bool | None = None,
        permission_config: Mapping[str, Any] | None = None,
        workspace_root: str | None = None,
    ) -> None:
        if isinstance(soft_delete_enabled, bool):
            self._soft_delete_enabled: SoftDeleteEnabledProvider = _fixed_soft_delete_enabled(
                soft_delete_enabled,
            )
        elif callable(soft_delete_enabled):
            self._soft_delete_enabled = soft_delete_enabled
        else:
            self._soft_delete_enabled = _default_soft_delete_enabled
        self._permission_config = permission_config
        self._workspace_root = workspace_root

    def enabled(self) -> bool:
        """软删除是否开启（批量删除审批的前置条件）。"""
        try:
            return bool(self._soft_delete_enabled(self._permission_config))
        except Exception:  # noqa: BLE001 - 开关解析失败视为关闭
            logger.warning("[DeletionGuard] soft_delete_enabled resolve failed", exc_info=True)
            return False

    def threshold(self) -> int:
        """读 ``soft_delete.batch_delete_threshold``。缺省 100，``0`` 关闭计数。"""
        section = _permissions_section(self._permission_config).get("soft_delete")
        if not isinstance(section, Mapping) or "batch_delete_threshold" not in section:
            return 100
        raw = section.get("batch_delete_threshold")
        try:
            value = int(raw)
        except (TypeError, ValueError):
            logger.warning(
                "[DeletionGuard] invalid soft_delete.batch_delete_threshold=%r; using 100",
                raw,
            )
            return 100
        return max(0, value)

    def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> PermissionResult | None:
        """评估删除数量；无意见或未达阈值时返回 ``None``。"""
        if not self.enabled():
            return None
        threshold = self.threshold()
        if threshold <= 0:
            return None
        shell_tools = shell_tools_from_config(self._permission_config)
        if not is_shell_tool(tool_name, shell_tools):
            return None

        args = tool_args if isinstance(tool_args, Mapping) else {}
        command = str(args.get("command", "") or args.get("cmd", "") or "")
        if not command.strip():
            return None

        workdir = args.get("workdir") or self._workspace_root
        shell_type = _shell_type_for_delete(tool_name, args)

        try:
            count, hit_paths = count_deletion_targets(command, shell_type, workdir)
        except Exception:  # noqa: BLE001 - fail-open
            logger.warning("[DeletionGuard] count failed tool=%s", tool_name, exc_info=True)
            return None

        if count == 0:
            return None
        if count < threshold:
            logger.info(
                "[DeletionGuard] below_threshold tool=%s count=%d threshold=%d",
                tool_name, count, threshold,
            )
            return None

        return PermissionResult(
            permission=PermissionLevel.ASK,
            matched_rule="del_guard:batch_delete",
            reason=f"本次操作将删除 {count} 个文件，达到阈值 {threshold}，需要确认",
            external_paths=hit_paths or None,
        )


def build_deletion_guard(
    permission_config: Mapping[str, Any] | None,
    *,
    soft_delete_enabled: SoftDeleteEnabledProvider | bool | None = None,
    workspace_root: str | None = None,
) -> DeletionGuard | None:
    """编译删除防护判定器；软删除关闭 / 未配置阈值时返回 ``None``。"""
    guard = DeletionGuard(
        soft_delete_enabled=soft_delete_enabled,
        permission_config=permission_config,
        workspace_root=workspace_root,
    )
    if not guard.enabled():
        return None
    if guard.threshold() <= 0:
        return None
    return guard


__all__ = [
    "DeletionGuard",
    "SoftDeleteEnabledProvider",
    "build_deletion_guard",
    "default_soft_delete_enabled",
]


def default_soft_delete_enabled(config: Mapping[str, Any] | None) -> bool:
    """暴露缺省开关解析器，供宿主复用/包装。"""
    return _default_soft_delete_enabled(config)