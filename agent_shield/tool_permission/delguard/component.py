# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Batch-delete approval component. Active only when soft-delete is enabled."""

from __future__ import annotations

from collections.abc import Mapping

from ..config_access import runtime_workspace_root
from ..models import PermissionResult
from ..routing import RouteContext
from .deletion_guard import DeletionGuard


class DeletionGuardComponent:
    """ASK when one shell call deletes at least ``batch_delete_threshold`` files."""

    def __init__(self) -> None:
        self._guard: DeletionGuard | None = None

    def active(self) -> bool:
        return (
            self._guard is not None
            and self._guard.enabled()
            and self._guard.threshold() > 0
        )

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise TypeError("Engine configuration must be a mapping")
        root = runtime_workspace_root(config)
        self._guard = DeletionGuard(
            permission_config=config,
            workspace_root=str(root) if root is not None else None,
        )

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        del route
        if self._guard is None:
            return None
        return self._guard.evaluate(tool_name, tool_args)
