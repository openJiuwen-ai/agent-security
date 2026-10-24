# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""W2 path guard components wired into :class:`PermissionEngine`."""

from __future__ import annotations

from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from ..config_access import (
    builtin_section,
    runtime_immutable_roots,
    runtime_path,
    runtime_trusted_dirs,
    runtime_workspace_root,
)
from .file_guard import FileGuardChecker, build_file_guard_checker
from .immutable_control_plane import ImmutableControlPlaneGuard
from .sensitive_paths import merge_builtin_sensitive_paths
from ..models import PermissionResult
from ..routing import RouteContext, RouteInterest, SecurityTarget

# Shell tools are routed as COMMAND, but path extraction still has to see them.
_PATH_INTERESTS = (
    RouteInterest(SecurityTarget.FILE),
    RouteInterest(SecurityTarget.COMMAND),
)


def _permissions_for_file_guard(config: Mapping[str, Any]) -> dict[str, Any]:
    """Merge top-level ``file_guard.paths`` with ``builtin.sensitive_paths``."""

    perms = dict(config)
    raw_paths = builtin_section(config).get("sensitive_paths")
    return merge_builtin_sensitive_paths(
        perms,
        raw_paths,
        package_builtin_rules=config.get("package_builtin_rules"),
    )


class FileGuardComponent:
    """Native / legacy file_guard path policy (Pipeline B)."""

    interests = _PATH_INTERESTS

    def __init__(self) -> None:
        self._checker: FileGuardChecker | None = None

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise TypeError("Engine configuration must be a mapping")
        workspace = runtime_path(config, "workspace_root") or runtime_workspace_root(config)
        agent_cwd = runtime_path(config, "cwd")
        trusted = [Path(item) for item in runtime_trusted_dirs(config)]
        perms = _permissions_for_file_guard(config)
        section = perms.get("file_guard")
        enabled = True
        if isinstance(section, Mapping) and section.get("enabled") is False:
            enabled = False
        if not enabled:
            self._checker = None
            return
        self._checker = build_file_guard_checker(
            perms,
            workspace_root=workspace,
            trusted_dirs=trusted,
            agent_cwd=agent_cwd,
        )

    def active(self) -> bool:
        """True after configure built a checker. A disabled file_guard stays inactive."""

        return self._checker is not None

    def collect_ask_accesses(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
    ) -> list[tuple[str, str]]:
        """ASK paths from the configured checker. Inactive file_guard returns none."""

        if self._checker is None:
            return []
        return [
            (path, action)
            for path, action in self._checker.collect_ask_accesses(tool_name, tool_args)
        ]

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        if self._checker is None:
            return None
        return self._checker.evaluate(tool_name, tool_args)


class ImmutableControlPlaneComponent:
    """Host control-plane write protection (independent of file_guard.enabled)."""

    interests = _PATH_INTERESTS

    def __init__(self) -> None:
        self._guard: ImmutableControlPlaneGuard | None = None

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise TypeError("Engine configuration must be a mapping")
        roots = runtime_immutable_roots(config)
        workspace = runtime_path(config, "workspace_root") or runtime_workspace_root(config)
        agent_cwd = runtime_path(config, "cwd")
        perms = config
        if not roots:
            self._guard = None
            return
        # The original guard resolved relative paths against the workspace, or
        # the process cwd when the workspace was missing. The cwd now has to
        # be passed in. Without either base, a relative write would skip the
        # control plane.
        if workspace is None and agent_cwd is None:
            raise ValueError(
                "runtime.immutable_control_roots requires runtime.workspace_root "
                "or runtime.cwd"
            )
        self._guard = ImmutableControlPlaneGuard(
            list(roots),
            workspace_root=workspace,
            permission_config=deepcopy(dict(perms)) if isinstance(perms, Mapping) else None,
            agent_cwd=agent_cwd,
        )

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        if self._guard is None or not self._guard.enabled:
            return None
        return self._guard.evaluate(tool_name, tool_args)


__all__ = ["FileGuardComponent", "ImmutableControlPlaneComponent"]
