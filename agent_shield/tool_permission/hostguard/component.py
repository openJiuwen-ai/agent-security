# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Host command guard component for shell tools."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from ..config_access import (
    host_guard_section,
    runtime_protected_pids,
    runtime_workspace_root,
)
from ..models import PermissionLevel, PermissionResult
from ..routing import RouteContext, resolve_route
from .safety import compile_name_patterns, evaluate_host_guard
from .shell_mismatch import shell_mismatch

# Original hooks are the bash tool, the powershell tool, and mcp_exec_command.
# core.powershell is the engine name of that powershell tool. sh, zsh, cmd and
# create_terminal are command routes, but the original hooks did not patch
# them, so the same kill text is allowed there.
_HOST_GUARD_SHELL_TOOLS = frozenset({"bash", "powershell", "core.powershell"})
_HOST_GUARD_SAFETY_TOOLS = _HOST_GUARD_SHELL_TOOLS | frozenset({"mcp_exec_command"})
_CONTINUATION_SHELLS = frozenset({"bash", "sh", "powershell", "cmd"})
_HOST_GUARD_KEYS = frozenset({"enabled", "protected_patterns"})


def _reject_unknown_host_guard_keys(section: Mapping[str, object]) -> None:
    """Fail closed when a caller sends a removed switch or an unknown key."""

    unknown = sorted(str(key) for key in section if key not in _HOST_GUARD_KEYS)
    if unknown:
        raise ValueError(
            "host_guard only accepts enabled and protected_patterns; remove "
            + ", ".join(unknown)
        )


@dataclass(frozen=True, slots=True)
class _State:
    project_root: Path | None
    protected_pids: frozenset[str] | None
    name_patterns: tuple[tuple[re.Pattern[str], str], ...] | None


def _command_text(tool_args: Mapping[str, object]) -> str | None:
    """Read the shell text. ``command`` wins; ``cmd`` is the tiered-policy alias."""

    for key in ("command", "cmd"):
        value = tool_args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


def _continuation_shell(tool_name: str, tool_args: Mapping[str, object]) -> str:
    """Shell whose line-continuation form the original guard joined."""

    if tool_name == "bash":
        return "bash"
    if tool_name in {"powershell", "core.powershell"}:
        return "powershell"
    if tool_name != "mcp_exec_command":
        return ""
    raw = tool_args.get("shell_type")
    if not isinstance(raw, str):
        return ""
    shell = raw.strip().lower()
    return shell if shell in _CONTINUATION_SHELLS else ""


def _tool_basename(tool_name: str) -> str:
    if not isinstance(tool_name, str):
        return ""
    base = os.path.basename(tool_name.strip().replace("\\", "/")).lower()
    return base.removesuffix(".exe")


class HostGuardComponent:
    """Block host-killing shell commands unless ``host_guard.enabled`` is false.

    Callers are not distinguished. The only switch is ``enabled`` and it is on
    by default. The other accepted key is ``protected_patterns``: omit it to
    keep the product-name floor, or pass a list to replace that floor only.
    Segment, image, pid, and worktree checks stay either way.

    With the switch on, worktree accepts only a real ``git worktree add`` and
    refuses one it cannot parse. Pid checks use the wide command match.
    ``sh``, ``zsh``, ``cmd``, and ``create_terminal`` are not hooked.

    Runtime values. A missing value skips only the check that needs it:

    - ``runtime.project_root``, or else ``runtime.workspace_root``. Worktree
      runs only when one is set.
    - ``runtime.protected_pids``. These ids are added to the discovered set
      (this process, its ancestors, and runtime-shaped processes). Omitting
      the key does not turn the pid check off, and a passed list does not
      remove discovered ids.
    """

    def __init__(self) -> None:
        self._state: _State | None = None

    def active(self) -> bool:
        """True when host_guard.enabled left a configured guard."""

        return self._state is not None

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise TypeError("Engine configuration must be a mapping")
        section = host_guard_section(config)
        enabled_raw = section.get("enabled", True)
        if not isinstance(enabled_raw, bool):
            raise TypeError("host_guard.enabled must be a boolean")
        _reject_unknown_host_guard_keys(section)
        name_patterns = None
        if "protected_patterns" in section:
            name_patterns = compile_name_patterns(section.get("protected_patterns"))
        if not enabled_raw:
            self._state = None
            return
        self._state = _State(
            project_root=runtime_workspace_root(config),
            protected_pids=runtime_protected_pids(config),
            name_patterns=name_patterns,
        )

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        state = self._state
        if state is None:
            return None
        name = _tool_basename(tool_name)
        route = route or resolve_route(tool_name, tool_args)
        if not route.is_shell:
            return None
        if name not in _HOST_GUARD_SAFETY_TOOLS:
            return None
        command = _command_text(tool_args)
        if command is None:
            return None
        if name == "bash":
            mismatch = shell_mismatch(name, command)
            if mismatch is not None:
                return PermissionResult(
                    permission=PermissionLevel.DENY,
                    matched_rule="host_guard:shell_mismatch",
                    reason=mismatch,
                )
        block = evaluate_host_guard(
            command,
            project_root=state.project_root,
            protected_pids=state.protected_pids,
            name_patterns=state.name_patterns,
            shell_type=_continuation_shell(name, tool_args),
        )
        if block is None:
            return None
        return PermissionResult(
            permission=PermissionLevel.DENY,
            matched_rule="host_guard:safety",
            reason=block,
        )


__all__ = ["HostGuardComponent"]
