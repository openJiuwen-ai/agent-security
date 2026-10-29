# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Host command guard component for shell tools."""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from ..config_access import (
    host_guard_flag,
    host_guard_section,
    runtime_protected_pids,
    runtime_workspace_root,
)
from ..models import PermissionLevel, PermissionResult
from ..routing import RouteContext, resolve_route
from .safety import HostGuardOptions, compile_name_patterns, evaluate_host_guard
from .shell_mismatch import shell_mismatch
from .whole_line_regex import evaluate_whole_line_regex

# Original hooks are the bash tool, the powershell tool, and mcp_exec_command.
# core.powershell is the engine name of that powershell tool. sh, zsh, cmd and
# create_terminal are command routes, but the original hooks did not patch
# them, so the same kill text is allowed there.
_HOST_GUARD_SHELL_TOOLS = frozenset({"bash", "powershell", "core.powershell"})
_HOST_GUARD_SAFETY_TOOLS = _HOST_GUARD_SHELL_TOOLS | frozenset({"mcp_exec_command"})
_CONTINUATION_SHELLS = frozenset({"bash", "sh", "powershell", "cmd"})


@dataclass(frozen=True, slots=True)
class _State:
    enabled: bool
    project_root: Path | None
    options: HostGuardOptions
    shell_mismatch: bool
    whole_line_regex: bool
    protected_pids: frozenset[str] | None


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
    """Block host-killing shell commands and optional bash/PowerShell mismatches."""

    def __init__(self) -> None:
        self._state: _State | None = None

    def active(self) -> bool:
        """True when host_guard.enabled left a configured guard."""

        return self._state is not None

    def configure(self, config: Mapping[str, object]) -> None:
        if not isinstance(config, Mapping):
            raise TypeError("Engine configuration must be a mapping")
        section = host_guard_section(config)
        enabled_raw = section.get("enabled", False)
        if not isinstance(enabled_raw, bool):
            raise TypeError("host_guard.enabled must be a boolean")
        enabled = enabled_raw
        if not enabled:
            self._state = None
            return
        project_root = runtime_workspace_root(config)
        options = HostGuardOptions(
            python_name_kill=host_guard_flag(section, "python_name_kill", False),
            backend_pid_kill=host_guard_flag(section, "backend_pid_kill", False),
            worktree_guard=host_guard_flag(section, "worktree_guard", True),
            name_patterns=(
                None
                if "protected_patterns" not in section
                else compile_name_patterns(section.get("protected_patterns"))
            ),
        )
        self._state = _State(
            enabled=True,
            project_root=project_root,
            options=options,
            shell_mismatch=host_guard_flag(section, "shell_mismatch", True),
            whole_line_regex=host_guard_flag(section, "whole_line_regex", False),
            protected_pids=runtime_protected_pids(config),
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
        if state.whole_line_regex:
            # Match the whole line. Segment checks, shell mismatch, process-tree
            # scans, and the stricter worktree parser stay on the other path.
            block = evaluate_whole_line_regex(
                command,
                project_root=state.project_root,
                worktree_guard=state.options.worktree_guard and name in _HOST_GUARD_SHELL_TOOLS,
                protected_pids=(
                    None if state.protected_pids is None else set(state.protected_pids)
                ),
            )
            if block is None:
                return None
            return PermissionResult(
                permission=PermissionLevel.DENY,
                matched_rule="host_guard:whole_line_regex",
                reason=block,
            )
        if state.shell_mismatch and name == "bash":
            mismatch = shell_mismatch(name, command)
            if mismatch is not None:
                return PermissionResult(
                    permission=PermissionLevel.DENY,
                    matched_rule="host_guard:shell_mismatch",
                    reason=mismatch,
                )
        guard_options = state.options
        if name not in _HOST_GUARD_SHELL_TOOLS:
            # Kill checks stay; worktree stays off. Name rules must be copied
            # or a caller protected_patterns list is dropped and the built-in
            # names come back.
            guard_options = replace(state.options, worktree_guard=False)
        block = evaluate_host_guard(
            command,
            project_root=state.project_root,
            options=guard_options,
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
