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
from .safety import (
    HostGuardOptions,
    PidKillMode,
    WorktreeParser,
    compile_name_patterns,
    evaluate_host_guard,
)
from .shell_mismatch import shell_mismatch

# Original hooks are the bash tool, the powershell tool, and mcp_exec_command.
# core.powershell is the engine name of that powershell tool. sh, zsh, cmd and
# create_terminal are command routes, but the original hooks did not patch
# them, so the same kill text is allowed there.
_HOST_GUARD_SHELL_TOOLS = frozenset({"bash", "powershell", "core.powershell"})
_HOST_GUARD_SAFETY_TOOLS = _HOST_GUARD_SHELL_TOOLS | frozenset({"mcp_exec_command"})
_CONTINUATION_SHELLS = frozenset({"bash", "sh", "powershell", "cmd"})


def _reject_removed_host_guard_keys(section: Mapping[str, object]) -> None:
    """Fail closed when a caller still sends a removed switch."""

    if "whole_line_regex" in section:
        raise ValueError(
            "host_guard.whole_line_regex has been removed; "
            "use process_image_kill, pid_kill, segment_guard, "
            "join_continuations, and worktree_parser"
        )
    if "backend_pid_kill" in section:
        raise ValueError(
            "host_guard.backend_pid_kill has been removed; "
            "set pid_kill to off, self_parent, or backend"
        )


def _pid_kill_mode(section: Mapping[str, object]) -> PidKillMode:
    raw = section.get("pid_kill", "off")
    if raw == "off" or raw == "self_parent" or raw == "backend":
        return raw
    raise ValueError("host_guard.pid_kill must be off, self_parent, or backend")


def _worktree_parser(section: Mapping[str, object]) -> WorktreeParser:
    raw = section.get("worktree_parser", "strict")
    if raw == "strict" or raw == "loose":
        return raw
    raise ValueError("host_guard.worktree_parser must be strict or loose")


@dataclass(frozen=True, slots=True)
class _State:
    enabled: bool
    project_root: Path | None
    options: HostGuardOptions
    shell_mismatch: bool


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
    """Block host-killing shell commands. Callers compose the switches below.

    ``mcp_exec_command`` keeps the kill checks and does not run the worktree
    check. ``sh``, ``zsh``, ``cmd``, and ``create_terminal`` are not hooked.

    Switches (``host_guard`` section):

    - ``enabled`` (default false).
    - ``shell_mismatch`` (default true). The bash tool rejects PowerShell.
    - ``python_name_kill`` (default false). Kill Python by name, including
      ``kill python`` and wmic by interpreter name. This does not block
      ``node``, ``py.exe``, ``taskkill /FI IMAGENAME``, or a pipeline that
      names no process. It runs only when ``segment_guard`` is true.
    - ``segment_guard`` (default true). Per-segment Rule 1 blocks a kill
      command that names jiuwenswarm or jiuwenclaw. Rule 2 is
      ``python_name_kill``. The whole-line caller turns this off.
    - ``process_image_kill`` (default false). ``taskkill /im`` and
      ``Stop-Process -Name`` for python, node, jiuwenswarm, and jiuwenclaw;
      ``pkill`` / ``killall`` of python; Get-Process combined with
      Stop-Process even when no image name is given.
    - ``join_continuations`` (default true). Join bash ``\\``, PowerShell
      backtick, and cmd ``^`` line continuations before matching.
    - ``pid_kill`` (default ``off``). ``off`` checks no pid. ``self_parent``
      blocks ``taskkill /pid`` and ``Stop-Process -Id`` aimed at this process
      and its direct parent. ``backend`` blocks a wider set of kill spellings
      aimed at this process, its ancestors, and processes started as the
      backend. Who is protected is nested. The command spellings are not:
      ``self_parent`` does not accept ``kill <pid>``.
    - ``worktree_guard`` (default true).
    - ``worktree_parser`` (default ``strict``). ``strict`` requires a real
      ``git worktree add`` and refuses one it cannot parse. ``loose`` takes
      the first path after the words ``worktree add``, blocks that path when
      it leaves the project, and allows the command when parsing fails.
    - ``protected_patterns``. Omit it to keep the built-in product-name
      floor. A list replaces that floor only. It does not remove Rule 1.

    ``runtime.protected_pids`` is read only when ``pid_kill`` is
    ``self_parent``. A present list replaces the local pid and parent.
    Omit the key to read them in this process. ``backend`` ignores the list
    and scans processes itself.

    Combinations. Unlisted switches stay at the defaults above.

    Xiaoyi::

        shell_mismatch: true
        python_name_kill: true
        process_image_kill: false
        segment_guard: true
        join_continuations: true
        pid_kill: off
        worktree_guard: true
        worktree_parser: strict

    dev-stable. This is the old whole-line check. It does not run segment
    rules, does not join continuations, and uses the loose worktree parser::

        shell_mismatch: false
        python_name_kill: false
        process_image_kill: true
        segment_guard: false
        join_continuations: false
        pid_kill: self_parent
        worktree_guard: true
        worktree_parser: loose

    Develop (open source)::

        shell_mismatch: false
        python_name_kill: true
        process_image_kill: false
        segment_guard: true
        join_continuations: true
        pid_kill: backend
        worktree_guard: true
        worktree_parser: strict
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
        enabled_raw = section.get("enabled", False)
        if not isinstance(enabled_raw, bool):
            raise TypeError("host_guard.enabled must be a boolean")
        enabled = enabled_raw
        if not enabled:
            self._state = None
            return
        _reject_removed_host_guard_keys(section)
        project_root = runtime_workspace_root(config)
        options = HostGuardOptions(
            python_name_kill=host_guard_flag(section, "python_name_kill", False),
            process_image_kill=host_guard_flag(section, "process_image_kill", False),
            segment_guard=host_guard_flag(section, "segment_guard", True),
            join_continuations=host_guard_flag(section, "join_continuations", True),
            pid_kill=_pid_kill_mode(section),
            worktree_guard=host_guard_flag(section, "worktree_guard", True),
            worktree_parser=_worktree_parser(section),
            name_patterns=(
                None
                if "protected_patterns" not in section
                else compile_name_patterns(section.get("protected_patterns"))
            ),
            protected_pids=runtime_protected_pids(config),
        )
        self._state = _State(
            enabled=True,
            project_root=project_root,
            options=options,
            shell_mismatch=host_guard_flag(section, "shell_mismatch", True),
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
