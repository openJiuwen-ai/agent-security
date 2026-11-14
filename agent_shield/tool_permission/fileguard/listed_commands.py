# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""read_deny_only adapter over the shared ``path_extract`` core.

Does not reimplement shell path extraction. Differences from the default
native entry are only:

- shell tools outside ``LISTED_SHELL_TOOLS`` yield no paths (powershell skipped)
- ``glob`` judges the ``pattern`` argument as a path (listed contract)
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal

from .path_extract import extract_accesses_native as _extract_accesses_native
from .tool_categories import is_shell_tool

FileAction = Literal["read", "write", "exec"]

LISTED_SHELL_TOOLS = frozenset({"mcp_exec_command", "bash", "create_terminal"})


def _resolve_path_str(raw: str, workspace: Path) -> Path | None:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return None
    try:
        path = Path(os.path.expandvars(os.path.expanduser(raw)))
        if not path.is_absolute():
            path = (workspace / path).resolve()
        else:
            path = path.resolve()
        return path
    except (OSError, RuntimeError):
        return None


def extract_accesses_native(
    tool_name: str,
    tool_args: Mapping[str, Any],
    workspace: Path,
) -> list[tuple[Path, FileAction, str]]:
    """Native accesses under the read_deny_only tool filter."""
    if is_shell_tool(tool_name) and tool_name not in LISTED_SHELL_TOOLS:
        return []

    # Listed contract: treat glob ``pattern`` as the path being judged.
    if tool_name == "glob":
        raw = tool_args.get("pattern")
        if not isinstance(raw, str) or not raw.strip():
            return []
        resolved = _resolve_path_str(raw, workspace)
        return [(resolved, "read", "tool_arg")] if resolved is not None else []

    return _extract_accesses_native(tool_name, tool_args, workspace)


def extract_paths_legacy(
    tool_name: str,
    tool_args: Mapping[str, Any],
    workspace: Path,
) -> list[Path]:
    """Path-only view of the listed native extractor."""
    paths: list[Path] = []
    for path, _action, _source in extract_accesses_native(
        tool_name, tool_args, workspace,
    ):
        paths.append(path)
    return paths


__all__ = [
    "LISTED_SHELL_TOOLS",
    "extract_accesses_native",
    "extract_paths_legacy",
]
