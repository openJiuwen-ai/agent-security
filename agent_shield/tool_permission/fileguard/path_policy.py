# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Path-tool helpers shared by file_guard and path_extract."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..models import PermissionLevel

_PATH_TOOLS = frozenset({
    "read_file", "write_file", "edit_file",
    "read_text_file", "write_text_file",
    "write", "read",
    "glob_file_search", "glob", "list_dir", "list_files",
    "grep", "search_replace",
})

_PATH_ARG_KEYS = frozenset({
    "path", "file_path", "target_file", "file", "old_path", "new_path",
    "source_path", "dest_path", "directory", "dir",
})

_STRICT_ORDER = {
    PermissionLevel.DENY: 0,
    PermissionLevel.ASK: 1,
    PermissionLevel.UNDETERMINED: 2,
    PermissionLevel.ALLOW: 3,
}


def strictest(*levels: PermissionLevel) -> PermissionLevel:
    if not levels:
        return PermissionLevel.ASK
    return min(levels, key=lambda level: _STRICT_ORDER[level])


def _tool_arg_value_looks_like_path(arg_key: str, value: str) -> bool:
    if arg_key in _PATH_ARG_KEYS:
        return True
    if "/" in value or "\\" in value:
        return True
    return len(value) > 1 and value[1] == ":"


def _iter_path_strings(_tool_name: str, tool_args: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for key, value in tool_args.items():
        if not isinstance(value, str) or not value.strip():
            continue
        if _tool_arg_value_looks_like_path(key, value):
            out.append(value.strip())
    return out


__all__ = ["_PATH_TOOLS", "_iter_path_strings", "strictest"]
