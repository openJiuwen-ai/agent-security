# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

_DEFAULT_SHELL_TOOLS = frozenset({
    "bash",
    "powershell",
    "core.powershell",
    "mcp_exec_command",
    "create_terminal",
})
_CATEGORY_SHELL = "shell"


def shell_tools_from_config(permission_config: Mapping[str, Any] | None) -> frozenset[str]:
    raw = (permission_config or {}).get("categories")
    names = raw.get("shell") if isinstance(raw, dict) else None
    if isinstance(names, list) and any(isinstance(n, str) and n.strip() for n in names):
        return frozenset(n.strip() for n in names if isinstance(n, str) and n.strip())
    return _DEFAULT_SHELL_TOOLS


def is_shell_tool(tool_name: str, shell_tools: Iterable[str] | None = None) -> bool:
    names = _DEFAULT_SHELL_TOOLS if shell_tools is None else frozenset(shell_tools)
    return (tool_name or "") in names


__all__ = [
    "_CATEGORY_SHELL",
    "_DEFAULT_SHELL_TOOLS",
    "is_shell_tool",
    "shell_tools_from_config",
]
