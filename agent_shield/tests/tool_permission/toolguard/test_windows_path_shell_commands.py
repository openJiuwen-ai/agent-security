# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""PowerShell tool + Windows-style quoted paths: trailing ``\\`` must not false-escalate."""

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel
from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.models import PermissionResult

_PS_ALLOW = {
    "tools": {"powershell": "allow"},
    "shell_allowlist": None,
}


def _check(command: str) -> PermissionResult:
    engine = PermissionEngine(_PS_ALLOW)
    return asyncio.run(engine.check_permission("powershell", {"command": command}))


@pytest.mark.parametrize(
    "command",
    [
        r'ls -la "C:\...\team-workspace\"',
        r'ls -la "C:\Users\foo\team-workspace\"',
        r'ls -la "C:/Users/foo/team-workspace/"',
    ],
)
def test_ls_windows_workspace_path_allows(command: str) -> None:
    result = _check(command)
    assert result.permission is PermissionLevel.ALLOW


@pytest.mark.parametrize(
    "command",
    [
        r'ls "C:\x\" | head',
        r'ls "C:/x/" | head',
    ],
)
def test_ls_pipe_head_windows_path_allows(command: str) -> None:
    # Benign ``|`` is not an interpreter sink; trailing ``\`` must not lift.
    result = _check(command)
    assert result.permission is PermissionLevel.ALLOW
    assert "interpreter_sink" not in (result.matched_rule or "")
    assert "complex" not in (result.matched_rule or "")


@pytest.mark.parametrize(
    "command",
    [
        r'rm -rf "C:\x\"',
        r'rm -rf "C:/x/"',
    ],
)
def test_rm_rf_windows_path_asks_or_denies(command: str) -> None:
    result = _check(command)
    assert result.permission in (PermissionLevel.ASK, PermissionLevel.DENY)
    assert result.matched_rule
