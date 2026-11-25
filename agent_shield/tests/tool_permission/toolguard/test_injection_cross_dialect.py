# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""bash/UNKNOWN/CMD 入口对 PowerShell 隐藏构造同样拦截（jiuwenswarm#6957）。

方言声明不改变命令文本的语义：bash 入口收到的 PowerShell 载荷在 Windows 上会被
执行侧按语法嗅探改道 powershell.exe 执行（jiuwenswarm ``_looks_like_powershell``），
或 ``powershell.exe -EncodedCommand …`` 本身就是合法 bash 行（嵌套解释器）；
``mcp_exec_command`` 的 ``shell_type`` 来自模型参数、可谎报方言。若按方言声明
只查 bash 规则表（CMD 干脆不查），PowerShell 的隐藏构造全部漏放——issue #6957
的复现路径。

跨方言规则是 PS 表的命令位锚定变体（行首 / ``;`` / ``|`` / ``&`` 之后）：
参数位出现关键词只是普通字符串（``grep iex .``、``git commit -m "…iex…"``、
``sleep 1 & (echo done)``），不得硬 DENY（!145 检视意见）。

#6499 同款载荷走 ``invoke_tool`` 转发的旁路已由 meta-tool 展开修复
（test_permission_meta_tools.py）；本文件覆盖直接调 bash 工具 / 谎报方言的入口。
"""

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel
from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.models import PermissionResult

# issue #6957 的四条 PowerShell 混淆载荷（原样取自复现步骤）。
ISSUE_PAYLOADS = [
    ('iex "Get-Process"', "Invoke-Expression"),
    ("& (Get-Command notepad)", "dynamic call operator"),
    ("powershell.exe -EncodedCommand aABlAGwAbABvAA==", "nested encoded command"),
    ('[ScriptBlock]::Create("Get-Date")', "dynamic ScriptBlock creation"),
]

# tools 全放行 + 关 allowlist + 关包内置规则：让 Injection 组件成为唯一 DENY
# 来源，隔离出组件本体的判定（对齐 test_powershell_benign_and_sink.py 的隔离
# 手法；包内置 tiered 规则的 `\biex\b` 整词松匹配对参数位关键词本就 ask 级
# 拦截，属预存行为，不混入本组件的判定面）。
_TOOL_ALLOW = {
    "tools": {"bash": "allow", "mcp_exec_command": "allow", "powershell": "allow"},
    "shell_allowlist": None,
    "package_builtin_rules": False,
}


def _check(command: str, *, tool: str = "bash", **extra: str) -> PermissionResult:
    engine = PermissionEngine(_TOOL_ALLOW)
    return asyncio.run(engine.check_permission(tool, {"command": command, **extra}))


@pytest.mark.parametrize("command,label", ISSUE_PAYLOADS)
def test_bash_tool_denies_powershell_obfuscation(command: str, label: str) -> None:
    """issue #6957 复现入口：bash 工具直接携带 PowerShell 载荷。"""
    result = _check(command)
    assert result.permission is PermissionLevel.DENY
    assert label in (result.matched_rule or "")


@pytest.mark.parametrize("command,label", ISSUE_PAYLOADS)
def test_unknown_dialect_denies_powershell_obfuscation(command: str, label: str) -> None:
    """mcp_exec_command 不带 shell_type → UNKNOWN 方言，同样不能放行。"""
    result = _check(command, tool="mcp_exec_command")
    assert result.permission is PermissionLevel.DENY
    assert label in (result.matched_rule or "")


@pytest.mark.parametrize("command,label", ISSUE_PAYLOADS)
def test_cmd_dialect_denies_powershell_obfuscation(command: str, label: str) -> None:
    """shell_type=cmd（模型可控参数，可谎报）同样不能放行（!145 检视意见 2）。"""
    result = _check(command, tool="mcp_exec_command", shell_type="cmd")
    assert result.permission is PermissionLevel.DENY
    assert label in (result.matched_rule or "")


@pytest.mark.parametrize(
    "command",
    [
        # 检视意见 1：关键词出现在参数位只是普通字符串，不得硬 DENY。
        "grep -rn iex .",
        'grep -rn "ScriptBlock::Create" .',
        'git commit -m "fix iex bug"',
        "echo Invoke-Expression docs",
        "sleep 1 & (echo done)",
        "echo a & echo b",
        # 常规良性命令。
        "ls -la",
        "echo hello world",
        "grep -r TODO .",
        "git status --short",
        "make build",
        'echo "quoted text"',
    ],
)
def test_bash_tool_benign_keyword_arguments_still_allow(command: str) -> None:
    result = _check(command)
    assert result.permission is PermissionLevel.ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "dir",
        "dir | findstr foo",
        "echo a & echo b",
    ],
)
def test_cmd_dialect_benign_commands_still_allow(command: str) -> None:
    result = _check(command, tool="mcp_exec_command", shell_type="cmd")
    assert result.permission is PermissionLevel.ALLOW


@pytest.mark.parametrize(
    "command",
    [
        "echo `whoami`",
        "echo $(whoami)",
        "cat <(ls)",
    ],
)
def test_bash_tool_posix_injection_still_denies(command: str) -> None:
    """POSIX 自身的隐藏构造在新规则表下保持原有拦截。"""
    result = _check(command)
    assert result.permission is PermissionLevel.DENY
