# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Command-injection detection for POSIX shell and PowerShell tools.

The patterns, labels and first-hit semantics are carried over unchanged from the
original ``check_injection`` of the bash and PowerShell tools (identical on every
branch); only the call shape is adapted to the permission component protocol.

POSIX/UNKNOWN/CMD 方言的路由同时套命令位锚定的 PowerShell 规则（jiuwenswarm#6957）：
bash 入口收到 PowerShell 载荷时执行侧并不按 bash 语义执行，方言声明可谎报，
静态审查不能因方言声明放行。
"""

from __future__ import annotations

from collections.abc import Mapping
import re

from ..models import PermissionLevel, PermissionResult
from ..routing import CandidateKind, CommandDialect, RouteContext

Rule = tuple[re.Pattern[str], str]

_BACKTICK_RE = re.compile(r"(?<!')`[^`]+`")
_DOLLAR_PAREN_RE = re.compile(r"\$\(")
_PROC_SUBST_RE = re.compile(r"[<>]\(")

_POSIX_RULES: tuple[Rule, ...] = (
    (_BACKTICK_RE, "backtick command substitution"),
    (_DOLLAR_PAREN_RE, "$() command substitution"),
    (_PROC_SUBST_RE, "process substitution <() or >()"),
)
_POWERSHELL_RULES: tuple[Rule, ...] = (
    (re.compile(r"(?i)\b(?:invoke-expression|iex)\b"), "Invoke-Expression"),
    (
        re.compile(r"(?i)\b(?:powershell|powershell\.exe|pwsh|pwsh\.exe)\b[^\n]*-encodedcommand\b"),
        "nested encoded command",
    ),
    (re.compile(r"(^|[\s;(])&\s*(?:\(|\$)"), "dynamic call operator"),
    (re.compile(r"(?i)\[scriptblock\]::create\s*\("), "dynamic ScriptBlock creation"),
)
# 跨方言规则 = PS 表的命令位锚定变体（背景与 issue 引用见模块 docstring）：
# 非 PowerShell 方言的命令里，PS 构造出现在命令位（行首 / ``;`` / ``|`` / ``&``
# 之后）才是「将要执行的东西」，参数位只是普通字符串（``grep iex .``），整词
# 松匹配会把这类良性命令硬 DENY。PowerShell 方言自身保持松匹配：PS 代码的
# 命令出现在管道、脚本块等多种位置，锚定过严。引号内嵌套载荷（powershell
# -Command "iex …"）不经本组件，由结构组件 sink 与内置规则兜底。
_CROSS_DIALECT_PS_RULES: tuple[Rule, ...] = (
    (
        re.compile(r"(?i)(^|[;\n|&])\s*(?:invoke-expression|iex)\b"),
        "Invoke-Expression",
    ),
    (
        re.compile(r"(?i)(^|[;\n|&])\s*(?:powershell|pwsh)(?:\.exe)?\b[^\n]*-encodedcommand\b"),
        "nested encoded command",
    ),
    (re.compile(r"(^|[;\n])\s*&\s*(?:\(|\$)"), "dynamic call operator"),
    (
        re.compile(r"(?i)(^|[;\n|&])\s*\[scriptblock\]::create\s*\("),
        "dynamic ScriptBlock creation",
    ),
)
_POSIX_SHELL_RULES: tuple[Rule, ...] = _POSIX_RULES + _CROSS_DIALECT_PS_RULES


class InjectionComponent:
    """Block shell syntax that hides a command from static inspection."""

    @staticmethod
    def configure(config: Mapping[str, object]) -> None:
        """Accept the complete engine config; the patterns are code-defined."""
        del config

    async def evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, object],
        *,
        route: RouteContext | None = None,
    ) -> PermissionResult | None:
        """Evaluate the command with the pattern table selected by ``route``."""
        del tool_name
        if route is None or not route.is_shell:
            return None
        # Structure / injection is about the whole view, not each leaf.
        if route.kind is CandidateKind.SUBCOMMAND:
            return None
        raw = tool_args.get("command")
        command = raw if isinstance(raw, str) else ""
        # UNKNOWN (e.g. mcp_exec_command without shell_type) uses the bash AST
        # for split; apply POSIX injection too so $() / <() are not fail-open
        # after structure stopped lifting on substitution.
        if route.command_dialect in (
            CommandDialect.POSIX_SHELL,
            CommandDialect.UNKNOWN,
        ):
            # bash 入口收到的 PowerShell 载荷同样要按 PS 规则审（命令位锚定，
            # 见 _CROSS_DIALECT_PS_RULES 注释）。
            rules, kind = _POSIX_SHELL_RULES, "Shell"
        elif route.command_dialect is CommandDialect.POWERSHELL:
            rules, kind = _POWERSHELL_RULES, "PowerShell"
        elif route.command_dialect is CommandDialect.CMD:
            # cmd 没有 bash 的 $() / 反引号 / <()，POSIX 表不适用；但 PS 构造
            # 经 cmd 同样危险：powershell.exe 能从 cmd 启动（嵌套解释器），且
            # 通用入口（mcp_exec_command）的 shell_type 来自模型参数、可谎报
            # 方言——命令位的 PS 构造按 fail-closed 审（检视意见：shell_type=
            # "cmd" 复现 #6957 的 fail-open 路径）。
            rules, kind = _CROSS_DIALECT_PS_RULES, "Shell"
        else:
            return None
        for pattern, label in rules:
            if pattern.search(command):
                return PermissionResult(
                    permission=PermissionLevel.DENY,
                    matched_rule=label,
                    reason=f"{kind} injection detected: {label}",
                )
        return PermissionResult(permission=PermissionLevel.ALLOW)


__all__ = ["InjectionComponent"]
