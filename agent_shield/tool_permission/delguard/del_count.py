# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""批量删除计数估算器（Pipeline D，删除数量防护）。

在 shell 类工具执行前，对命令里的删除目标做静态解析 + 文件系统递归计数，
用于把「一次调用删除大量文件」抬升为 ASK。

计数语义（对齐设计文档 §4.2）：

- 普通文件 / 符号链接：计 1（符号链接不追踪其指向，指向目录也按 1 计）。
- 目录：不统计目录节点自身，递归统计其内部的「文件 + 符号链接」。
- 空目录：计 0。
- 同一调用内多条删除命令（``rm a && rm -rf b``、``Remove-Item a; Remove-Item b``）
  的计数累加，并按 ``resolve()`` 后的绝对路径去重。
"""

from __future__ import annotations

import glob as _glob
import os
import re
import shlex
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from ..toolguard.command_canonicalize import (
    canonicalize_shell_command_for_permission,
)
from ..toolguard.shell_ast import parse_shell_for_permission

# 删除命令按 shell 归类。
_BASH_DELETE_CMDS = frozenset({"rm", "unlink"})
_CMD_DELETE_CMDS = frozenset({"del", "erase", "rd", "rmdir"})
_PS_DELETE_CMDS = frozenset({"remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"})

# 递归 / 强制标志只影响语义，不影响目标抽取；这里保留用于注释说明，不参与过滤。
_RECURSIVE_FLAGS = frozenset({"-r", "-r", "-rf", "-fr", "-R", "--recursive", "-recurse", "/s"})

# 拆分链式命令：`;`、`&&`、`||`、以及幂等断开用的换行。
_SEGMENT_SPLIT_RE = re.compile(r"(?:\r?\n|&&|\|\||;)")

# 未展开变量外壳（例如 ``$x`` / ``${x}`` / ``%VAR%``）。
_UNEXPANDED_VAR_RE = re.compile(r"\$(\w+|\{[^}]+\})|%\w+%")

# ``'a','b'`` / ``"a","b"``：引号之间的逗号才是 PowerShell 列表分隔，引号内逗号不是。
_QUOTED_LIST_GAP_RE = re.compile(r"""['"]\s*,\s*['"]""")


def _basename_lower(cmd: str) -> str:
    base = Path(cmd.replace("\\", "/")).name.lower()
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _delete_cmds_for(shell_type: str) -> frozenset[str]:
    st = (shell_type or "auto").strip().lower()
    if st in {"cmd", "dos"}:
        return _CMD_DELETE_CMDS
    if st in {"powershell", "pwsh", "ps"}:
        return _PS_DELETE_CMDS
    return _BASH_DELETE_CMDS | _CMD_DELETE_CMDS | _PS_DELETE_CMDS


def _segments(command: str) -> list[str]:
    """把复合命令拆成独立命令段，优先树 sitter，退化为分隔符启发式。"""
    text = canonicalize_shell_command_for_permission((command or "").strip())
    if not text:
        return []
    parsed = parse_shell_for_permission(text)
    subs = [sc.text.strip() for sc in (parsed.subcommands or ()) if sc.text and sc.text.strip()]
    if len(subs) >= 2:
        return subs
    heuristic = [p.strip() for p in _SEGMENT_SPLIT_RE.split(text) if p.strip()]
    if len(heuristic) >= 2:
        return heuristic
    if subs:
        return subs
    return [text]


def _split_tokens(segment: str) -> list[str]:
    try:
        return shlex.split(segment.strip(), posix=False)
    except ValueError:
        return segment.strip().split()


def _is_flag(token: str, *, shell_type: str = "") -> bool:
    """``-r`` / ``--force`` 始终是旗标。

    ``/f``、``/s``、``/q`` 这种单词开关只在 cmd.exe 下丢弃。``/tmp``、``/etc``、
    ``/opt``、``/data`` 是单层 POSIX 路径，不能用同一条正则静默吞掉。
    """
    t = token.strip().strip('"').strip("'")
    if not t:
        return True
    if t.startswith("-"):
        return True
    if (shell_type or "").strip().lower() in {"cmd", "dos"} and re.match(
        r"^/[A-Za-z][A-Za-z0-9]*$", t
    ):
        return True
    return False


def _peel_shlex_comma(token: str) -> str:
    """去掉 ``shlex(posix=False)`` 粘在下一参数上的前导逗号（``,'b'``）。"""
    raw = token.strip()
    while raw.startswith(","):
        nxt = raw[1:].lstrip()
        if not nxt:
            return ""
        if (
            nxt[0] in "\"'"
            or re.match(r"^[A-Za-z]:[\\/]", nxt)
            or nxt.startswith(("\\\\", "./", "../", "/", "\\"))
        ):
            raw = nxt
            continue
        break
    return raw


def _split_unquoted_commas(token: str) -> list[str]:
    """按引号外的逗号拆分；引号内逗号保留（``'foo,bar.txt'`` 仍是一个路径）。"""
    parts: list[str] = []
    buf: list[str] = []
    quote = ""
    i = 0
    while i < len(token):
        ch = token[i]
        if quote:
            if quote == "'" and token.startswith("''", i):
                buf.append("'")
                i += 2
                continue
            buf.append(ch)
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "\"'":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == ",":
            part = "".join(buf).strip()
            if part:
                parts.append(part)
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    tail = "".join(buf).strip()
    if tail:
        parts.append(tail)
    return parts


def split_shell_operands(token: str, *, shell_type: str, cmd0: str) -> list[str]:
    """把一个 shell 词展开成删除/路径操作数。

    PowerShell 的 ``Remove-Item a,b`` 和 ``'a','b'`` 是多个目标。``shlex(posix=False)``
    会把逗号粘到后一个带引号参数上（``,'b'``），这里先剥掉再按引号外逗号拆开。
    bash 的普通 ``rm`` 不把文件名里的逗号当成分隔符。
    """
    if _is_flag(token, shell_type=shell_type):
        return []
    peeled = _peel_shlex_comma(token)
    if not peeled or _is_flag(peeled, shell_type=shell_type):
        return []
    st = (shell_type or "auto").strip().lower()
    split = (
        st in {"powershell", "pwsh", "ps"}
        or cmd0 in {"remove-item", "ri"}
        or bool(_QUOTED_LIST_GAP_RE.search(peeled))
    )
    if split and "," in peeled:
        return [
            part for part in _split_unquoted_commas(peeled)
            if part and not _is_flag(part, shell_type=shell_type)
        ]
    return [peeled]


def _expand_target(raw: str, base: Path) -> list[Path]:
    """展开操作数：绝对/相对路径 + glob。返回实际存在的候选绝对路径。"""
    raw = raw.strip().strip('"').strip("'")
    if not raw or _UNEXPANDED_VAR_RE.search(raw):
        return []
    expanded = os.path.expandvars(os.path.expanduser(raw))
    has_glob = any(c in expanded for c in ("*", "?", "["))
    try:
        p = Path(expanded)
        candidate = p if p.is_absolute() else base / p
    except (OSError, ValueError):
        return []

    if not has_glob:
        try:
            resolved = candidate.resolve(strict=False)
        except (OSError, ValueError):
            return []
        # 只有真实存在（或能被 os.lstat 捕捉到，例如破坏性 symlink）的路径才计数。
        try:
            os.lstat(resolved)
        except OSError:
            return []
        return [resolved]

    # glob 特殊字符（* ? [）在 Windows 文件名中非法，出现即视为通配意图；
    # 直接以候选为 pattern 展开（不 escape/replace，避免破坏通配符）。
    try:
        matches = _glob.glob(str(candidate), recursive=True)
    except Exception:  # noqa: BLE001 - 任何 glob 异常都不应抬升误判
        return []
    out: list[Path] = []
    for m in matches:
        try:
            out.append(Path(m).resolve(strict=False))
        except (OSError, ValueError):
            continue
    return out


def _entry_cost(path: Path) -> int:
    """递归计数：文件/符号链接 = 1，目录不自身计，递归内部文件+符号链接。"""
    try:
        if path.is_symlink():
            return 1
        if path.is_file():
            return 1
        if not path.is_dir():
            return 0
        cost = 0
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    child = Path(entry.path)
                except (OSError, ValueError):
                    continue
                if entry.is_symlink() or entry.is_file():
                    cost += 1
                elif entry.is_dir():
                    cost += _entry_cost(child)
                # 其它（套接字/FIFO/设备）不计
        return cost
    except OSError:
        return 0


def count_deletion_targets(
    command: str,
    shell_type: str,
    workdir: str | Path | None,
) -> tuple[int, list[str]]:
    """估算一次 shell 调用删除的文件/符号链接数。

    Returns:
        ``(count, hit_paths)``：``count`` 为去重后的累计删除计数；``hit_paths``
        为命中的顶层目标绝对路径（供审批展示）。无法可靠估算时返回 ``(0, [])``，
        由调用方按 fail-open 处理。
    """
    if not command or not isinstance(command, str):
        return 0, []
    try:
        base = Path(workdir).resolve() if workdir else Path.cwd().resolve()
    except (OSError, ValueError):
        base = Path.cwd().resolve()

    delete_cmds = _delete_cmds_for(shell_type)
    seen: set[str] = set()
    hit_paths: list[str] = []

    for segment in _segments(command):
        tokens = _split_tokens(segment)
        if not tokens:
            continue
        cmd0 = _basename_lower(tokens[0].strip('"').strip("'"))
        if cmd0 not in delete_cmds:
            continue
        operands: list[str] = []
        for tok in tokens[1:]:
            operands.extend(split_shell_operands(tok, shell_type=shell_type, cmd0=cmd0))
        for tok in operands:
            for candidate in _expand_target(tok, base):
                key = str(candidate)
                if key in seen:
                    continue
                seen.add(key)
                hit_paths.append(key)

    count = 0
    for key in hit_paths:
        try:
            count += _entry_cost(Path(key))
        except (OSError, ValueError):
            continue
    return count, hit_paths


__all__ = ["count_deletion_targets", "_entry_cost"]


def _iter_flags_for_tests() -> Iterable[Any]:
    """测试辅助：暴露内部常量供单测断言覆盖。"""
    return (_BASH_DELETE_CMDS, _CMD_DELETE_CMDS, _PS_DELETE_CMDS)