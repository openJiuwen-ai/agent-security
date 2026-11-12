# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""批量删除计数估算器（Pipeline D，删除数量防护）。

在 shell 类工具执行前，对命令里的删除目标做静态解析 + 文件系统递归计数，
用于把「一次调用删除大量文件」抬升为 ASK。

计数语义（对齐设计文档 §4.2）：

- 普通文件 / 符号链接 / 目录连接点（junction）：计 1（不追踪指向，指向目录也按 1 计）。
  操作数带尾部分隔符（``rm -rf link/``）时，保守递归统计目标目录内容，
  避免按链接本体低估可能的删除范围。
- 目录：不统计目录节点自身，递归统计其内部的「文件 + 链接 + 子目录内容」。
- 空目录：计 0。
- 同一调用内多条删除命令（``rm a && rm -rf b``、``Remove-Item a; Remove-Item b``）
  的计数累加，并按绝对路径去重。路径只做规范化和拼接，不调用 ``resolve()``：
  解析会把链接替换成目标，导致链接身份丢失、目标目录被展开计数。
"""

from __future__ import annotations

import fnmatch
import glob as _glob
import os
import re
import stat as _stat
from collections.abc import Iterable
from pathlib import Path
from typing import Any

# 删除命令按 shell 归类。
_BASH_DELETE_CMDS = frozenset({"rm", "unlink"})
_CMD_DELETE_CMDS = frozenset({"del", "erase", "rd", "rmdir"})
_PS_DELETE_CMDS = frozenset({"remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"})


class _DeletionCountIncompleteError(ValueError):
    """Shell analysis or filesystem enumeration cannot provide a complete count."""


# ReFS/NTFS 的目录连接点（junction）不一定是 S_ISLNK，必须看 reparse 属性。
_FILE_ATTRIBUTE_REPARSE_POINT = getattr(_stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

# 递归 / 强制标志只影响语义，不影响目标抽取；这里保留用于注释说明，不参与过滤。
_RECURSIVE_FLAGS = frozenset({"-r", "-r", "-rf", "-fr", "-R", "--recursive", "-recurse", "/s"})

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


def _lexical_path(path: Path) -> Path:
    """Normalize cwd/operands without replacing a link with its target."""
    return Path(os.path.normpath(os.path.abspath(path)))


def _is_link_like(path: str | os.PathLike[str], info: os.stat_result | None = None) -> bool:
    """符号链接 / 目录连接点判定。不跟随目标；悬空链接也返回 True。"""
    try:
        info = info if info is not None else os.lstat(path)
    except OSError:
        return False
    if _stat.S_ISLNK(info.st_mode):
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT)


def _glob_targets(base: Path, parts: tuple[str, ...]) -> Iterable[Path]:
    """Use standard glob matching, but never suppress directory read errors.

    glob.glob() silently skips scandir failures. That would turn an incomplete
    deletion range into an empty or smaller list before counting even starts.
    """
    try:
        if not parts:
            os.lstat(base)
            yield base
            return
        pattern, *rest = parts
        if not _glob.has_magic(pattern):
            yield from _glob_targets(base / pattern, tuple(rest))
            return
        recursive = pattern == "**"
        if recursive:
            yield from _glob_targets(base, tuple(rest))
        with os.scandir(base) as entries:
            for entry in entries:
                if entry.name.startswith(".") and not pattern.startswith("."):
                    continue
                if recursive:
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    if _is_link_like(entry.path, info):
                        if entry.is_dir():
                            raise _DeletionCountIncompleteError("Recursive deletion glob reaches a directory link")
                    elif _stat.S_ISDIR(info.st_mode):
                        yield from _glob_targets(Path(entry.path), parts)
                        continue
                    if not rest:
                        yield Path(entry.path)
                elif fnmatch.fnmatch(entry.name, pattern):
                    yield from _glob_targets(Path(entry.path), tuple(rest))
    except (FileNotFoundError, NotADirectoryError):
        return


def _expand_target(raw: str, base: Path | None, shell_type: str) -> list[Path]:
    """展开操作数：绝对/相对路径 + glob。返回实际存在的候选绝对路径。

    叶子路径一般保持原样（链接就是链接），不做 ``resolve()``：删除链接只删链接
    本体，把链接替换成目标会让计数对象和审批列表都变成另一个路径。带尾部分隔符
    的链接是例外，见下方分支注释。
    """
    from ..fileguard.path_extract import _resolve_shell_operand

    # 尾部分隔符会被 normpath 抹掉，先记录并保守计目标目录内容。
    # 不承诺所有 Shell 的执行行为相同，也不把这种候选当作访问授权。
    trailing_sep = raw.strip().strip('"').strip("'").endswith(("/", "\\"))
    candidate = _resolve_shell_operand(raw, base, shell_type, bare=True, resolve_path=_lexical_path)
    if candidate is None or _UNEXPANDED_VAR_RE.search(str(candidate)):
        raise _DeletionCountIncompleteError("Deletion target could not be resolved")
    has_glob = any(c in str(candidate) for c in ("*", "?", "["))

    if not has_glob:
        # ``lstat`` 能捕捉到悬空链接，``exists`` 不能。
        try:
            info = os.lstat(candidate)
        except FileNotFoundError:
            return []
        if trailing_sep and _is_link_like(candidate, info):
            # 计数对象换成链接的目标目录：_entry_cost 对目录递归计内容数，
            # 与实际删除范围一致；否则只计 1 会让达阈值的批量删除静默放行。
            return [Path(os.path.realpath(candidate))]
        return [candidate]

    # glob 特殊字符（* ? [）在 Windows 文件名中非法，出现即视为通配意图；
    # 直接以候选为 pattern 展开（不 escape/replace，避免破坏通配符）。
    return list(_glob_targets(Path(candidate.anchor), candidate.parts[1:]))


def _entry_cost(path: Path) -> int:
    """递归计数：文件/链接 = 1，目录不自身计，递归内部文件 + 链接 + 子目录。"""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return 0
    # 链接/连接点删的是本体，目标目录内容不会被删除，因此只计 1 且不展开。
    if _is_link_like(path, info):
        return 1
    if _stat.S_ISREG(info.st_mode):
        return 1
    if not _stat.S_ISDIR(info.st_mode):
        return 0
    cost = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                try:
                    child_info = entry.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if _is_link_like(entry.path, child_info) or _stat.S_ISREG(child_info.st_mode):
                    cost += 1
                elif _stat.S_ISDIR(child_info.st_mode):
                    cost += _entry_cost(Path(entry.path))
                # 其它（套接字/FIFO/设备）不计
    except OSError as exc:
        raise _DeletionCountIncompleteError(f"Deletion directory scan incomplete: {path}") from exc
    return cost


def count_deletion_targets(
    command: str,
    shell_type: str,
    workdir: str | Path | None,
) -> tuple[int, list[str]]:
    """估算一次 shell 调用删除的文件/符号链接数。

    Returns:
        ``(count, hit_paths)``：``count`` 为去重后的累计删除计数；``hit_paths``
        为命中的顶层目标绝对路径（供审批展示）。Shell 分析、目标读取或目录扫描
        不完整时抛 ValueError 子类，Guard 入口转为审批，不返回偏小的部分计数。
    """
    if not command or not isinstance(command, str):
        return 0, []
    # Lazy import: path extraction also reuses split_shell_operands above.
    from ..fileguard.path_extract import _execution_tokens, _segment_tokens, _walk_shell_segments

    seen: set[str] = set()
    hit_paths: list[str] = []
    try:
        base = _lexical_path(Path(workdir)) if workdir else Path.cwd()
        for segment, cwd, profile in _walk_shell_segments(
            command, base, shell_type=(shell_type or "auto").strip().lower(), resolve_path=_lexical_path,
        ):
            tokens, _ = _segment_tokens(segment, profile)
            tokens = _execution_tokens(tokens, profile)
            if not tokens:
                continue
            cmd0 = _basename_lower(tokens[0].strip('"').strip("'"))
            if cmd0 not in _delete_cmds_for(profile):
                continue
            for token in tokens[1:]:
                for operand in split_shell_operands(token, shell_type=profile, cmd0=cmd0):
                    for candidate in _expand_target(operand, cwd, profile):
                        key = os.path.normcase(os.path.normpath(str(candidate)))
                        if key in seen:
                            continue
                        seen.add(key)
                        hit_paths.append(str(candidate))

        count = sum(_entry_cost(Path(path)) for path in hit_paths)
    except (OSError, ValueError, RuntimeError) as exc:
        raise _DeletionCountIncompleteError(f"Deletion count incomplete: {exc}") from exc
    return count, hit_paths


__all__ = ["count_deletion_targets", "_entry_cost"]


def _iter_flags_for_tests() -> Iterable[Any]:
    """测试辅助：暴露内部常量供单测断言覆盖。"""
    return (_BASH_DELETE_CMDS, _CMD_DELETE_CMDS, _PS_DELETE_CMDS)
