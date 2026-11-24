"""Path scope, sensitive globs, and system-catalog membership."""

from __future__ import annotations

import os
import re
from functools import lru_cache

_OS_NAMES = {"windows", "posix"}


def event_os(event: dict) -> str:
    workspace = event.get("workspace") if isinstance(event.get("workspace"), dict) else {}
    name = workspace.get("os") or "posix"
    return name if name in _OS_NAMES else "posix"


def case_insensitive(os_name: str) -> bool:
    return os_name == "windows"


def normalize_path(path: str) -> str:
    text = str(path).replace("\\", "/")
    if text.startswith("//"):
        body = text[2:]
        while "//" in body:
            body = body.replace("//", "/")
        text = os.path.join("//", body.replace("/", os.sep)).replace("\\", "/")
    else:
        while "//" in text:
            text = text.replace("//", "/")
    if len(text) > 1 and text.endswith("/"):
        text = text.rstrip("/")
    return text


def paths_equal(left: str, right: str, *, os_name: str) -> bool:
    a = normalize_path(left)
    b = normalize_path(right)
    if case_insensitive(os_name):
        return a.casefold() == b.casefold()
    return a == b


def is_within(path: str, root: str, *, os_name: str) -> bool:
    if not path or not root:
        return False
    child = normalize_path(path)
    parent = normalize_path(root)
    if not parent:
        return False
    if case_insensitive(os_name):
        child_cmp = child.casefold()
        parent_cmp = parent.casefold()
    else:
        child_cmp = child
        parent_cmp = parent
    return child_cmp == parent_cmp or child_cmp.startswith(parent_cmp + "/")


def workspace_roots(event: dict) -> list[str]:
    workspace = event.get("workspace") if isinstance(event.get("workspace"), dict) else {}
    roots: list[str] = []
    root = workspace.get("root") or ""
    if isinstance(root, str) and root:
        roots.append(root)
    trusted = workspace.get("trusted_dirs") or []
    if isinstance(trusted, list):
        roots.extend(item for item in trusted if isinstance(item, str) and item)
    return roots


def path_scope(path: str, event: dict) -> str:
    os_name = event_os(event)
    if path and any(is_within(path, root, os_name=os_name) for root in workspace_roots(event)):
        return "workspace"
    return "outside"


def final_component(path: str) -> str:
    normalized = normalize_path(path)
    if normalized.endswith("/"):
        normalized = normalized.rstrip("/")
    return normalized.rsplit("/", 1)[-1]


@lru_cache(maxsize=512)
def _glob_regex(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    source = pattern.replace("\\", "/")
    pieces: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith("**/", index):
            pieces.append("(?:.*/)?")
            index += 3
        elif source.startswith("**", index):
            pieces.append(".*")
            index += 2
        elif source[index] == "*":
            pieces.append("[^/]*")
            index += 1
        else:
            pieces.append(re.escape(source[index]))
            index += 1
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("^" + "".join(pieces) + "$", flags)


def glob_match(pattern: str, path: str, *, os_name: str) -> bool:
    if not path:
        return False
    normalized = normalize_path(path)
    ignore_case = case_insensitive(os_name)
    if _glob_regex(pattern, ignore_case).match(normalized):
        return True
    unified = pattern.replace("\\", "/")
    if unified.endswith("/**"):
        base = unified[:-3]
        if _glob_regex(base, ignore_case).match(normalized):
            return True
        if is_within(normalized, base, os_name=os_name):
            return True
    return False


def glob_any(path: str, patterns: tuple[str, ...] | list[str], *, os_name: str) -> bool:
    return any(glob_match(pattern, path, os_name=os_name) for pattern in patterns)


def implicit_windows_prefixes() -> tuple[str, ...]:
    found: list[str] = []
    windir = os.environ.get("WINDIR")
    if windir:
        found.append(windir)
    program_data = os.environ.get("ProgramData")
    if program_data:
        found.append(str(os.path.join(program_data, "Microsoft")))
    return tuple(found)


def in_system_prefixes(path: str, prefixes: tuple[str, ...] | list[str], *, os_name: str) -> bool:
    if not path:
        return False
    normalized = normalize_path(path)
    for prefix in prefixes:
        prefix_norm = normalize_path(prefix)
        if os_name == "posix" and prefix_norm == "/var":
            if is_within(normalized, "/var/tmp", os_name="posix") or normalized == "/var/tmp":
                continue
        if is_within(normalized, prefix, os_name=os_name):
            return True
    return False


def in_system_critical(path: str, entries: tuple[str, ...] | list[str], *, os_name: str) -> bool:
    if not path:
        return False
    normalized = normalize_path(path)
    for entry in entries:
        if _critical_entry_matches(normalized, entry, os_name=os_name):
            return True
    return False


def _critical_entry_matches(path: str, entry: str, *, os_name: str) -> bool:
    if entry.replace("\\", "/").rstrip("/").casefold() == "bootmgr":
        return final_component(path).casefold() == "bootmgr"
    unified = entry.replace("\\", "/")
    if "*" in unified or "?" in unified:
        return glob_match(unified, path, os_name=os_name)
    if entry.endswith("/") or entry.endswith("\\"):
        return is_within(path, unified, os_name=os_name)
    return paths_equal(path, unified, os_name=os_name)
