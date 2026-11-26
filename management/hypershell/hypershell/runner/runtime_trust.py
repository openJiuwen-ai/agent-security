"""Statically audit administrator-controlled runtime trees before executing them.

No target interpreter, import hook, .pth file or application is executed. This
checks ownership, permissions and filesystem links of explicitly supplied roots,
not Python import closure: callers must separately reject/resolve editable
installs and external .pth references before claiming a controlled runtime.
Root can still modify files after this observation; this is not immutability or
an atomic hash-to-execution guarantee.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
import os
from pathlib import Path
import stat
import sys
from typing import Any

from ..console import log_console
from .client import RunnerError

MAX_ROOTS = 64
MAX_SYMLINK_HOPS = 40
_INCOMPLETE = {
    "LINUX_REQUIRED",
    "ADMIN_REQUIRED",
    "INVALID_LIMITS",
    "TOO_MANY_ROOTS",
    "ENTRY_LIMIT",
    "DEPTH_LIMIT",
    "METADATA_UNAVAILABLE",
    "DIRECTORY_UNREADABLE",
    "SYMLINK_UNREADABLE",
    "INVALID_METADATA",
}


def _lstat(path: Path):
    return os.lstat(path)


def _readlink(path: Path) -> str:
    return os.readlink(path)


class _EntryLimit(Exception):
    pass


class _Audit:
    def __init__(self, roots: list[Path], *, max_entries: int, max_depth: int, max_issues: int):
        self.roots = roots
        self.max_entries, self.max_depth, self.max_issues = max_entries, max_depth, max_issues
        self.metadata: dict[Path, Any] = {}
        self.visited: set[tuple[int, int]] = set()
        self.issues: list[dict] = []
        self.issue_count = 0
        self.issue_keys = set()
        self.incomplete = False

    def issue(self, code: str, path: Path | str = "", *, target=None, number=None):
        key = (code, str(path), str(target) if target is not None else None)
        if key in self.issue_keys:
            return
        self.issue_keys.add(key)
        self.issue_count += 1
        self.incomplete |= code in _INCOMPLETE
        if len(self.issues) >= self.max_issues:
            return
        item = {"code": code, "path": str(path)[:4096]}
        if target is not None:
            item["target"] = str(target)[:4096]
        if type(number) is int:
            item["errno"] = number
        self.issues.append(item)

    def inspect(self, path: Path):
        if path in self.metadata:
            return self.metadata[path]
        if len(self.metadata) >= self.max_entries:
            self.issue("ENTRY_LIMIT", path)
            raise _EntryLimit()
        self.metadata[path] = None
        try:
            info = _lstat(path)
        except FileNotFoundError as exc:
            self.issue("PATH_MISSING", path, number=exc.errno)
            return None
        except OSError as exc:
            self.issue("METADATA_UNAVAILABLE", path, number=exc.errno)
            return None
        metadata = (info.st_mode, info.st_uid, info.st_dev, info.st_ino, info.st_nlink)
        if any(type(value) is not int for value in metadata):
            self.issue("INVALID_METADATA", path)
            return None
        valid = True
        if info.st_uid != 0:
            self.issue("NOT_ROOT_OWNED", path)
            valid = False
        # Unix symlink mode is normally 0777 and is not a write permission.
        # Its owner and every containing directory/target are still checked.
        if not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022:
            self.issue("GROUP_WORLD_WRITABLE", path)
            valid = False
        if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)):
            self.issue("SPECIAL_FILE", path)
            valid = False
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            self.issue("HARDLINK_FILE", path)
            valid = False
        if valid:
            self.metadata[path] = info
            return info
        return None

    def inside_root(self, path: Path) -> bool:
        return any(path == root or root in path.parents for root in self.roots)

    def resolve(self, path: Path, active_links=frozenset(), hops=0):
        """Resolve component by component, preserving real symlink/.. semantics."""
        current = Path(path.anchor)
        info = self.inspect(current)
        if info is None:
            return None
        for component in path.parts[1:]:
            if not stat.S_ISDIR(info.st_mode):
                self.issue("NOT_A_DIRECTORY", current)
                return None
            if component == "..":
                current = current.parent
                info = self.inspect(current)
            elif component == ".":
                continue
            else:
                candidate = current / component
                info = self.inspect(candidate)
                if info is None:
                    return None
                if stat.S_ISLNK(info.st_mode):
                    if candidate in active_links or hops >= MAX_SYMLINK_HOPS:
                        self.issue("SYMLINK_CYCLE", candidate)
                        return None
                    try:
                        target = _readlink(candidate)
                    except OSError as exc:
                        self.issue("SYMLINK_UNREADABLE", candidate, number=exc.errno)
                        return None
                    if not isinstance(target, str) or not target or "\x00" in target:
                        self.issue("INVALID_SYMLINK_TARGET", candidate)
                        return None
                    destination = Path(target)
                    if not destination.is_absolute():
                        destination = current / destination
                    resolved = self.resolve(destination, active_links | {candidate}, hops + 1)
                    if resolved is None:
                        return None
                    current, info = resolved
                    if not self.inside_root(current):
                        self.issue("SYMLINK_OUTSIDE_ROOTS", candidate, target=current)
                        return None
                else:
                    current = candidate
            if info is None:
                return None
        return current, info

    def visit(self, path: Path, depth=0, ancestors=frozenset()):
        if depth > self.max_depth:
            self.issue("DEPTH_LIMIT", path)
            return
        resolved = self.resolve(path)
        if resolved is None:
            return
        actual, info = resolved
        if not stat.S_ISDIR(info.st_mode):
            return
        identity = (info.st_dev, info.st_ino)
        if identity in ancestors:
            self.issue("DIRECTORY_CYCLE", path, target=actual)
            return
        if identity in self.visited:
            return
        self.visited.add(identity)
        try:
            with os.scandir(actual) as entries:
                for entry in entries:
                    self.visit(actual / entry.name, depth + 1, ancestors | {identity})
        except OSError as exc:
            self.issue("DIRECTORY_UNREADABLE", actual, number=exc.errno)

    def report(self):
        return {
            "schema_version": 1,
            "trusted": self.issue_count == 0,
            "status": "incomplete" if self.incomplete else "untrusted" if self.issue_count else "trusted",
            "roots": [str(root) for root in self.roots],
            "checked_entries": len(self.metadata),
            "issue_count": self.issue_count,
            "issues": self.issues,
            "issues_truncated": self.issue_count > len(self.issues),
            "limits": {
                "entries": self.max_entries,
                "depth": self.max_depth,
                "issues": self.max_issues,
                "roots": MAX_ROOTS,
                "symlink_hops": MAX_SYMLINK_HOPS,
            },
        }


def audit_runtime(
    paths: Iterable[str | os.PathLike[str]] | Mapping[str, str | os.PathLike[str]],
    *,
    max_entries: int = 100000,
    max_depth: int = 64,
    max_issues: int = 64,
) -> dict:
    """Audit explicit runtime roots and all ancestors without executing code.

    Symlink destinations must remain in the explicitly supplied roots; a venv
    pointing to a separate Python prefix requires both roots. Hardlinked regular
    files are rejected. Limits may be lowered for callers/tests, but never disable
    the default Linux/root/ownership/permission/link checks.
    """
    valid_limits = (
        type(max_entries) is int
        and 1 <= max_entries <= 1000000
        and type(max_depth) is int
        and 1 <= max_depth <= 256
        and type(max_issues) is int
        and 1 <= max_issues <= 1024
    )
    audit = _Audit(
        [],
        max_entries=max_entries if valid_limits else 1,
        max_depth=max_depth if valid_limits else 1,
        max_issues=max_issues if valid_limits else 1,
    )
    if not valid_limits:
        audit.issue("INVALID_LIMITS")
        return audit.report()
    if not sys.platform.startswith("linux"):
        audit.issue("LINUX_REQUIRED")
        return audit.report()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        audit.issue("ADMIN_REQUIRED")
        return audit.report()
    if isinstance(paths, (str, bytes, os.PathLike)):
        audit.issue("INVALID_ROOT_SET")
        return audit.report()
    try:
        values = paths.values() if isinstance(paths, Mapping) else iter(paths)
        for index, value in enumerate(values):
            if index >= MAX_ROOTS:
                audit.issue("TOO_MANY_ROOTS")
                break
            try:
                path = Path(value)
                if not path.is_absolute() or ".." in path.parts:
                    raise ValueError()
                path_text = str(path)
                if len(path_text) > 4096 or "\x00" in path_text:
                    raise ValueError()
            except (TypeError, ValueError):
                audit.issue("INVALID_ROOT")
                continue
            if path not in audit.roots:
                audit.roots.append(path)
    except TypeError:
        audit.issue("INVALID_ROOT_SET")
    if not audit.roots:
        audit.issue("NO_ROOTS")
    try:
        for root in audit.roots:
            audit.visit(root)
    except _EntryLimit:
        pass
    return audit.report()


def require_trusted_runtime(paths, **limits) -> dict:
    """Return a complete trusted audit or reject before a target can execute."""
    report = audit_runtime(paths, **limits)
    if not report["trusted"]:
        first = report["issues"][0]
        raise RunnerError(
            "runtime trust audit refused the runtime",
            issue=first["code"],
            path=first["path"],
            issue_count=report["issue_count"],
        )
    return report


def main(argv=None):
    import argparse
    import json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    args = parser.parse_args(argv)
    report = audit_runtime(args.paths)
    log_console(json.dumps(report, sort_keys=True))
    return 0 if report["trusted"] else 2 if report["status"] == "incomplete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
