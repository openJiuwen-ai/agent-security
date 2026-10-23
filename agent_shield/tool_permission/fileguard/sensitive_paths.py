# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Merge caller-supplied builtin sensitive paths into ``file_guard.paths``.

The path list used to be read from a package YAML file. The caller now puts
that same list on ``config["builtin"]["sensitive_paths"]``. Evaluation still
consumes the merged ``paths`` only. Builtin ``action`` is copied onto
read/write/exec. An overlay cannot widen a builtin path to allow.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .package_switch import package_rules_enabled

logger = logging.getLogger(__name__)

_HOME_PREFIX = "~/"
_VALID_ACTIONS = frozenset({"ask", "deny", "allow"})
_AXIS_RANK = {"deny": 0, "ask": 1, "allow": 2}


def _expand_home_path(raw: str) -> str:
    text = str(raw or "").strip()
    if text.startswith(_HOME_PREFIX) or text == "~":
        home = Path.home().as_posix().rstrip("/")
        rest = text[1:].lstrip("/")
        return f"{home}/{rest}" if rest else home
    return text


def _builtin_action(item: Mapping[str, Any]) -> str | None:
    action = item.get("action")
    if not (isinstance(action, str) and action.strip()):
        logger.warning(
            "[PermissionEngine] permission.sensitive_paths.missing_action id=%r",
            item.get("id"),
        )
        return None
    action = action.strip().lower()
    if action not in _VALID_ACTIONS:
        logger.warning(
            "[PermissionEngine] permission.sensitive_paths.invalid_action id=%r action=%r",
            item.get("id"),
            action,
        )
        return None
    if action == "allow":
        logger.warning(
            "[PermissionEngine] permission.sensitive_paths.skip id=%r reason=allow_not_allowed",
            item.get("id"),
        )
        return None
    return action


def normalize_builtin_sensitive_paths(raw: object) -> list[dict[str, Any]]:
    """Turn ``builtin.sensitive_paths`` into file_guard path entries."""

    if not isinstance(raw, list):
        return []
    out: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        raw_path = item.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            continue
        action = _builtin_action(item)
        if action is None:
            continue
        entry = dict(item)
        entry["path"] = _expand_home_path(raw_path)
        entry["match"] = str(item.get("match") or "glob")
        entry["read"] = action
        entry["write"] = action
        entry["exec"] = action
        entry["layer"] = "builtin"
        out.append(entry)
    return out


def _stricter_axis(left: str, right: str) -> str:
    left_rank = _AXIS_RANK.get(str(left).strip().lower(), 1)
    right_rank = _AXIS_RANK.get(str(right).strip().lower(), 1)
    rank = min(left_rank, right_rank)
    if rank == 0:
        return "deny"
    if rank == 1:
        return "ask"
    return "allow"


def _merge_paths(
    overlay_paths: list[dict[str, Any]],
    packaged: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for item in packaged:
        key = str(item.get("path") or "").replace("\\", "/")
        if key:
            by_key[key] = dict(item)
    merged: list[dict[str, Any]] = []
    used: set[str] = set()
    for item in overlay_paths:
        path = str(item.get("path") or "").replace("\\", "/")
        if path in by_key:
            floor = by_key[path]
            used.add(path)
            combined = dict(item)
            for axis in ("read", "write", "exec"):
                overlay_val = str(item.get(axis) or "").strip().lower()
                floor_val = str(floor.get(axis) or "ask").strip().lower()
                if overlay_val == "allow" and floor_val != "allow":
                    combined[axis] = floor_val
                elif overlay_val:
                    combined[axis] = _stricter_axis(overlay_val, floor_val)
                else:
                    combined[axis] = floor_val
            combined["layer"] = "builtin"
            merged.append(combined)
        else:
            merged.append(dict(item))
    for key, item in by_key.items():
        if key not in used:
            merged.append(dict(item))
    return merged


def merge_builtin_sensitive_paths(
    permissions: dict[str, Any],
    raw_paths: object,
    *,
    package_builtin_rules: object,
) -> dict[str, Any]:
    """Merge builtin paths when package rules and file_guard are both on."""

    if not package_rules_enabled(package_builtin_rules):
        return permissions
    file_guard = permissions.get("file_guard")
    if not isinstance(file_guard, dict) or not file_guard.get("enabled"):
        return permissions
    packaged = normalize_builtin_sensitive_paths(raw_paths)
    if not packaged:
        return permissions
    paths = [item for item in (file_guard.get("paths") or []) if isinstance(item, dict)]
    updated = dict(file_guard)
    updated["paths"] = _merge_paths(paths, packaged)
    permissions["file_guard"] = updated
    return permissions


__all__ = ["merge_builtin_sensitive_paths", "normalize_builtin_sensitive_paths"]
