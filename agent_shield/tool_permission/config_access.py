# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Read host/file guard settings and the runtime / builtin sections.

``file_guard`` and ``host_guard`` sit at the top of the engine config, the
same place they occupied inside the old permissions mapping. ``runtime`` and
``builtin`` are extra top-level sections the caller fills in.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any


def _mapping_section(config: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    section = config.get(key)
    return section if isinstance(section, Mapping) else {}


def runtime_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    runtime = config.get("runtime")
    if isinstance(runtime, Mapping):
        return runtime
    return {}


def builtin_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    """Caller-supplied package defaults. Same role as the old builtin YAML."""

    return _mapping_section(config, "builtin")


def nested_section(config: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    current: object = config
    for key in keys:
        if not isinstance(current, Mapping):
            return {}
        current = current.get(key)
    return current if isinstance(current, Mapping) else {}


def file_guard_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping_section(config, "file_guard")


def host_guard_section(config: Mapping[str, Any]) -> Mapping[str, Any]:
    return _mapping_section(config, "host_guard")


def runtime_path(config: Mapping[str, Any], key: str) -> Path | None:
    runtime = runtime_section(config)
    raw = runtime.get(key)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        return None
    if isinstance(raw, str):
        return Path(raw).expanduser()
    return None


def runtime_workspace_root(config: Mapping[str, Any]) -> Path | None:
    return runtime_path(config, "project_root") or runtime_path(config, "workspace_root")


def runtime_trusted_dirs(config: Mapping[str, Any]) -> tuple[str, ...]:
    runtime = runtime_section(config)
    raw = runtime.get("trusted_dirs", ())
    if not isinstance(raw, (list, tuple)):
        return ()
    return tuple(str(item) for item in raw if isinstance(item, str) and item.strip())


def runtime_protected_pids(config: Mapping[str, Any]) -> frozenset[str] | None:
    """Process ids supplied by the caller. Missing key keeps the local process ids."""

    runtime = runtime_section(config)
    if "protected_pids" not in runtime:
        return None
    raw = runtime.get("protected_pids")
    if not isinstance(raw, (list, tuple)):
        return frozenset()
    pids: set[str] = set()
    for item in raw:
        if isinstance(item, bool):
            continue
        if isinstance(item, int):
            pids.add(str(item))
        elif isinstance(item, str) and item.strip():
            pids.add(item.strip())
    return frozenset(pids)


def runtime_immutable_roots(config: Mapping[str, Any]) -> tuple[Path, ...]:
    runtime = runtime_section(config)
    raw = runtime.get("immutable_control_roots", ())
    if not isinstance(raw, (list, tuple)):
        return ()
    roots: list[Path] = []
    for item in raw:
        if isinstance(item, str) and item.strip():
            roots.append(Path(item).expanduser())
    return tuple(roots)


def host_guard_flag(section: Mapping[str, Any], key: str, default: bool = False) -> bool:
    value = section.get(key, default)
    return value if isinstance(value, bool) else default


__all__ = [
    "builtin_section",
    "file_guard_section",
    "host_guard_flag",
    "host_guard_section",
    "nested_section",
    "runtime_immutable_roots",
    "runtime_path",
    "runtime_protected_pids",
    "runtime_section",
    "runtime_trusted_dirs",
    "runtime_workspace_root",
]
