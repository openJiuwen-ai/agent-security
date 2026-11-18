# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Framework-level permission config diff logging.

Manager keeps ``user_key → full config``.  Each publish compares the previous
full config with the new one at print-unit granularity (top-level key, or
``approval_overrides.<id>``).  Within a unit, recurse to leaves and stop at
the first difference; emit at most one line for that unit.
"""

from __future__ import annotations

import copy
import logging
from collections.abc import Mapping
from typing import Any, Literal

logger = logging.getLogger(__name__)

FieldOp = Literal["create", "update", "remove"]

_SPLIT_BY_ID_KEYS = frozenset({"approval_overrides"})


def _deepcopy(value: Any) -> Any:
    return copy.deepcopy(value)


def _print_units(config: Mapping[str, Any] | None) -> dict[str, Any]:
    """Map print-unit path → subtree value (emit boundary)."""

    if not isinstance(config, Mapping):
        return {}
    units: dict[str, Any] = {}
    for key, value in config.items():
        name = str(key)
        if name in _SPLIT_BY_ID_KEYS:
            units.update(_approval_override_units(value))
        else:
            units[name] = _deepcopy(value)
    return units


def _approval_override_units(value: Any) -> dict[str, Any]:
    if not isinstance(value, list):
        return {"approval_overrides": _deepcopy(value)}
    by_id: dict[str, Any] = {}
    for item in value:
        if not isinstance(item, Mapping):
            return {"approval_overrides": _deepcopy(value)}
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id.strip():
            return {"approval_overrides": _deepcopy(value)}
        by_id[f"approval_overrides.{item_id.strip()}"] = _deepcopy(dict(item))
    return by_id


def _subtree_differs(left: Any, right: Any) -> bool:
    """True if any leaf differs.  Short-circuits on the first difference."""

    if left is right:
        return False
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        keys = set(left) | set(right)
        for key in keys:
            if key not in left or key not in right:
                return True
            if _subtree_differs(left[key], right[key]):
                return True
        return False
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return True
        for a, b in zip(left, right, strict=True):
            if _subtree_differs(a, b):
                return True
        return False
    if isinstance(left, tuple) and isinstance(right, tuple):
        if len(left) != len(right):
            return True
        for a, b in zip(left, right, strict=True):
            if _subtree_differs(a, b):
                return True
        return False
    return left != right


def _emit_field(*, key: str, op: FieldOp, field: str, value: Any = None) -> None:
    if op == "remove":
        logger.info("permission.config key=%s op=remove field=%s", key, field)
        return
    logger.info(
        "permission.config key=%s op=%s field=%s value=%s",
        key,
        op,
        field,
        value,
    )


def log_config_diff(
    *,
    key: str,
    previous: Mapping[str, Any] | None,
    config: Mapping[str, Any],
) -> dict[str, Any]:
    """Diff full ``config`` against previous full config; return new snapshot.

    Missing previous is treated as ``{}``.  Identical trees emit nothing.
    Each dirty print unit is emitted at most once; leaf walks under a dirty
    unit stop as soon as a difference is found.
    """

    resolved = key or "-"
    prior_units = _print_units(previous if previous is not None else {})
    current_units = _print_units(config)

    # Each print unit is visited once; ``_subtree_differs`` short-circuits
    # further leaf walks under a dirty unit.
    for field in sorted(set(prior_units) | set(current_units)):
        if field not in prior_units:
            _emit_field(
                key=resolved, op="create", field=field, value=current_units[field]
            )
        elif field not in current_units:
            _emit_field(key=resolved, op="remove", field=field)
        elif _subtree_differs(prior_units[field], current_units[field]):
            _emit_field(
                key=resolved, op="update", field=field, value=current_units[field]
            )

    return _deepcopy(dict(config))


def log_config_key_removed(*, key: str) -> None:
    """Log removal of an entire manager registration key."""

    logger.info("permission.config key=%s op=remove", key or "-")


# Back-compat alias used by older tests / call sites.
flatten_config = _print_units


__all__ = [
    "FieldOp",
    "flatten_config",
    "log_config_diff",
    "log_config_key_removed",
]
