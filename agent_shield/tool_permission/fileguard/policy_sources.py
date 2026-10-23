# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Labels for where a path rule came from.

A stacked file_guard config can carry user, cloud, and builtin layers.
``source_order`` names which layers count, and each path rule is tagged
with one of these ids.
"""

from typing import Any

SOURCE_USER = "user"
SOURCE_CLOUD = "cloud"
SOURCE_BUILTIN = "builtin"

DEFAULT_SOURCE_ORDER = (SOURCE_USER, SOURCE_CLOUD, SOURCE_BUILTIN)
POLICY_SOURCE_IDS = frozenset(DEFAULT_SOURCE_ORDER)


def validate_source_order(order: Any) -> list[str]:
    if not isinstance(order, list) or any(
        not isinstance(source, str) or source not in POLICY_SOURCE_IDS for source in order
    ) or len(order) != len(set(order)):
        raise ValueError("invalid permissions.composition source_order")
    return order


def validate_policy_sources(sources: Any) -> list[dict[str, Any]]:
    if not isinstance(sources, list):
        raise ValueError("policy_sources must be a list")
    seen: set[str] = set()
    for source in sources:
        if not isinstance(source, dict) or set(source) != {"id", "enabled"}:
            raise ValueError("each policy source requires id and enabled")
        source_id = source["id"]
        if not isinstance(source_id, str) or source_id not in POLICY_SOURCE_IDS or source_id in seen:
            raise ValueError("unknown or duplicate policy source")
        if not isinstance(source["enabled"], bool):
            raise ValueError("policy source enabled must be boolean")
        seen.add(source_id)
    return sources


__all__ = [
    "DEFAULT_SOURCE_ORDER",
    "POLICY_SOURCE_IDS",
    "SOURCE_BUILTIN",
    "SOURCE_CLOUD",
    "SOURCE_USER",
    "validate_policy_sources",
    "validate_source_order",
]
