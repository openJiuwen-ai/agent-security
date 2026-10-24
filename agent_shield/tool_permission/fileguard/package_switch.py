# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Whether ``package_builtin_rules`` turns on the builtin sensitive-path floor."""

from __future__ import annotations

_FALSE_STRINGS = frozenset({"false", "0", "no", "off"})


def package_rules_enabled(value: object) -> bool:
    """Enable packaged defaults unless the caller explicitly turns them off."""

    if isinstance(value, bool):
        return value
    return not (isinstance(value, str) and value.strip().lower() in _FALSE_STRINGS)


__all__ = ["package_rules_enabled"]
