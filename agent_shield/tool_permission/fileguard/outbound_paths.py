# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Shared path normalization for outbound file tools and their permission checks."""

import ast
import json
from pathlib import Path
from typing import Any


def normalize_file_path_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return []
        if text[0] in "[(" and text[-1] in ")]":
            for loader in (json.loads, ast.literal_eval):
                try:
                    parsed = loader(text)
                except (TypeError, ValueError, SyntaxError):
                    continue
                if isinstance(parsed, (list, tuple)):
                    return [str(item).strip() for item in parsed if str(item).strip()]
                if isinstance(parsed, str):
                    return [parsed.strip()] if parsed.strip() else []
                break
        return [text]
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [str(value)]


def is_public_file_url(value: str) -> bool:
    return value.strip().lower().startswith(("http://", "https://"))


def resolve_outbound_path(value: str, base: Path | None = None) -> Path:
    """Resolve ``value`` against ``base``.

    An absolute ``value`` does not use ``base``. A relative ``value`` requires
    ``base``; the process working directory is not a substitute.
    """
    path = Path(value)
    if path.is_absolute():
        return path.resolve()
    if base is None:
        raise ValueError("relative outbound path requires a base directory")
    return (base / value).resolve()
