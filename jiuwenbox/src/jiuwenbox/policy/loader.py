# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Policy loading with schema-version migration (design doc section 5.5).

The processing chain is:

    YAML / etcd
      -> schema version migration (this module)
      -> SecurityPolicy validation
      -> capability validation
      -> backend-specific translation
      -> immutable snapshot

``load_policy`` is the single entry point for turning raw YAML text into a
validated :class:`SecurityPolicy`. It keeps the legacy top-level fields
loadable (the pre-``schema_version`` files) while clearly rejecting unknown
*future* schema versions.
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml
from pydantic import ValidationError

from jiuwenbox.logging_config import configure_logging
from jiuwenbox.models.policy import SecurityPolicy
from jiuwenbox.server.runtime.errors import PolicyValidationError

configure_logging()
logger = logging.getLogger(__name__)

#: The schema versions this build understands. ``None`` is the legacy
#: "no schema_version key present" form.
SUPPORTED_SCHEMA_VERSIONS: frozenset[int | None] = frozenset({1, None})


def _extract_schema_version(data: object) -> int | None:
    if isinstance(data, dict):
        raw = data.get("schema_version")
        if raw is None:
            return None
        if isinstance(raw, bool):  # guard against ``true`` -> 1
            raise PolicyValidationError(
                "schema_version must be an integer, not a boolean"
            )
        if isinstance(raw, int):
            return raw
        raise PolicyValidationError(
            f"schema_version must be an integer, got {type(raw).__name__}"
        )
    return None


def load_policy_from_text(text: str) -> SecurityPolicy:
    """Parse and validate a policy from YAML text (with schema migration)."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyValidationError(f"policy YAML parse error: {exc}") from exc

    if data is None:
        raise PolicyValidationError("policy YAML is empty")

    version = _extract_schema_version(data)
    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise PolicyValidationError(
            f"unsupported policy schema_version {version!r}; "
            f"supported: {sorted(v for v in SUPPORTED_SCHEMA_VERSIONS if v is not None)}"
        )

    try:
        return SecurityPolicy.model_validate(data)
    except ValidationError as exc:
        raise PolicyValidationError(str(exc)) from exc


def load_policy_from_file(path: str | Path) -> SecurityPolicy:
    """Load a policy from a YAML file (with schema migration)."""
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    return load_policy_from_text(text)