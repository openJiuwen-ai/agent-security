# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Control-plane input / output limits (design doc section 4.6 / 9.2).

Consolidated bounds that apply to *every* runtime backend. Historically the
xiaoyi line added these as per-request model constraints; the ``develop``
line dropped some of them. This module centralises them so the limits layer
is independent of any single runtime and covers the full transport surface
(Content-Length, chunked bodies, multipart overhead, base64 download
fallback, daemon IPC, and remote runtimes).

Each bound has an environment override so operators can tune values without
re-packaging, but the default is the fail-safe documented maximum.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

# --- Sizes ---------------------------------------------------------------

#: Upper bound for any single request *body* (JSON, multipart parts, etc).
MAX_REQUEST_BODY_BYTES = 16 * 1024 * 1024  # 16 MiB

#: Upper bound for a single uploaded file.
MAX_FILE_BYTES = 256 * 1024 * 1024  # 256 MiB

#: Combined upper bound for a multipart upload (all forms overhead included).
MAX_MULTIPART_BYTES = 512 * 1024 * 1024  # 512 MiB

#: Upper bound on per-exec stdin payload.
MAX_STDIN_BYTES = 64 * 1024 * 1024  # 64 MiB

#: Upper bound on per-exec command output (stdout + stderr combined).
MAX_EXEC_OUTPUT_BYTES = 64 * 1024 * 1024  # 64 MiB

#: Upper bound on command argc / env var count.
MAX_COMMAND_ARGS = 512
MAX_ENV_VARS = 256

#: Upper bound on search patterns / list result entries.
MAX_SEARCH_PATTERNS = 256
MAX_LIST_RESULTS = 10_000

#: Upper bound on a base64 download fallback decoded size (the encoded text
#: is 4/3x; we bound the decoded bytes and refuse anything larger).
MAX_DOWNLOAD_BASE64_DECODED_BYTES = 256 * 1024 * 1024

# --- Timeouts ------------------------------------------------------------

#: Default exec timeout when the client omits one (seconds).
DEFAULT_EXEC_TIMEOUT_SECONDS = 300.0

#: Hard upper bound on any exec timeout (seconds).
MAX_EXEC_TIMEOUT_SECONDS = 3600.0


_ENV_OVERRIDES: dict[str, str] = {
    "MAX_REQUEST_BODY_BYTES": "JIUWENBOX_MAX_REQUEST_BODY_MB",
    "MAX_FILE_BYTES": "JIUWENBOX_MAX_FILE_MB",
    "MAX_MULTIPART_BYTES": "JIUWENBOX_MAX_MULTIPART_MB",
    "MAX_STDIN_BYTES": "JIUWENBOX_MAX_STDIN_KB",
    "MAX_EXEC_OUTPUT_BYTES": "JIUWENBOX_MAX_EXEC_OUTPUT_KB",
    "MAX_COMMAND_ARGS": "JIUWENBOX_MAX_COMMAND_ARGS",
    "MAX_ENV_VARS": "JIUWENBOX_MAX_ENV_VARS",
    "MAX_SEARCH_PATTERNS": "JIUWENBOX_MAX_SEARCH_PATTERNS",
    "MAX_LIST_RESULTS": "JIUWENBOX_MAX_LIST_RESULTS",
    "MAX_EXEC_TIMEOUT_SECONDS": "JIUWENBOX_EXEC_TIMEOUT_SECONDS",
}


@dataclass(frozen=True)
class Limits:
    """Resolved control-plane limits (after env overrides)."""

    max_request_body_bytes: int
    max_file_bytes: int
    max_multipart_bytes: int
    max_stdin_bytes: int
    max_exec_output_bytes: int
    max_command_args: int
    max_env_vars: int
    max_search_patterns: int
    max_list_results: int
    max_exec_timeout_seconds: float


def _parse_mb_to_bytes(raw: str | None, default: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return int(value * 1024 * 1024)


def _parse_kb_to_bytes(raw: str | None, default: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return int(value * 1024)


def _parse_int(raw: str | None, default: int) -> int:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def _parse_float(raw: str | None, default: float) -> float:
    if raw is None or raw.strip() == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    if value <= 0:
        return default
    return value


def resolve_limits(environ: dict[str, str] | None = None) -> Limits:
    """Resolve limits from the environment, falling back to defaults."""
    env = environ if environ is not None else os.environ
    return Limits(
        max_request_body_bytes=_parse_mb_to_bytes(
            env.get(_ENV_OVERRIDES["MAX_REQUEST_BODY_BYTES"]),
            MAX_REQUEST_BODY_BYTES,
        ),
        max_file_bytes=_parse_mb_to_bytes(
            env.get(_ENV_OVERRIDES["MAX_FILE_BYTES"]),
            MAX_FILE_BYTES,
        ),
        max_multipart_bytes=_parse_mb_to_bytes(
            env.get(_ENV_OVERRIDES["MAX_MULTIPART_BYTES"]),
            MAX_MULTIPART_BYTES,
        ),
        max_stdin_bytes=_parse_kb_to_bytes(
            env.get(_ENV_OVERRIDES["MAX_STDIN_BYTES"]),
            MAX_STDIN_BYTES,
        ),
        max_exec_output_bytes=_parse_kb_to_bytes(
            env.get(_ENV_OVERRIDES["MAX_EXEC_OUTPUT_BYTES"]),
            MAX_EXEC_OUTPUT_BYTES,
        ),
        max_command_args=_parse_int(
            env.get(_ENV_OVERRIDES["MAX_COMMAND_ARGS"]),
            MAX_COMMAND_ARGS,
        ),
        max_env_vars=_parse_int(
            env.get(_ENV_OVERRIDES["MAX_ENV_VARS"]),
            MAX_ENV_VARS,
        ),
        max_search_patterns=_parse_int(
            env.get(_ENV_OVERRIDES["MAX_SEARCH_PATTERNS"]),
            MAX_SEARCH_PATTERNS,
        ),
        max_list_results=_parse_int(
            env.get(_ENV_OVERRIDES["MAX_LIST_RESULTS"]),
            MAX_LIST_RESULTS,
        ),
        max_exec_timeout_seconds=_parse_float(
            env.get(_ENV_OVERRIDES["MAX_EXEC_TIMEOUT_SECONDS"]),
            MAX_EXEC_TIMEOUT_SECONDS,
        ),
    )


DEFAULT_LIMITS = resolve_limits(environ={})