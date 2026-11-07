"""Process-level services: the error envelope and the instance guard."""

from __future__ import annotations

from .config import (
    Config,
    ConfigError,
    parse_duration,
)
from .errs import (
    Code,
    ServiceError,
    code_of,
    http_status,
    new,
    wrap,
)
from .singleinstance import (
    SingleInstanceError,
    acquire_single_instance_lock,
    open_lock_file,
    write_pid_file,
)

__all__ = [
    "Code",
    "Config",
    "ConfigError",
    "ServiceError",
    "SingleInstanceError",
    "acquire_single_instance_lock",
    "code_of",
    "http_status",
    "new",
    "open_lock_file",
    "parse_duration",
    "wrap",
    "write_pid_file",
]
