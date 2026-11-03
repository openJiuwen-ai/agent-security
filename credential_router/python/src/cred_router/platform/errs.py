"""The central error envelope for the service.

Every package wraps its errors with an :class:`Error` carrying a
machine-readable code, the logical operation name, a human message,
and an optional cause. Callers switch on :func:`code_of` for HTTP
routing, or match the sentinel exceptions for a specific condition.
"""

from __future__ import annotations

from enum import StrEnum


class Code(StrEnum):
    """A machine-readable error category."""

    BAD_REQUEST = "bad_request"
    UNAUTHORIZED = "unauthorized"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    INTERNAL = "internal"
    SERVICE_UNAVAILABLE = "service_unavailable"
    ROTATION_IN_PROGRESS = "rotation_in_progress"
    NESTED_ROTATION = "nested_rotation"
    NO_ROTATION_IN_PROGRESS = "no_rotation_in_progress"
    BACKUP_FAILED = "backup_failed"
    UNSUPPORTED_CIPHER_FORMAT = "unsupported_cipher_format"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    BAD_GATEWAY = "bad_gateway"
    GATEWAY_TIMEOUT = "gateway_timeout"


#: The HTTP status code for each error code. Centralised so the rest of
#: the codebase never hardcodes status numbers.
_HTTP_STATUS: dict[Code, int] = {
    Code.BAD_REQUEST: 400,
    Code.UNSUPPORTED_CIPHER_FORMAT: 400,
    Code.UNAUTHORIZED: 401,
    Code.NOT_FOUND: 404,
    Code.CONFLICT: 409,
    Code.ROTATION_IN_PROGRESS: 409,
    Code.NESTED_ROTATION: 409,
    Code.NO_ROTATION_IN_PROGRESS: 409,
    Code.PAYLOAD_TOO_LARGE: 413,
    Code.BACKUP_FAILED: 500,
    Code.INTERNAL: 500,
    Code.BAD_GATEWAY: 502,
    Code.SERVICE_UNAVAILABLE: 503,
    Code.GATEWAY_TIMEOUT: 504,
}


def http_status(code: Code | str) -> int:
    """Return the HTTP status code for the error code."""
    try:
        key = Code(code)
    except ValueError:
        return 500
    return _HTTP_STATUS.get(key, 500)


class ServiceError(Exception):
    """The error envelope: a code, an operation, a message, a cause."""

    def __init__(
        self,
        code: Code,
        op: str = "",
        message: str = "",
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.op = op
        self.message = message
        self.cause = cause
        if cause is not None:
            # Python's own chaining mechanism, so that "raise ... from"
            # and the traceback both show the cause.
            self.__cause__ = cause

    def __str__(self) -> str:
        parts = []
        if self.op:
            parts.append(f"{self.op}: ")
        parts.append(self.message)
        if self.cause is not None:
            parts.append(f": {self.cause}")
        return "".join(parts)


def new(code: Code, op: str, message: str) -> ServiceError:
    """Create an error with the given code, operation, and message."""
    return ServiceError(code, op, message)


def wrap(code: Code, op: str, message: str, cause: BaseException) -> ServiceError:
    """Create a new error wrapping an existing one."""
    return ServiceError(code, op, message, cause)


def code_of(exc: BaseException | None) -> Code | str:
    """Extract the code from an error, unwrapping the cause chain."""
    seen: set[int] = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, ServiceError):
            return current.code
        current = current.__cause__
    return ""
