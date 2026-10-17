# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Stable runtime error codes shared across all runtime adapters.

This module is the single source of truth for the machine-readable error
taxonomy required by the unified architecture (see the design doc section
5.6 "错误模型"). Route handlers translate these domain errors into HTTP
responses; runtime adapters and the policy engine raise them without ever
constructing FastAPI exceptions directly.

The codes are intentionally coarse: they must remain stable across
releases so clients can branch on them. Adding a code is a backwards
compatible change; renaming or renumbering one is not.
"""

from __future__ import annotations

import enum


class ErrorCode(str, enum.Enum):
    """Stable, machine-readable error codes.

    Every value here has a one-to-one mapping to a documented HTTP status
    code in :data:`HTTP_STATUS_BY_CODE`. Do not reuse a value for a
    semantically different condition.
    """

    # 4xx
    BAD_REQUEST = "bad_request"
    POLICY_VALIDATION = "policy_validation"
    AUTH_REQUIRED = "auth_required"
    AUTH_FAILED = "auth_failed"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    CAPABILITY_UNSUPPORTED = "capability_unsupported"
    LIMIT_EXCEEDED = "limit_exceeded"
    FORBIDDEN = "forbidden"

    # 5xx
    RUNTIME_UNAVAILABLE = "runtime_unavailable"
    BACKEND_ERROR = "backend_error"
    INTERNAL_ERROR = "internal_error"


#: HTTP status codes each error code maps to at the API boundary.
HTTP_STATUS_BY_CODE: dict[ErrorCode, int] = {
    ErrorCode.BAD_REQUEST: 400,
    ErrorCode.POLICY_VALIDATION: 400,
    ErrorCode.AUTH_REQUIRED: 401,
    ErrorCode.AUTH_FAILED: 401,
    ErrorCode.NOT_FOUND: 404,
    ErrorCode.CONFLICT: 409,
    ErrorCode.CAPABILITY_UNSUPPORTED: 422,
    ErrorCode.LIMIT_EXCEEDED: 413,
    ErrorCode.FORBIDDEN: 403,
    ErrorCode.RUNTIME_UNAVAILABLE: 503,
    ErrorCode.BACKEND_ERROR: 502,
    ErrorCode.INTERNAL_ERROR: 500,
}


class JiuwenboxError(Exception):
    """Base class for all domain errors carrying a stable ``ErrorCode``.

    The ``detail`` field is a human-readable message; ``code`` is the
    machine-readable value clients branch on. ``status_code`` is derived
    from ``code`` so the HTTP mapping lives in exactly one place.
    """

    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, detail: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(detail)
        self.detail = detail
        if code is not None:
            self.code = code

    @property
    def status_code(self) -> int:
        return HTTP_STATUS_BY_CODE.get(self.code, 500)

    def to_dict(self) -> dict[str, str]:
        return {"error": self.code.value, "detail": self.detail}


class RequestFormatError(JiuwenboxError):
    """Malformed request body, headers, or parameters."""

    code = ErrorCode.BAD_REQUEST


class PolicyValidationError(JiuwenboxError):
    """A policy failed schema / semantic validation."""

    code = ErrorCode.POLICY_VALIDATION


class RuntimeUnavailableError(JiuwenboxError):
    """The requested runtime backend is not configured or cannot load."""

    code = ErrorCode.RUNTIME_UNAVAILABLE


class CapabilityUnsupportedError(JiuwenboxError):
    """A policy requests a security capability the runtime cannot enforce.

    Per the fail-closed rule (design doc section 5.3), this must never be
    silently downgraded: raise it so the caller sees a stable error.
    """

    code = ErrorCode.CAPABILITY_UNSUPPORTED


class LimitExceededError(JiuwenboxError):
    """A request exceeds a control-plane input/output bound."""

    code = ErrorCode.LIMIT_EXCEEDED


class BackendError(JiuwenboxError):
    """A backend SDK / daemon error mapped to a stable code."""

    code = ErrorCode.BACKEND_ERROR


class SandboxConflictError(JiuwenboxError):
    """Sandbox lifecycle conflict (duplicate id, wrong phase, etc.)."""

    code = ErrorCode.CONFLICT


class SandboxNotFoundError(JiuwenboxError):
    """Referenced sandbox does not exist."""

    code = ErrorCode.NOT_FOUND
