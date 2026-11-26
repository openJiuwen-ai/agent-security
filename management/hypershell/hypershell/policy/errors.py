"""Policy compilation errors.

Every error carries a stable machine-readable ``code`` so the API layer can
return a structured 4xx instead of a generic 500. The codes mirror the ones
documented in ``docs/ARCHITECTURE.md`` and defined below.
"""

from __future__ import annotations


class PolicyError(Exception):
    """Base class for all policy compilation failures."""

    code = "POLICY_ERROR"
    http_status = 422

    def __init__(self, message: str, **details: object) -> None:
        super().__init__(message)
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, object]:
        return {"code": self.code, "message": self.message, "details": self.details}


class InvalidRequest(PolicyError):
    """Schema / type / unknown-field violation."""

    code = "INVALID_REQUEST"


class UnknownResource(PolicyError):
    """The request names a resource id that is not in the trusted catalog."""

    code = "RESOURCE_NOT_FOUND"
    http_status = 404


class PermissionExceedsBoundary(PolicyError):
    """The request asks for more than the effective permission set allows."""

    code = "PERMISSION_EXCEEDS_BOUNDARY"
    http_status = 422


class IncompatibleProfile(PolicyError):
    """The application's required resources are not satisfiable."""

    code = "INCOMPATIBLE_PROFILE"


class InvalidQuota(PolicyError):
    """A quota value is not a finite positive number."""

    code = "INVALID_QUOTA"


class UnsupportedCapability(PolicyError):
    """The backend / node cannot provide a requested capability."""

    code = "UNSUPPORTED_CAPABILITY"
