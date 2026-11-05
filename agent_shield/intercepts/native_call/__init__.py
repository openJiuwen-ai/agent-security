"""Native-call intercept. One hooked API is decided before it runs."""

from agent_shield.intercepts.native_call.launch import (
    PreflightResult,
    ProcessGuardUnavailable,
    preflight,
    wrap,
)
from agent_shield.intercepts.native_call.record import native_record_to_event
from agent_shield.intercepts.native_call.session import ProcessBinding, settle_native_record

__all__ = [
    "PreflightResult",
    "ProcessBinding",
    "ProcessGuardUnavailable",
    "native_record_to_event",
    "preflight",
    "settle_native_record",
    "wrap",
]
