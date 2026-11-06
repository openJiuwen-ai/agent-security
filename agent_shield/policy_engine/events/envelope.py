"""Build an agent-event/v1 envelope."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone


def new_event_id() -> str:
    return "evt_" + uuid.uuid4().hex


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_event(
    *,
    source: dict,
    workspace: dict,
    effects: list[dict],
    raw: dict,
    normalization: dict | None = None,
    user_intent: dict | None = None,
    host_capabilities: dict | None = None,
    execution: dict | None = None,
    event_id: str | None = None,
    category: str = "tool_call",
) -> dict:
    return {
        "spec": "agent-event/v1",
        "id": event_id or new_event_id(),
        "time": utc_now(),
        "source": source,
        "workspace": workspace,
        "user_intent": user_intent,
        "action": {
            "category": category,
            "raw": raw,
            "effects": effects,
            "normalization": normalization or {"status": "ok", "warnings": []},
        },
        "host_capabilities": host_capabilities or {"hitl": True, "auto_intent": True},
        "execution": execution
        or {
            "plane": "host",
            "provider": "host",
            "intercept": False,
            "escaped": False,
            "escape_reason": "",
        },
    }
