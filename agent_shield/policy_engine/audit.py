"""File JSONL audit. The in-memory audit lives on the server registry."""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path

from agent_shield.policy_engine.matchers.paths import event_os, glob_any
from agent_shield.policy_engine.builtin.policy import Policy

_SECRET = re.compile(
    r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9_\-]{8,}|api_key\s*=\s*\S+|BEGIN (?:RSA |OPENSSH )?PRIVATE KEY)",
    re.IGNORECASE,
)
_LOCK = threading.Lock()


def write_audit(decision: dict, event: dict, path: str | Path | None, policy: Policy | None) -> None:
    if not path:
        return
    action = decision.get("action")
    record = {
        "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "event_id": decision.get("event_id") or "",
        "framework": _source(event).get("framework") or "",
        "session_id": _source(event).get("session_id") or "",
        "action": action,
        "raw_action": decision.get("raw_action") or action,
        "winner_rule_id": decision.get("winner_rule_id"),
        "tool_raw_name": _tool_name(event),
    }
    line = json.dumps(_redact(record, event, policy), ensure_ascii=False, separators=(",", ":"))
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


def _builtin_sensitive() -> tuple[str, ...]:
    from agent_shield.policy_engine.builtin.policy import load_builtin_policy

    return load_builtin_policy().catalog("sensitive_globs")


def _source(event: dict) -> dict:
    source = event.get("source")
    return source if isinstance(source, dict) else {}


def _tool_name(event: dict) -> str:
    raw = (event.get("action") or {}).get("raw") if isinstance(event.get("action"), dict) else {}
    if isinstance(raw, dict) and isinstance(raw.get("name"), str):
        return raw["name"]
    return ""


def _redact(record: dict, event: dict, policy: Policy | None) -> dict:
    patterns = policy.catalog("sensitive_globs") if policy is not None else _builtin_sensitive()
    os_name = event_os(event) if isinstance(event, dict) else "posix"

    def walk(value):
        if isinstance(value, str):
            text = _SECRET.sub("***", value)
            if patterns and glob_any(text, patterns, os_name=os_name):
                return "<redacted-path>"
            return text
        if isinstance(value, list):
            return [walk(item) for item in value]
        if isinstance(value, dict):
            return {key: walk(item) for key, item in value.items()}
        return value

    return walk(record)
