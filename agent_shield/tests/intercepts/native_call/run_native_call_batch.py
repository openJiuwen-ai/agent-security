"""Decide 100 native-call records with the behavior policy engine and save each result.

The engine entry is agent_shield.policy_engine.evaluate. Each native
record is turned into an agent-event first, then submitted as a DecisionRequest.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent_shield.policy_engine.evaluate import evaluate
from agent_shield.intercepts.native_call.record import native_record_to_event
from agent_shield.tests.stdio import log_line

HERE = Path(__file__).resolve().parent
CASES = HERE / "native_call_cases.json"
RESULTS = HERE / "native_call_results.jsonl"
WORKSPACE = {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}


def _context() -> dict:
    return {
        "user_intent": {"text": "read the project file"},
        "workspace": WORKSPACE,
        "host_capabilities": {"hitl": False, "auto_intent": True},
        "source": {"framework": "other", "session_id": "native-call-batch", "agent_id": "leader"},
        "execution": {
            "plane": "host",
            "provider": "windows-process-guard",
            "intercept": True,
            "escaped": False,
            "escape_reason": "",
        },
    }


def _request(record: dict, event: dict) -> dict:
    return {
        "spec": "agent-decision-request/v1",
        "request_id": record.get("request_id") or "",
        "subject_id": "user-a",
        "task_id": "native-call-batch",
        "event": event,
        "user_rules": [],
        "grants": [],
    }


def _summary(record: dict) -> str:
    operation = record.get("operation") if isinstance(record.get("operation"), dict) else {}
    resources = operation.get("resources") if isinstance(operation.get("resources"), list) else []
    parts = []
    for item in resources:
        if not isinstance(item, dict):
            continue
        if item.get("command_line"):
            parts.append(str(item["command_line"]))
        elif item.get("path"):
            parts.append(str(item["path"]))
        elif item.get("host") or item.get("ip"):
            parts.append(f"{item.get('host') or item.get('ip')}:{item.get('port')}")
    return " | ".join(parts)


def main() -> None:
    parser = argparse.ArgumentParser(description="Decide the native-call batch and write JSONL results.")
    parser.add_argument("--unmatched", default="none", choices=("none", "allow", "ask", "deny"))
    args = parser.parse_args()
    if not CASES.is_file():
        from generate_native_call_cases import main as generate

        generate()
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    rows = []
    for case in cases:
        body = case["body"]
        event = native_record_to_event(body, _context())
        decision = evaluate(_request(body, event), unmatched=args.unmatched)
        rows.append(
            {
                "id": case["id"],
                "label": case["label"],
                "request_id": body.get("request_id"),
                "operation_id": body.get("operation_id"),
                "summary": _summary(body),
                "action": decision.get("action"),
                "raw_action": decision.get("raw_action"),
                "winner_rule_id": decision.get("winner_rule_id"),
                "response": decision,
            }
        )
    RESULTS.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    counts: dict[str, int] = {}
    for row in rows:
        key = row["action"] or ""
        counts[key] = counts.get(key, 0) + 1
    log_line(f"recorded {len(rows)} decisions in {RESULTS}")
    for key in sorted(counts):
        log_line(f"  {key}: {counts[key]}")


if __name__ == "__main__":
    main()
