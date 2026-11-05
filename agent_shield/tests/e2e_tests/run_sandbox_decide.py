"""Feed 100 sandbox native records to one Decide task and save each decision."""

from __future__ import annotations

import json
from pathlib import Path

from agent_shield.policy_engine.server.decide import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry
from agent_shield.intercepts.native_call import ProcessBinding, settle_native_record
from agent_shield.tests.stdio import log_line

HERE = Path(__file__).resolve().parent
RECORDS = HERE / "sandbox_records.json"
RESULTS = HERE / "sandbox_decide_results.jsonl"


class Host:
    @staticmethod
    def user_intent():
        return {"text": "read the project file"}

    @staticmethod
    def workspace():
        return {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}

    @staticmethod
    def capabilities():
        return {"hitl": False, "auto_intent": True}

    @staticmethod
    def request_approval(decision, event):
        return False

    @staticmethod
    def user_rules():
        return []

    @staticmethod
    def grants():
        return []


BINDING = ProcessBinding(
    pid=4200,
    parent_pid=3100,
    process_instance_id="4200:134214912000000000",
    image="C:/Program Files/PowerShell/7/pwsh.exe",
    user_sid="S-1-5-21-1",
    integrity_level="medium",
)


def main() -> None:
    if not RECORDS.is_file():
        from generate_sandbox_records import main as generate

        generate()
    cases = json.loads(RECORDS.read_text(encoding="utf-8"))
    registry = RulesetRegistry(unmatched="allow")
    info = registry.register({"spec": "agent-pdp/v1"})
    registry.open_task(info.ruleset_id, "user-a", "task-a")
    decide = Decide(
        Host(),
        source={"framework": "jiuwenswarm", "session_id": "sandbox-e2e", "agent_id": "leader"},
        registry=registry,
        ruleset_id=info.ruleset_id,
        subject_id="user-a",
        task_id="task-a",
    )
    rows = []
    for case in cases:
        body = case["body"]
        decision = settle_native_record(decide, body, binding=BINDING)
        operation = body.get("operation") if isinstance(body.get("operation"), dict) else {}
        if decision.get("allow") is True and (
            operation.get("kind") in {"delete", "rmdir"} or operation.get("access") == "delete"
        ):
            decide.handle_operation_result(
                {
                    "spec": "native-operation-result/v1",
                    "request_id": body.get("request_id"),
                    "operation_id": body.get("operation_id"),
                    "success": True,
                    "disposition": "trash",
                }
            )
        rows.append(
            {
                "id": case["id"],
                "label": case["label"],
                "request_id": body.get("request_id"),
                "operation_id": body.get("operation_id"),
                "allow": decision.get("allow"),
                "reason": decision.get("reason"),
                "response": decision,
            }
        )
    RESULTS.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    counts: dict[str, int] = {}
    for row in rows:
        key = f"{'allow' if row['allow'] else 'deny'} {row['reason']}"
        counts[key] = counts.get(key, 0) + 1
    log_line(f"recorded {len(rows)} decisions in {RESULTS}")
    for key in sorted(counts):
        log_line(f"  {key}: {counts[key]}")


if __name__ == "__main__":
    main()
