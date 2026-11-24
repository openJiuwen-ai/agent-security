"""Turn one native record into a decision. Policy only sees the event."""

from __future__ import annotations

from dataclasses import dataclass

from agent_shield.policy_engine.matchers.paths import paths_equal
from agent_shield.intercepts.native_call.record import native_record_to_event


@dataclass(frozen=True)
class ProcessBinding:
    pid: int
    parent_pid: int
    process_instance_id: str
    image: str
    user_sid: str
    integrity_level: str


def settle_native_record(decide, record: dict, *, binding: ProcessBinding) -> dict:
    request_id = record.get("request_id") if isinstance(record, dict) else ""
    operation_id = record.get("operation_id") if isinstance(record, dict) else ""
    if not isinstance(request_id, str):
        request_id = ""
    if not isinstance(operation_id, str):
        operation_id = ""
    if isinstance(record, dict) and {"user_rules", "grants", "rules", "preauth"} & set(record):
        return _native(request_id, operation_id, "", False, "invalid_event")
    if _record_error(record):
        return _native(request_id, operation_id, "", False, "invalid_event")
    mismatch = _binding_error(record, binding)
    if mismatch:
        return _native(request_id, operation_id, "", False, mismatch)
    event = native_record_to_event(record, _context(decide))
    delete_id = operation_id if _is_delete(record) else ""
    if delete_id:
        if decide.begin_delete(delete_id):
            for effect in event["action"]["effects"]:
                if effect.get("type") == "fs.delete":
                    effect["bulk"] = True
    settled = decide.settle(event)
    if delete_id and settled["action"] != "allow":
        decide.handle_operation_result(
            {"spec": "native-operation-result/v1", "operation_id": delete_id, "success": False}
        )
    return _native(
        request_id,
        operation_id,
        settled.get("event_id") or "",
        settled["action"] == "allow",
        settled.get("winner_rule_id") or "",
    )


def _context(decide) -> dict:
    context = dict(decide.host_context())
    context["execution"] = {
        "plane": "host",
        "provider": "windows-process-guard",
        "intercept": True,
        "escaped": False,
        "escape_reason": "",
    }
    return context


def _record_error(record: dict) -> str | None:
    if not isinstance(record, dict) or record.get("spec") != "native-record/v1":
        return "spec"
    for field in ("request_id", "operation_id", "time"):
        if not isinstance(record.get(field), str) or not record[field]:
            return field
    process = record.get("process")
    operation = record.get("operation")
    if not isinstance(process, dict) or not isinstance(operation, dict):
        return "shape"
    for field in ("pid", "tid", "process_instance_id"):
        if field not in process:
            return field
    if not isinstance(operation.get("resources"), list):
        return "resources"
    if operation.get("category") not in {"file", "process", "network"}:
        return "category"
    return None


def _binding_error(record: dict, binding: ProcessBinding) -> str | None:
    process = record["process"]
    expected = {
        "pid": binding.pid,
        "parent_pid": binding.parent_pid,
        "process_instance_id": binding.process_instance_id,
    }
    for key, value in expected.items():
        if key in process and process.get(key) != value:
            return "process_identity_mismatch"
    image = process.get("image")
    if isinstance(image, str) and image and not paths_equal(image, binding.image, os_name="windows"):
        return "process_identity_mismatch"
    identity = process.get("identity") if isinstance(process.get("identity"), dict) else {}
    if identity.get("user_sid") not in (None, "", binding.user_sid) and identity.get("user_sid") != binding.user_sid:
        return "process_identity_mismatch"
    level = identity.get("integrity_level")
    if isinstance(level, str) and level and level.casefold() != binding.integrity_level.casefold():
        return "process_identity_mismatch"
    return None


def _is_delete(record: dict) -> bool:
    operation = record["operation"]
    return operation.get("kind") in {"delete", "rmdir"} or operation.get("access") == "delete"


def _native(request_id: str, operation_id: str, event_id: str, allow: bool, reason: str) -> dict:
    return {
        "spec": "native-decision/v1",
        "request_id": request_id,
        "operation_id": operation_id,
        "event_id": event_id,
        "allow": allow,
        "reason": reason,
    }
