"""Decision envelope shared by evaluate() and the isolated PDP."""

from __future__ import annotations

from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset
from agent_shield.policy_engine.core.ruleset import Ruleset
from agent_shield.policy_engine.core.intent import allows_auto
from agent_shield.policy_engine.builtin.policy import load_builtin_policy

_MODEL = {"summary": "模型调用已放行", "content": "", "risk": "无风险"}
_INVALID = {"summary": "事件格式不正确，已拒绝", "content": "", "risk": "无风险"}


def _validation_error(event: dict) -> str | None:
    if event.get("spec") != "agent-event/v1":
        return "spec"
    for field in ("id", "time"):
        if not isinstance(event.get(field), str) or not event[field].strip():
            return field
    if not isinstance(event.get("source"), dict):
        return "source"
    workspace = event.get("workspace")
    if not isinstance(workspace, dict):
        return "workspace"
    if "root" in workspace and not isinstance(workspace.get("root"), str):
        return "workspace.root"
    if "os" in workspace and workspace.get("os") not in {"windows", "posix"}:
        return "workspace.os"
    if "trusted_dirs" in workspace and not _string_list(workspace.get("trusted_dirs")):
        return "workspace.trusted_dirs"
    if "preauth" in event:
        return "preauth"
    intent = event.get("user_intent", None)
    if intent is not None and not isinstance(intent, dict):
        return "user_intent"
    action = event.get("action")
    if not isinstance(action, dict):
        return "action"
    if action.get("category") not in {"tool_call", "model_call"}:
        return "action.category"
    effects = action.get("effects", [])
    if not isinstance(effects, list) or not all(isinstance(item, dict) for item in effects):
        return "effects"
    normalization = action.get("normalization", {"status": "ok"})
    if not isinstance(normalization, dict):
        return "normalization"
    if normalization.get("status", "ok") not in {"ok", "partial", "failed"}:
        return "normalization.status"
    caps = event.get("host_capabilities", {})
    if caps is not None and not isinstance(caps, dict):
        return "host_capabilities"
    execution = event.get("execution", {})
    if execution is not None and not isinstance(execution, dict):
        return "execution"
    if isinstance(execution, dict) and execution:
        plane = execution.get("plane", "host")
        if plane not in {"host", "sandbox"}:
            return "execution.plane"
        if "intercept" in execution and not isinstance(execution.get("intercept"), bool):
            return "execution.intercept"
        if "escaped" in execution and not isinstance(execution.get("escaped"), bool):
            return "execution.escaped"
        if execution.get("escaped") is True and plane != "host":
            return "execution.escaped"
    return None


def _string_list(value) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def evaluate_event(
    event: dict,
    *,
    ruleset: Ruleset | None = None,
    user_rules: list | tuple = (),
    grants: list | tuple = (),
    subject_id: str | None = None,
) -> dict:
    if not isinstance(event, dict) or _validation_error(event):
        event_id = event.get("id") if isinstance(event, dict) and isinstance(event.get("id"), str) else ""
        return _envelope(event_id, "deny", "invalid_event", _INVALID, ())
    if event["action"]["category"] == "model_call":
        return _envelope(event.get("id") or "", "allow", None, _MODEL, ())
    active = ruleset or load_builtin_ruleset()
    decision = active.decide(
        event,
        user_rules=user_rules,
        grants=grants,
        intent_allows=allows_auto(event, load_builtin_policy()),
    )
    event_time = event.get("time") if isinstance(event.get("time"), str) else ""
    stamped = _stamp(decision.grants, subject_id, str(event.get("id") or ""), event_time)
    return _envelope(
        event.get("id") or "",
        decision.action,
        decision.winner_rule_id,
        decision.user_visible,
        stamped,
        decision.raw_action,
    )


def decision_denied(event_id: str, code: str) -> dict:
    text = {
        "invalid_ruleset": "请求格式不正确，已拒绝",
        "missing_ruleset": "没有规则集，已拒绝",
        "unknown_ruleset": "规则集已失效，已拒绝",
        "unknown_task": "任务未打开，已拒绝",
        "missing_subject": "没有主体，已拒绝",
    }
    visible = {"summary": text.get(code, "已拒绝"), "content": "", "risk": "无风险"}
    return _envelope(event_id, "deny", code, visible, ())


def _stamp(grants: tuple[dict, ...], subject_id: str | None, event_id: str, approved_at: str) -> tuple[dict, ...]:
    stamped = []
    for grant in grants:
        item = dict(grant)
        if subject_id:
            item["subject_id"] = subject_id
            item.setdefault(
                "provenance",
                {"decision_id": event_id, "approved_at": approved_at, "via": "hitl"},
            )
        stamped.append(item)
    return tuple(stamped)


def _envelope(
    event_id: str,
    action: str,
    winner: str | None,
    visible: dict[str, str],
    grants: tuple[dict, ...],
    raw_action: str | None = None,
) -> dict:
    return {
        "spec": "agent-decision/v1",
        "event_id": event_id,
        "action": action,
        "winner_rule_id": winner,
        "advice": {"user_visible": visible},
        "grants": list(grants),
        "raw_action": action if raw_action is None else raw_action,
    }
