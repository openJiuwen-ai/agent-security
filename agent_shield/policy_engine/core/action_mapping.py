"""Risk floors and the five-tier action map."""

from __future__ import annotations

from agent_shield.policy_engine.builtin.policy import RISK_RANK
from agent_shield.policy_engine.errors import PolicyError

DEFAULT_ACTION = {
    "none": "allow",
    "low": "allow",
    "medium": "ask",
    "high": "ask",
    "critical": "deny",
}
_STRENGTH = {"allow": 0, "ask": 1, "deny": 2}
_OPEN_FLOOR = {
    "fs.write.outside": "low",
    "fs.delete.outside": "low",
    "fs.write.system_new": "low",
    "net.egress": "low",
    "schedule.create": "low",
    "git.force_push": "none",
    "fs.read.userFiles": "none",
    "fs.write.userFiles": "none",
    "fs.delete.userFiles": "none",
    "net.fetch.get": "none",
    "net.connect.unlisted": "none",
    "fs.read.nonsensitive_outside": "none",
    "net.connect.allowlist": "none",
    "net.fetch.allowlist": "none",
    "net.egress.allowlist": "none",
}


def floor_for(rule_id: str, default_risk: str) -> str:
    return _OPEN_FLOOR.get(rule_id, default_risk)


def check_override(rule_id: str, default_risk: str, new_risk: str) -> None:
    floor = floor_for(rule_id, default_risk)
    if new_risk not in RISK_RANK or RISK_RANK[new_risk] < RISK_RANK[floor]:
        raise PolicyError(f"{rule_id} cannot drop below {floor}")


def effective_action(risk: str, baseline: dict[str, str] | None, ruleset: dict[str, str] | None) -> str:
    chosen: list[str] = []
    for mapping in (baseline or {}, ruleset or {}):
        action = mapping.get(risk)
        if action in _STRENGTH:
            chosen.append(action)
    if not chosen:
        return DEFAULT_ACTION[risk]
    return max(chosen, key=lambda action: _STRENGTH[action])


def reject_user_mapping(document: dict) -> None:
    if isinstance(document, dict) and "action_mapping" in document:
        raise PolicyError("user rules cannot set action_mapping")


def validate_action_mapping(mapping: dict | None) -> dict[str, str]:
    if mapping is None:
        return {}
    if not isinstance(mapping, dict):
        raise PolicyError("action_mapping must be a mapping")
    cleaned: dict[str, str] = {}
    for risk, action in mapping.items():
        if risk not in DEFAULT_ACTION or action not in _STRENGTH:
            raise PolicyError(f"invalid action_mapping entry: {risk} -> {action}")
        cleaned[str(risk)] = str(action)
    return cleaned
