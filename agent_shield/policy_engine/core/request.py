"""DecisionRequest parsing. Rule failures stay separate from event failures."""

from __future__ import annotations

from dataclasses import dataclass, field

from agent_shield.policy_engine.core.grants import grant_provenance

_FIELDS = {"spec", "request_id", "ruleset_id", "subject_id", "task_id", "event", "user_rules", "grants"}
_GRANT_FORBIDDEN = {"action", "pattern", "match", "cidrs", "mac"}
_MAX_RULES = 500
_MAX_GRANTS = 2000


@dataclass
class ParsedRequest:
    error: str | None
    request_id: str = ""
    ruleset_id: str = ""
    subject_id: str = ""
    task_id: str = ""
    event: dict = field(default_factory=dict)
    user_rules: list = field(default_factory=list)
    grants: list = field(default_factory=list)


def parse_decision_request(payload: dict) -> ParsedRequest:
    if not isinstance(payload, dict) or payload.get("spec") != "agent-decision-request/v1":
        return ParsedRequest("invalid_ruleset")
    if set(payload) - _FIELDS:
        return ParsedRequest("invalid_ruleset")
    request_id = payload.get("request_id", "")
    if not isinstance(request_id, str):
        return ParsedRequest("invalid_ruleset")
    subject_id = payload.get("subject_id")
    if not isinstance(subject_id, str) or not subject_id:
        return ParsedRequest("missing_subject")
    task_id = payload.get("task_id")
    if not isinstance(task_id, str) or not task_id:
        return ParsedRequest("invalid_ruleset")
    ruleset_id = payload.get("ruleset_id", "")
    if not isinstance(ruleset_id, str):
        return ParsedRequest("invalid_ruleset")
    event = payload.get("event")
    if not isinstance(event, dict):
        return ParsedRequest("invalid_ruleset")
    user_rules = payload.get("user_rules", [])
    grants = payload.get("grants", [])
    if not isinstance(user_rules, list) or not isinstance(grants, list):
        return ParsedRequest("invalid_ruleset")
    if len(user_rules) > _MAX_RULES or len(grants) > _MAX_GRANTS:
        return ParsedRequest("invalid_ruleset")
    if any(not isinstance(item, dict) or "source" in item for item in user_rules):
        return ParsedRequest("invalid_ruleset")
    if any(_bad_grant(item) for item in grants):
        return ParsedRequest("invalid_ruleset")
    return ParsedRequest(None, request_id, ruleset_id, subject_id, task_id, event, user_rules, grants)


def _bad_grant(item: dict) -> bool:
    if not isinstance(item, dict) or set(item) & _GRANT_FORBIDDEN:
        return True
    if not isinstance(item.get("subject_id"), str) or not item["subject_id"]:
        return True
    if grant_provenance(item) is None:
        return True
    hosts = item.get("hosts", [])
    names = item.get("names", [])
    tokens = item.get("tokens", [])
    if not isinstance(hosts, list) or not isinstance(names, list) or not isinstance(tokens, list):
        return True
    values = hosts + names + tokens
    return any(isinstance(value, str) and "*" in value for value in values)
