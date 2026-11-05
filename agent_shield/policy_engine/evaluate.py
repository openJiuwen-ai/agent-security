"""Public PDP entry. A DecisionRequest is decided by the ruleset pipeline."""

from __future__ import annotations

from agent_shield.policy_engine.audit import write_audit


def evaluate(
    request: dict,
    *,
    ruleset=None,
    audit_path: str | None = None,
    unmatched: str = "none",
) -> dict:
    """Return the decision envelope. A bare event is invalid_ruleset, not an exception."""
    from agent_shield.policy_engine.builtin.rules import builtin_catalogs, load_builtin_ruleset
    from agent_shield.policy_engine.core.envelope import decision_denied, evaluate_event
    from agent_shield.policy_engine.core.request import parse_decision_request
    from agent_shield.policy_engine.core.ruleset import load_ruleset
    from agent_shield.policy_engine.errors import PolicyError

    if not isinstance(request, dict):
        result = decision_denied("", "invalid_ruleset")
        write_audit(result, {}, audit_path, None)
        return result
    parsed = parse_decision_request(request)
    event = parsed.event if isinstance(parsed.event, dict) else {}
    event_id = event.get("id") if isinstance(event.get("id"), str) else ""
    if parsed.error:
        result = decision_denied(event_id, parsed.error)
        write_audit(result, event, audit_path, None)
        return result
    try:
        active = _active_ruleset(ruleset, unmatched, load_builtin_ruleset, load_ruleset, builtin_catalogs)
    except PolicyError:
        result = decision_denied(event_id, "invalid_ruleset")
        write_audit(result, event, audit_path, None)
        return result
    result = evaluate_event(
        event,
        ruleset=active,
        user_rules=parsed.user_rules,
        grants=parsed.grants,
        subject_id=parsed.subject_id,
    )
    write_audit(result, event, audit_path, None)
    return result


def _active_ruleset(ruleset, unmatched: str, load_builtin_ruleset, load_ruleset, builtin_catalogs):
    if isinstance(ruleset, dict):
        base = load_builtin_ruleset(unmatched=unmatched)
        return load_ruleset(ruleset, baseline=base.behaviors, catalogs=builtin_catalogs(), unmatched=unmatched)
    if ruleset is None and unmatched != "none":
        return load_builtin_ruleset(unmatched=unmatched)
    return ruleset
