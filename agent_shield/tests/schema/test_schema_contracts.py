"""JSON schemas accept the objects the PDP and adapters emit."""

import json

from jsonschema import Draft202012Validator

from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.policy_engine.evaluate import evaluate
from agent_shield.intercepts.native_call.dll_guard.events import operation_to_event
from agent_shield.tests.paths import SCHEMA_DIR

ROOT = SCHEMA_DIR


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / name).read_text(encoding="utf-8"))
    return Draft202012Validator(schema)


def test_decision_and_event_match_their_schemas():
    event = {
        "spec": "agent-event/v1",
        "id": "evt_schema",
        "time": "2026-10-19T00:00:00Z",
        "source": {"framework": "jiuwenswarm", "session_id": "s"},
        "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
        "action": {
            "category": "tool_call",
            "effects": [{"type": "fs.read", "path": "C:/Users/me/proj/README.md"}],
            "normalization": {"status": "ok"},
        },
    }
    _validator("agent-event.v1.json").validate(event)
    decision = evaluate_event(event)
    _validator("agent-decision.v1.json").validate(decision)
    invalid = evaluate_event({"spec": "nope"})
    _validator("agent-decision.v1.json").validate(invalid)
    assert invalid["action"] == "deny"
    assert invalid["winner_rule_id"] == "invalid_event"
    bare = evaluate(event)
    _validator("agent-decision.v1.json").validate(bare)
    assert bare["winner_rule_id"] == "invalid_ruleset"


def test_suggested_grant_matches_the_decision_schema():
    from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset
    from agent_shield.policy_engine.core.ruleset import load_ruleset

    base = load_builtin_ruleset()
    rules = load_ruleset(
        {
            "spec": "agent-pdp/v1",
            "behavior_rules": [
                {
                    "id": "tp.read.note",
                    "risk": "high",
                    "note": "读取笔记",
                    "user_grantable": True,
                    "when": {"effect": "fs.read", "path.glob_any": ["**/notes.txt"]},
                }
            ],
        },
        baseline=base.behaviors,
        catalogs=base.catalogs,
    )
    event = {
        "spec": "agent-event/v1",
        "id": "evt_grant",
        "time": "2026-10-19T00:00:00Z",
        "source": {"framework": "jiuwenswarm", "session_id": "s"},
        "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
        "action": {
            "category": "tool_call",
            "raw": {"name": "bash"},
            "effects": [{"type": "fs.read", "path": "C:/Users/me/proj/notes.txt"}],
            "normalization": {"status": "ok"},
        },
        "execution": {"intercept": False},
        "host_capabilities": {"hitl": True, "auto_intent": True},
    }
    decision = evaluate_event(event, ruleset=rules, subject_id="user-a")
    _validator("agent-decision.v1.json").validate(decision)
    assert decision["grants"] and "mac" not in decision["grants"][0]
    assert decision["winner_rule_id"] == "tp.read.note"


def test_operation_event_and_audit_schemas():
    event = operation_to_event(
        {"category": "file", "kind": "read", "access": "read",
         "resources": [{"path": "C:/Users/me/proj/README.md", "role": "subject"}]},
        {"workspace": {"root": "C:/Users/me/proj", "os": "windows", "trusted_dirs": []},
         "source": {"framework": "jiuwenswarm"}},
    )
    _validator("agent-event.v1.json").validate(event)
    _validator("audit-event.v1.json").validate(
        {
            "time": "2026-10-19T00:00:00Z",
            "event_id": "evt",
            "framework": "jiuwenswarm",
            "session_id": "s",
            "action": "allow",
            "raw_action": "allow",
            "winner_rule_id": "fs.read.userFiles",
            "tool_raw_name": "read_file",
        }
    )
