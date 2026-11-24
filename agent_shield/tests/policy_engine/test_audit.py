"""File JSONL audit redacts secrets and sensitive paths."""

import json

from agent_shield.policy_engine.audit import write_audit
from agent_shield.policy_engine.builtin.policy import load_builtin_policy

WORKSPACE = {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}
POLICY = load_builtin_policy()


def test_audit_redacts_secrets_and_sensitive_paths(tmp_path):
    path = tmp_path / "audit.jsonl"
    event = {
        "spec": "agent-event/v1",
        "id": "evt_audit",
        "source": {"framework": "jiuwenswarm", "session_id": "s"},
        "workspace": WORKSPACE,
        "action": {"raw": {"name": "C:/Users/me/proj/.env"}, "category": "tool_call"},
    }
    decision = {
        "event_id": "evt_audit",
        "risk_class": "high",
        "action": "ask",
        "confirmation": "force",
        "matched": ["fs.sensitive"],
        "reason": "fs.sensitive",
    }
    write_audit(decision, event, path, POLICY)
    line = json.loads(path.read_text(encoding="utf-8"))
    assert line["tool_raw_name"] == "<redacted-path>"
    event["action"]["raw"]["name"] = "sk-abcdefghijklmnopqrstuvwxyz"
    write_audit(decision, event, path, POLICY)
    second = path.read_text(encoding="utf-8").splitlines()[1]
    assert "sk-" not in second
    assert "***" in second
