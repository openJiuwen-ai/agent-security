"""Builtin tiers map onto allow, ask, and deny."""

from agent_shield.policy_engine.core.envelope import evaluate_event as evaluate

from agent_shield.tests.policy_engine._factory import exec_effect, fs, make_event


def test_action_table():
    none = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/README.md")]))
    low = evaluate(make_event([fs("fs.write", "C:/Users/me/proj/a.txt")]))
    medium = evaluate(make_event([exec_effect(["git", "push", "--force"])]))
    high = evaluate(make_event([fs("fs.read", "C:/Users/me/proj/.env")]))
    critical = evaluate(make_event([exec_effect(["sudo", "id"])]))
    assert none["action"] == "allow"
    assert none["winner_rule_id"] == "fs.read.userFiles"
    assert low["action"] == "allow"
    assert low["winner_rule_id"] == "fs.write.userFiles"
    assert medium["action"] == "ask"
    assert medium["winner_rule_id"] == "git.force_push"
    assert high["action"] == "ask"
    assert high["winner_rule_id"] == "fs.read.sensitiveFiles"
    assert critical["action"] == "deny"
    assert critical["winner_rule_id"] == "privilege.escalate"
