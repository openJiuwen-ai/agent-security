"""The strictest finding wins, including across several effects."""

from agent_shield.policy_engine.core.envelope import evaluate_event as evaluate

from agent_shield.tests.policy_engine._factory import exec_effect, fs, make_event


def test_strictest_effect_wins():
    result = evaluate(
        make_event(
            [
                fs("fs.read", "C:/Users/me/proj/README.md"),
                fs("fs.write", "D:/other/a.txt"),
                exec_effect(["sudo", "id"]),
            ]
        )
    )
    assert result["action"] == "deny"
    assert result["winner_rule_id"] == "privilege.escalate"
