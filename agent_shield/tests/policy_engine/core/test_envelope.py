"""evaluate_event: builtin judgment and suggested grants."""

from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.policy_engine.core.grants import accept_grant

from agent_shield.tests.policy_engine._factory import make_event


def test_invalid_event_denies_and_model_call_allows():
    invalid = evaluate_event({"spec": "nope"})
    model = evaluate_event(make_event([], category="model_call"))
    assert invalid["action"] == "deny"
    assert invalid["winner_rule_id"] == "invalid_event"
    assert model["action"] == "allow"
    assert model["advice"]["user_visible"]["summary"] == "模型调用已放行"
    assert model["grants"] == []


def test_secret_read_asks_without_an_always_allow_grant():
    path = "C:/Users/me/proj/.env"
    host = evaluate_event(make_event([{"type": "fs.read", "path": path}]))
    sandbox = evaluate_event(
        make_event([{"type": "fs.read", "path": path}], execution={"plane": "sandbox", "provider": "jiuwenbox"})
    )
    assert host["action"] == "ask"
    assert host["winner_rule_id"] == "fs.read.sensitiveFiles"
    assert host["advice"]["user_visible"]["summary"] == "读取敏感文件需要授权"
    assert host["grants"] == []
    assert sandbox["action"] == host["action"]
    assert sandbox["winner_rule_id"] == host["winner_rule_id"]


def test_event_preauth_is_invalid():
    event = make_event(
        [{"type": "fs.write", "path": "D:/other/a.txt", "exists": False}],
        preauth=[{"grant": "allow_paths", "path": "D:/other", "ops": ["write"]}],
    )
    result = evaluate_event(event)
    assert result["action"] == "deny"
    assert result["winner_rule_id"] == "invalid_event"


def test_unobserved_ask_has_no_always_allow_grant():
    event = make_event([], normalization="partial")
    event["action"]["command_line"] = "powershell -enc AA=="
    result = evaluate_event(event)
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "exec.unobserved"
    assert result["grants"] == []


def test_builtin_asks_do_not_suggest_grants():
    event = make_event(
        [
            {"type": "fs.read", "path": "/etc/shadow"},
            {"type": "fs.delete", "path": "/tmp/build", "force": False},
        ],
        workspace={"root": "/work", "os": "posix"},
    )
    result = evaluate_event(event, subject_id="user-a")
    assert result["action"] == "ask"
    assert result["grants"] == []


def test_grantable_asks_suggest_two_grants():
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
                },
                {
                    "id": "tp.delete.note",
                    "risk": "high",
                    "note": "删除笔记",
                    "user_grantable": True,
                    "when": {"effect": "fs.delete", "path.glob_any": ["**/notes.txt"]},
                },
            ],
        },
        baseline=base.behaviors,
        catalogs=base.catalogs,
    )
    event = make_event(
        [
            {"type": "fs.read", "path": "C:/Users/me/proj/notes.txt"},
            {"type": "fs.delete", "path": "C:/Users/me/proj/notes.txt"},
        ]
    )
    result = evaluate_event(event, ruleset=rules, subject_id="user-a")
    assert result["action"] == "ask"
    assert [item["path"] for item in result["grants"]] == ["C:/Users/me/proj/notes.txt", "C:/Users/me/proj/notes.txt"]
    assert all("mac" not in item and accept_grant(item, subject_id="user-a") for item in result["grants"])
