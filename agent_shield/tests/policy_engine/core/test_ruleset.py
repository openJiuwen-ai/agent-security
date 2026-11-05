"""Loading an agent-pdp/v1 ruleset, user rules, and grants."""

import pytest

from agent_shield.policy_engine.core.grants import accept_grant
from agent_shield.policy_engine.models.types import BehaviorRule
from agent_shield.policy_engine.core.ruleset import load_grants, load_ruleset, load_user_rules
from agent_shield.policy_engine.errors import PolicyError

SENSITIVE = BehaviorRule(
    id="fs.read.sensitiveFiles",
    risk="high",
    source="builtin",
    note="读取敏感文件",
    when={"effect": "fs.read"},
)


def _event(effects):
    return {
        "workspace": {"root": "C:/Users/me/proj", "os": "windows"},
        "action": {
            "category": "tool_call",
            "raw": {"name": "bash"},
            "effects": effects,
            "normalization": {"status": "ok"},
        },
        "execution": {"intercept": False},
    }


def test_loaded_behavior_is_judged_with_its_catalog():
    ruleset = load_ruleset(
        {
            "spec": "agent-pdp/v1",
            "catalogs": {"projectKeys": {"kind": "glob", "entries": ["**/secrets.yaml"]}},
            "behavior_rules": [
                {
                    "id": "tp.fs.projectKeys",
                    "risk": "high",
                    "note": "读写项目密钥文件",
                    "when": {"effect": ["fs.read", "fs.write", "fs.delete"], "path.glob_any": "projectKeys"},
                }
            ],
        }
    )
    decision = ruleset.decide(_event([{"type": "fs.read", "path": "C:/Users/me/proj/secrets.yaml"}]))
    assert decision.action == "ask"
    assert decision.winner_rule_id == "tp.fs.projectKeys"
    assert decision.user_visible["summary"] == "读写项目密钥文件需要授权"


def test_override_keeps_the_builtin_name_and_floor():
    raised = load_ruleset(
        {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "risk": "critical"}]},
        baseline=[SENSITIVE],
    )
    rule = raised.behaviors[0]
    assert (rule.risk, rule.note, rule.source, rule.when) == ("critical", "读取敏感文件", "builtin", SENSITIVE.when)
    with pytest.raises(PolicyError):
        load_ruleset(
            {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "risk": "medium"}]},
            baseline=[SENSITIVE],
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "note": "别的名字"}]},
            baseline=[SENSITIVE],
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [{"id": "fs.read.sensitiveFiles", "when": {"effect": "fs.read"}}],
            },
            baseline=[SENSITIVE],
        )


def test_new_behavior_shape_is_closed():
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [{"id": "tp.kubectl.delete", "risk": "medium", "when": {"effect": "process.exec"}}],
            }
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [
                    {"id": "kubectl.delete", "risk": "medium", "note": "x", "when": {"effect": "process.exec"}}
                ],
            }
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [
                    {
                        "id": "tp.kubectl.delete",
                        "risk": "medium",
                        "note": "执行 kubectl delete",
                        "when": {"effect": "process.exec"},
                    },
                    {"id": "tp.kubectl.delete", "risk": "high", "note": "再次", "when": {"effect": "process.exec"}},
                ],
            }
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [
                    {
                        "id": "tp.kubectl.delete",
                        "risk": "medium",
                        "note": "执行 kubectl delete",
                        "action": "allow",
                        "when": {"effect": "process.exec"},
                    }
                ],
            }
        )


def test_catalog_names_and_references_fail_closed():
    with pytest.raises(PolicyError):
        load_ruleset({"spec": "agent-pdp/v1", "catalogs": {"user_denylist_hosts": ["evil.test"]}})
    with pytest.raises(PolicyError):
        load_ruleset(
            {"spec": "agent-pdp/v1", "catalogs": {"sensitiveFiles": {"kind": "glob", "entries": ["**/*.tfvars"]}}}
        )
    with pytest.raises(PolicyError):
        load_ruleset({"spec": "agent-pdp/v1", "catalogs": {"projectKeys": ["**/secrets.yaml"]}})
    with pytest.raises(PolicyError):
        load_ruleset({"spec": "agent-pdp/v1", "catalogs": {"projectKeys": {"kind": "glob", "entries": []}}})
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "catalogs": {"corpGit": {"kind": "host", "entries": ["github.example.com"]}},
                "behavior_rules": [
                    {
                        "id": "tp.net.bad",
                        "risk": "low",
                        "note": "错误目录",
                        "when": {"effect": "net.egress", "endpoint.in_any_catalog": "projectKeys"},
                    },
                ],
            }
        )
    with pytest.raises(PolicyError):
        load_ruleset(
            {
                "spec": "agent-pdp/v1",
                "catalogs": {
                    "projectKeys": {"kind": "glob", "entries": ["**/secrets.yaml"]},
                    "corpGit": {"kind": "host", "entries": ["github.example.com"]},
                },
                "behavior_rules": [
                    {
                        "id": "tp.fs.bad",
                        "risk": "high",
                        "note": "主机不是路径",
                        "when": {"effect": "fs.read", "path.glob_any": "corpGit"},
                    },
                ],
            }
        )


def test_builtin_catalog_append_keeps_existing_entries_and_native_deny():
    ruleset = load_ruleset(
        {"spec": "agent-pdp/v1", "catalogs": {"sensitiveFiles": ["**/*.tfvars"], "nativeToolsDenyList": ["wevtutil"]}},
        catalogs={
            "sensitiveFiles": {"kind": "glob", "entries": ["**/.env"]},
            "nativeToolsDenyList": {"kind": "program", "entries": ["reg"]},
        },
    )
    assert ruleset.catalogs["sensitiveFiles"]["entries"] == ["**/.env", "**/*.tfvars"]
    decision = ruleset.decide(
        _event([{"type": "process.exec", "argv": ["notepad"], "image": r"C:\Windows\System32\wevtutil.exe"}])
    )
    assert decision.action == "deny"
    assert decision.winner_rule_id == "nativeTools.deny"


def test_user_allow_does_not_cover_a_loaded_third_party_ask():
    ruleset = load_ruleset(
        {
            "spec": "agent-pdp/v1",
            "behavior_rules": [
                {
                    "id": "tp.kubectl.delete",
                    "risk": "medium",
                    "note": "执行 kubectl delete",
                    "when": {"effect": "process.exec", "argv0": ["kubectl", "oc"], "argv_prefix": ["delete"]},
                }
            ],
        }
    )
    user = load_user_rules(
        {
            "spec": "agent-user-rules/v1",
            "rules": [{"id": "user-allow", "object": "command", "match": "*", "action": "allow"}],
        }
    )
    effect = {"type": "process.exec", "argv": ["kubectl", "delete", "pod"], "command_line": "kubectl delete pod"}
    decision = ruleset.decide(_event([effect]), user_rules=user)
    assert decision.action == "ask"
    assert decision.winner_rule_id == "tp.kubectl.delete"
    with pytest.raises(PolicyError):
        load_user_rules({"spec": "agent-user-rules/v1", "action_mapping": {"high": "allow"}})
    with pytest.raises(PolicyError):
        load_user_rules(
            {
                "spec": "agent-user-rules/v1",
                "rules": [
                    {
                        "id": "user-ask",
                        "object": "file",
                        "action": "ask",
                        "pattern": ["**/*.txt"],
                        "user_grantable": True,
                    }
                ],
            }
        )


def test_grant_subject_must_match_and_mac_is_rejected():
    from agent_shield.policy_engine.core.request import parse_decision_request

    grant = {
        "id": "g1",
        "object": "command",
        "tokens": ["git", "push"],
        "subject_id": "user-a",
        "provenance": {"decision_id": "dec", "approved_at": "2026-11-03T00:00:00Z", "via": "hitl"},
    }
    assert accept_grant(grant, subject_id="user-a")
    assert not accept_grant(grant, subject_id="user-b")
    assert load_grants([grant])[0].tokens == ("git", "push")
    with pytest.raises(PolicyError):
        load_grants([dict(grant, mac="old")])
    parsed = parse_decision_request(
        {
            "spec": "agent-decision-request/v1",
            "ruleset_id": "app",
            "subject_id": "user-a",
            "task_id": "task-a",
            "event": {"spec": "agent-event/v1"},
            "grants": [dict(grant, mac="old")],
        }
    )
    assert parsed.error == "invalid_ruleset"


def test_disabled_object_rule_does_not_match():
    ruleset = load_ruleset(
        {
            "spec": "agent-pdp/v1",
            "rules": [
                {"id": "block-env", "object": "file", "action": "deny", "pattern": ["**/.env"], "enabled": False}
            ],
        }
    )
    decision = ruleset.decide(_event([{"type": "fs.read", "path": "C:/Users/me/proj/.env"}]))
    assert decision.action == "undetermined"
    assert decision.winner_rule_id != "block-env"


def test_ruleset_rejects_unknown_fields():
    with pytest.raises(PolicyError):
        load_ruleset({"spec": "agent-pdp/v1", "unmatched": "deny"})


def test_command_grant_rejects_a_star_token():
    from agent_shield.policy_engine.core.request import parse_decision_request

    grant = {
        "id": "g",
        "object": "command",
        "tokens": ["*"],
        "subject_id": "user-a",
        "provenance": {"decision_id": "dec", "approved_at": "", "via": "hitl"},
    }
    parsed = parse_decision_request(
        {
            "spec": "agent-decision-request/v1",
            "ruleset_id": "app",
            "subject_id": "user-a",
            "task_id": "task-a",
            "event": {"spec": "agent-event/v1"},
            "grants": [grant],
        }
    )
    assert parsed.error == "invalid_ruleset"
    with pytest.raises(PolicyError):
        load_grants([grant])


def test_grant_without_provenance_is_rejected():
    with pytest.raises(PolicyError):
        load_grants([{"id": "g", "object": "command", "tokens": ["git"], "subject_id": "user-a"}])
