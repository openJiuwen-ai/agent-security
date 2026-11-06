"""Decide settles ask, merges duplicate prompts, and records the audit."""

import threading

import pytest

from agent_shield.policy_engine.server import Decide
from agent_shield.policy_engine.server.host import VersionedRules
from agent_shield.policy_engine.server.registry import RulesetRegistry, RulesetRejected, fingerprint
from agent_shield.tests.policy_engine._factory import fs, make_event
from agent_shield.tests.policy_engine.server.support import FakeHost, decide


def test_hitl_false_settles_medium_as_deny():
    host = FakeHost(hitl=False)
    event = make_event([fs("fs.write", "D:/other/a.txt")], host_capabilities={"hitl": False, "auto_intent": True})
    settled = decide(host).settle(event)
    assert settled["pdp_action"] == "ask"
    assert settled["action"] == "deny"
    assert host.prompts == 0


def test_duplicate_asks_share_one_approval():
    host = FakeHost(answer=True, hitl=True)
    host.block = True
    task = decide(host)
    event = make_event([fs("fs.read", "C:/Users/me/proj/.env")])
    results = []

    def run():
        results.append(task.settle(event))

    first = threading.Thread(target=run)
    first.start()
    assert host.entered.wait(timeout=2)
    second = threading.Thread(target=run)
    second.start()
    host.release.set()
    first.join(timeout=2)
    second.join(timeout=2)
    assert host.prompts == 1
    assert [item["action"] for item in results] == ["allow", "allow"]
    again = task.settle(event)
    assert again["action"] == "allow"
    assert host.prompts == 2


def test_close_denies_a_waiting_approval():
    host = FakeHost(answer=True)
    host.block = True
    task = decide(host)
    outcome = {}

    def run():
        outcome["result"] = task.settle(make_event([fs("fs.read", "C:/Users/me/proj/.env")]))

    worker = threading.Thread(target=run)
    worker.start()
    assert host.entered.wait(timeout=2)
    task.close()
    host.release.set()
    worker.join(timeout=2)
    assert outcome["result"]["action"] == "deny"


def test_unopened_task_is_refused_and_close_releases_only_that_triple():
    registry = RulesetRegistry()
    info = registry.register({"spec": "agent-pdp/v1"})
    with pytest.raises(RulesetRejected) as caught:
        Decide(
            FakeHost(),
            source={"framework": "jiuwenswarm"},
            registry=registry,
            ruleset_id=info.ruleset_id,
            subject_id="user-a",
            task_id="missing",
        )
    assert caught.value.code == "unknown_task"
    task = decide(FakeHost(), also_open=("user-b", "task-a"))
    task.close()
    assert task.registry.resolve(task.ruleset_id, "user-a", "task-a").error == "unknown_task"
    assert task.registry.resolve(task.ruleset_id, "user-b", "task-a").error is None


def test_host_failure_denies_the_event():
    host = FakeHost(hitl=False)
    host.fail = True
    failed = decide(host).settle(make_event([fs("fs.read", "C:/Users/me/proj/README.md")]))
    assert failed["action"] == "deny"
    assert failed["winner_rule_id"] == "host_context_unavailable"


def test_grant_for_another_subject_does_not_allow():
    host = FakeHost(hitl=False)
    host.saved_grants = [
        {
            "id": "g",
            "object": "file",
            "ops": ["read"],
            "path": "C:/Users/me/proj/.env",
            "subject_id": "user-b",
            "provenance": {"decision_id": "dec", "approved_at": "2026-11-03T00:00:00Z", "via": "hitl"},
        }
    ]
    event = make_event(
        [fs("fs.read", "C:/Users/me/proj/.env")],
        host_capabilities={"hitl": False, "auto_intent": True},
    )
    task = decide(host)
    settled = task.settle(event)
    assert settled["pdp_action"] == "ask"
    assert settled["action"] == "deny"
    assert host.prompts == 0
    assert any(item["op"] == "grant_rejected" and item["grant_id"] == "g" for item in task.registry.audit)
    host.saved_grants[0]["subject_id"] = "user-a"
    document = {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "user_grantable": True}]}
    allowed = decide(host, document=document).settle(event)
    assert allowed["action"] == "allow"
    assert allowed["winner_rule_id"] == "g"
    assert host.prompts == 0
    accepted = [item for item in task.registry.audit if item["op"] == "grant_accepted"]
    assert accepted == []
    allowed_decide = decide(host, document=document)
    assert allowed_decide.settle(event)["winner_rule_id"] == "g"
    accepted = [item for item in allowed_decide.registry.audit if item["op"] == "grant_accepted"]
    assert accepted[-1]["provenance"]["decision_id"] == "dec"
    assert accepted[-1]["grant_object"] == "file"


def test_settle_audits_the_winner_and_the_host_action():
    host = FakeHost(hitl=False)
    event = make_event([fs("fs.write", "D:/other/a.txt")], host_capabilities={"hitl": False, "auto_intent": True})
    task = decide(host)
    settled = task.settle(event)
    recorded = task.registry.audit[-1]
    assert settled["action"] == "deny"
    assert recorded["op"] == "decide"
    assert recorded["mode"] == "trusted"
    assert recorded["subject_id"] == "user-a"
    assert recorded["winner_rule_id"] == "fs.write.outside"
    assert recorded["raw_action"] == "ask"
    assert recorded["pdp_action"] == "ask"
    assert recorded["action"] == "deny"
    assert recorded["version"] == 1
    assert recorded["unmatched"] == "none"
    assert recorded["request_fingerprint"] == fingerprint({"user_rules": [], "grants": []})


def test_same_rule_version_skips_the_fingerprint(monkeypatch):
    calls = {"n": 0}
    real = fingerprint

    def counted(document):
        calls["n"] += 1
        return real(document)

    monkeypatch.setattr("agent_shield.policy_engine.server.decide.fingerprint", counted)
    host = FakeHost()
    host.rules = VersionedRules(1, [{"id": "u", "object": "file", "action": "deny", "pattern": ["**/*.txt"]}])
    host.saved_grants = VersionedRules(1, [])
    event = make_event([fs("fs.read", "C:/Users/me/proj/a.txt")])
    task = decide(host)
    assert task.settle(event)["action"] == "deny"
    assert task.settle(event)["winner_rule_id"] == "u"
    assert calls["n"] == 1
    host.rules = VersionedRules(2, [])
    assert task.settle(event)["action"] == "allow"
    assert calls["n"] == 2


def test_unmatched_rewrite_keeps_the_raw_action_in_the_audit():
    host = FakeHost(hitl=False)
    event = make_event(
        [{"type": "process.exec", "argv": ["powershell", "-Command", "Get-Date"]}],
        host_capabilities={"hitl": False, "auto_intent": True},
    )
    task = decide(host, unmatched="ask")
    task.settle(event)
    recorded = task.registry.audit[-1]
    assert recorded["raw_action"] == "undetermined"
    assert recorded["pdp_action"] == "ask"
    assert recorded["action"] == "deny"
    assert recorded["unmatched"] == "ask"


def test_argv_without_a_command_line_is_audited():
    host = FakeHost(hitl=False)
    event = make_event(
        [{"type": "process.exec", "argv": ["git", "push"]}],
        host_capabilities={"hitl": False, "auto_intent": True},
    )
    task = decide(host)
    task.settle(event)
    recorded = task.registry.audit[-1]
    assert recorded["missing_command_line"] == [["git", "push"]]
