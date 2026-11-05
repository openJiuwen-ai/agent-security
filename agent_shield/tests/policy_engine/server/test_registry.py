"""Ruleset registry: versions, semantic updates, and task pins."""

import pytest

from agent_shield.policy_engine.server.registry import RulesetRegistry, RulesetRejected, fingerprint


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def _ids():
    counter = {"n": 0}

    def _next() -> str:
        counter["n"] += 1
        return f"{counter['n']:032x}"

    return _next


def _registry(**kwargs) -> RulesetRegistry:
    clock = kwargs.pop("clock", None) or Clock()
    return RulesetRegistry(clock=clock, id_factory=_ids(), **kwargs)


def _file(rule_id: str, action: str, pattern: str) -> dict:
    return {"id": rule_id, "object": "file", "action": action, "pattern": [pattern]}


def _doc(*rules, **extra) -> dict:
    document = {"spec": "agent-pdp/v1", "rules": list(rules)}
    document.update(extra)
    return document


def _behavior(rule_id: str, when: dict) -> dict:
    return {"id": rule_id, "risk": "high", "note": "执行 kubectl delete", "when": when}


def _open(registry: RulesetRegistry, ruleset_id: str, subject: str = "user-a", task: str = "task-a") -> None:
    registry.open_task(ruleset_id, subject, task)


def _rule(registry: RulesetRegistry, ruleset_id: str, rule_id: str, subject: str = "user-a", task: str = "task-a"):
    resolved = registry.resolve(ruleset_id, subject, task)
    assert resolved.error is None
    return next(rule for rule in resolved.ruleset.objects if rule.id == rule_id)


def test_register_returns_a_handle_and_rejects_invalid_documents():
    registry = _registry()
    info = registry.register({"spec": "agent-pdp/v1"})
    assert info.version == 1
    assert info.fingerprint == fingerprint({"spec": "agent-pdp/v1"})
    assert len(info.ruleset_id) == 32
    with pytest.raises(RulesetRejected) as caught:
        registry.register({"spec": "not-a-ruleset"})
    assert caught.value.code == "invalid_ruleset"
    assert registry.audit[-1]["op"] == "register_failed"
    assert "ruleset_id" not in registry.audit[-1]


def test_rulesets_do_not_affect_each_other():
    registry = _registry()
    first = registry.register(_doc(_file("keep", "deny", "**/*.txt"))).ruleset_id
    second = registry.register(_doc(_file("other", "ask", "**/*.log"))).ruleset_id
    registry.close(first)
    assert registry.resolve(first, "user-a", "task-a").error == "unknown_ruleset"
    _open(registry, second)
    assert _rule(registry, second, "other").action == "ask"


def test_update_bumps_the_version_and_keeps_the_old_one_on_failure():
    registry = _registry()
    ruleset_id = registry.register(_doc(_file("files", "ask", "**/*.txt"))).ruleset_id
    updated = registry.update(ruleset_id, _doc(_file("files", "deny", "**/*.txt")), expected_version=1)
    assert updated.version == 2
    assert updated.classification == "tighten"
    with pytest.raises(RulesetRejected) as conflict:
        registry.update(ruleset_id, _doc(_file("files", "allow", "**/*.txt")), expected_version=1)
    assert conflict.value.code == "version_conflict"
    with pytest.raises(RulesetRejected) as invalid:
        registry.update(
            ruleset_id,
            {
                "spec": "agent-pdp/v1",
                "behavior_rules": [{"id": "fs.read.sensitiveFiles", "when": {"effect": "fs.read"}}],
            },
            expected_version=2,
        )
    assert invalid.value.code == "invalid_ruleset"
    assert registry.status(ruleset_id).version == 2
    _open(registry, ruleset_id)
    assert _rule(registry, ruleset_id, "files").action == "deny"


def test_tighten_reaches_open_tasks_and_relax_does_not():
    registry = _registry()
    ruleset_id = registry.register(_doc(_file("files", "ask", "**/*.txt"))).ruleset_id
    _open(registry, ruleset_id)
    registry.update(ruleset_id, _doc(_file("files", "deny", "**/*.txt")), expected_version=1)
    assert _rule(registry, ruleset_id, "files").action == "deny"

    relaxed = _registry()
    ruleset_id = relaxed.register(_doc(_file("files", "deny", "**/*.txt"))).ruleset_id
    _open(relaxed, ruleset_id, task="open")
    result = relaxed.update(ruleset_id, _doc(_file("files", "allow", "**/*.txt")), expected_version=1)
    assert result.classification == "relax"
    assert _rule(relaxed, ruleset_id, "files", task="open").action == "deny"
    _open(relaxed, ruleset_id, task="later")
    assert _rule(relaxed, ruleset_id, "files", task="later").action == "allow"


def test_unprovable_matcher_and_behavior_edits_are_relax_or_tighten():
    registry = _registry()
    ruleset_id = registry.register(_doc(_file("files", "deny", "**/*.txt"))).ruleset_id
    _open(registry, ruleset_id)
    rewritten = registry.update(ruleset_id, _doc(_file("files", "deny", "**/*.log")), expected_version=1)
    assert rewritten.classification == "relax"
    assert _rule(registry, ruleset_id, "files").pattern == ("**/*.txt",)

    longer = _registry()
    first = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [_behavior("tp.kubectl.delete", {"effect": "process.exec", "argv_prefix": ["delete"]})],
    }
    second = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [
            _behavior("tp.kubectl.delete", {"effect": "process.exec", "argv_prefix": ["delete", "pod"]})
        ],
    }
    ruleset_id = longer.register(first).ruleset_id
    assert longer.update(ruleset_id, second, expected_version=1).classification == "relax"

    added = _registry()
    before = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [_behavior("tp.kubectl.delete", {"effect": "process.exec", "argv0": ["kubectl"]})],
    }
    after = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [
            _behavior(
                "tp.kubectl.delete", {"effect": "process.exec", "argv0": ["kubectl"], "argv_has_any": ["--force"]}
            )
        ],
    }
    ruleset_id = added.register(before).ruleset_id
    assert added.update(ruleset_id, after, expected_version=1).classification == "relax"

    wider = _registry()
    before = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [_behavior("tp.kubectl.delete", {"effect": "process.exec", "argv0": ["kubectl"]})],
    }
    after = {
        "spec": "agent-pdp/v1",
        "behavior_rules": [_behavior("tp.kubectl.delete", {"effect": "process.exec", "argv0": ["kubectl", "oc"]})],
    }
    ruleset_id = wider.register(before).ruleset_id
    assert wider.update(ruleset_id, after, expected_version=1).classification == "tighten"


def test_runtime_relax_deny_rejects_a_looser_update():
    registry = _registry(runtime_relax="deny")
    ruleset_id = registry.register(_doc(_file("files", "deny", "**/*.txt"))).ruleset_id
    _open(registry, ruleset_id)
    with pytest.raises(RulesetRejected) as caught:
        registry.update(ruleset_id, _doc(_file("files", "allow", "**/*.txt")), expected_version=1)
    assert caught.value.code == "runtime_relax"
    assert registry.status(ruleset_id).version == 1
    assert _rule(registry, ruleset_id, "files").action == "deny"


def test_task_binding_is_the_full_triple_and_idle_timeout_is_per_task():
    clock = Clock()
    registry = _registry(clock=clock, idle_timeout=100)
    ruleset_id = registry.register({"spec": "agent-pdp/v1"}).ruleset_id
    assert registry.resolve(None, "user-a", "task-a").error == "missing_ruleset"
    assert registry.resolve(ruleset_id, "user-a", "task-a").error == "unknown_task"
    registry.open_task(ruleset_id, "user-a", "task-a")
    with pytest.raises(RulesetRejected) as caught:
        registry.open_task(ruleset_id, "user-a", "task-a")
    assert caught.value.code == "task_id_in_use"
    registry.open_task(ruleset_id, "user-b", "task-a")
    registry.close_task(ruleset_id, "user-a", "task-a")
    assert registry.resolve(ruleset_id, "user-a", "task-a").error == "unknown_task"
    assert registry.resolve(ruleset_id, "user-b", "task-a").error is None

    clock.now = 40
    registry.open_task(ruleset_id, "user-a", "later")
    clock.now = 130
    assert registry.resolve(ruleset_id, "user-b", "task-a").error == "unknown_task"
    assert registry.resolve(ruleset_id, "user-a", "later").error is None
    assert registry.status(ruleset_id).task_count == 1


def test_update_records_the_classification():
    registry = _registry()
    ruleset_id = registry.register(_doc(_file("files", "ask", "**/*.txt"))).ruleset_id
    registry.update(ruleset_id, _doc(_file("files", "deny", "**/*.txt")), expected_version=1)
    recorded = registry.audit[-1]
    assert recorded["op"] == "update"
    assert recorded["classification"] == "tighten"
    assert recorded["version"] == 2
    assert recorded["fingerprint"] == fingerprint(_doc(_file("files", "deny", "**/*.txt")))
    assert recorded["previous_version"] == 1
    assert recorded["previous_fingerprint"] == fingerprint(_doc(_file("files", "ask", "**/*.txt")))


def test_userfiles_append_is_audited_as_a_relax():
    registry = _registry()
    info = registry.register({"spec": "agent-pdp/v1"})
    updated = registry.update(
        info.ruleset_id,
        {"spec": "agent-pdp/v1", "catalogs": {"userFiles": ["C:/Windows"]}},
        expected_version=1,
    )
    recorded = registry.audit[-1]
    assert updated.classification == "relax"
    assert recorded["classification"] == "relax"
    assert "userFiles append" in recorded["changes"]
    assert recorded["previous_fingerprint"] == info.fingerprint
    _open(registry, info.ruleset_id)
    ruleset = registry.resolve(info.ruleset_id, "user-a", "task-a").ruleset
    result = ruleset.decide(
        {
            "workspace": {"root": "C:/Users/me/proj", "os": "windows"},
            "action": {
                "category": "tool_call",
                "raw": {"name": "bash"},
                "effects": [{"type": "fs.write", "path": "C:/Windows/System32/kernel32.dll", "exists": True}],
                "normalization": {"status": "ok"},
            },
            "execution": {"intercept": False},
        }
    )
    assert result.action == "ask"
    assert result.winner_rule_id == "fs.write.protectedFiles"


def test_user_grantable_on_is_relax_and_off_is_tighten():
    registry = _registry()
    info = registry.register({"spec": "agent-pdp/v1"}).ruleset_id
    opened = registry.update(
        info,
        {"spec": "agent-pdp/v1", "behavior_rules": [{"id": "fs.read.sensitiveFiles", "user_grantable": True}]},
        expected_version=1,
    )
    assert opened.classification == "relax"
    closed = registry.update(info, {"spec": "agent-pdp/v1"}, expected_version=2)
    assert closed.classification == "tighten"
    assert "fs.read.sensitiveFiles user_grantable off" in registry.audit[-1]["changes"]
