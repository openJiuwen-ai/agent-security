"""Shared host and Decide setup for server tests."""

import threading

from agent_shield.policy_engine.server import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry


class FakeHost:
    def __init__(self, *, hitl=True, answer=True):
        self._hitl = hitl
        self._answer = answer
        self.prompts = 0
        self.release = threading.Event()
        self.entered = threading.Event()
        self.block = False
        self.rules: list[dict] = []
        self.saved_grants: list[dict] = []
        self.fail = False

    @staticmethod
    def user_intent():
        return None

    @staticmethod
    def workspace():
        return {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}

    def capabilities(self):
        return {"hitl": self._hitl, "auto_intent": True}

    def request_approval(self, decision, event):
        self.prompts += 1
        self.entered.set()
        if self.block:
            self.release.wait(timeout=2)
        return self._answer

    def user_rules(self):
        if self.fail:
            raise RuntimeError("host down")
        return self.rules

    def grants(self):
        if self.fail:
            raise RuntimeError("host down")
        return self.saved_grants


def decide(host, **kwargs):
    unmatched = kwargs.pop("unmatched", "none")
    document = kwargs.pop("document", None)
    registry = RulesetRegistry(unmatched=unmatched)
    info = registry.register(document or {"spec": "agent-pdp/v1"})
    subject_id = kwargs.pop("subject_id", "user-a")
    task_id = kwargs.pop("task_id", "task-a")
    registry.open_task(info.ruleset_id, subject_id, task_id)
    other = kwargs.pop("also_open", None)
    if other is not None:
        registry.open_task(info.ruleset_id, other[0], other[1])
    return Decide(
        host,
        source={"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
        registry=registry,
        ruleset_id=info.ruleset_id,
        subject_id=subject_id,
        task_id=task_id,
        **kwargs,
    )
