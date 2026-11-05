"""Settle a PDP decision for one task.

Ask never leaves this object. No HITL, a closed task, or a rejected approval
becomes deny. Identical in-flight asks share one approval window.
"""

from __future__ import annotations

import json
import threading

from agent_shield.policy_engine.core.envelope import decision_denied, evaluate_event
from agent_shield.policy_engine.core.grants import accept_grant
from agent_shield.policy_engine.core.ruleset import load_grants, load_user_rules
from agent_shield.policy_engine.server.host import Host, VersionedRules
from agent_shield.policy_engine.server.registry import (
    RulesetRegistry,
    RulesetRejected,
    effect_audit,
    fingerprint,
)


class _Gate:
    def __init__(self) -> None:
        self.event = threading.Event()
        self.result = False


class Decide:
    def __init__(
        self,
        host: Host,
        *,
        source: dict,
        registry: RulesetRegistry,
        ruleset_id: str,
        subject_id: str,
        task_id: str,
        isolated: bool = False,
        delete_threshold: int = 20,
    ) -> None:
        if delete_threshold < 1:
            raise ValueError("delete_threshold must be at least 1")
        if isolated and (not isinstance(subject_id, str) or not subject_id):
            raise RulesetRejected("missing_subject", "subject_id is required")
        if not isinstance(subject_id, str) or not subject_id:
            raise RulesetRejected("unknown_task", "task is not open")
        if not isinstance(task_id, str) or not task_id:
            raise RulesetRejected("unknown_task", "task is not open")
        resolved = registry.resolve(ruleset_id, subject_id, task_id)
        if resolved.error:
            raise RulesetRejected(resolved.error, resolved.error)
        self._host = host
        self._source = source
        self.registry = registry
        self.ruleset_id = ruleset_id
        self._subject_id = subject_id
        self._task_id = task_id
        self._isolated = isolated
        self._threshold = delete_threshold
        self._lock = threading.Lock()
        self._closed = False
        self._inflight: dict[str, _Gate] = {}
        self._delete_success = 0
        self._delete_reserved = 0
        self._pending_deletes: set[str] = set()
        self._rule_cache: tuple | None = None

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        with self._lock:
            self._closed = True
            gates = list(self._inflight.values())
            for gate in gates:
                gate.result = False
                gate.event.set()
            self._inflight.clear()
            self._pending_deletes.clear()
            self._delete_reserved = 0
        try:
            self.registry.close_task(self.ruleset_id, self._subject_id, self._task_id)
        except RulesetRejected:
            return

    def settle(self, event: dict) -> dict:
        resolved = self.registry.resolve(self.ruleset_id, self._subject_id, self._task_id)
        event_id = event.get("id") if isinstance(event, dict) and isinstance(event.get("id"), str) else ""
        raw_rules = None
        raw_grants = None
        request_fingerprint = None
        if resolved.error or resolved.ruleset is None:
            settled = _settle(decision_denied(event_id, resolved.error or "unknown_task"), "deny")
        else:
            try:
                user_rules, grants, raw_rules, raw_grants, request_fingerprint = self._host_rules()
            except Exception:
                settled = _settle(decision_denied(event_id, "host_context_unavailable"), "deny")
            else:
                result = evaluate_event(
                    event,
                    ruleset=resolved.ruleset,
                    user_rules=user_rules,
                    grants=grants,
                    subject_id=self._subject_id,
                )
                action = result["action"]
                if action == "deny":
                    settled = _settle(result, "deny")
                elif action == "allow":
                    settled = _settle(result, "allow")
                elif self._closed or not _hitl(event, self._host):
                    settled = _settle(result, "deny")
                else:
                    allowed = self._ask(_cache_key(event), result, event)
                    settled = _settle(result, "allow" if allowed else "deny")
        self._audit_decision(resolved, event, settled, request_fingerprint)
        return settled

    def handle_operation_result(self, result: dict) -> None:
        if not isinstance(result, dict) or result.get("spec") != "native-operation-result/v1":
            return
        operation_id = result.get("operation_id")
        if not isinstance(operation_id, str):
            return
        with self._lock:
            if operation_id not in self._pending_deletes:
                return
            self._pending_deletes.remove(operation_id)
            self._delete_reserved = max(0, self._delete_reserved - 1)
            if result.get("success") is True:
                self._delete_success += 1

    def begin_delete(self, operation_id: str) -> bool:
        with self._lock:
            bulk = self._delete_success + self._delete_reserved >= self._threshold
            self._delete_reserved += 1
            self._pending_deletes.add(operation_id)
            return bulk

    def host_context(self) -> dict:
        try:
            intent = self._host.user_intent()
            workspace = self._host.workspace()
            capabilities = self._host.capabilities()
        except Exception:
            intent = None
            workspace = {"root": "", "trusted_dirs": [], "os": "posix"}
            capabilities = {"hitl": False, "auto_intent": False}
        return {
            "source": self._source,
            "workspace": workspace,
            "user_intent": intent,
            "host_capabilities": capabilities,
        }

    def _host_rules(self):
        rules_version, raw_rules = _cached_items(self._host.user_rules())
        grants_version, raw_grants = _cached_items(self._host.grants())
        with self._lock:
            cached = self._rule_cache
        if cached is not None and rules_version is not None and grants_version is not None:
            if cached[0] == rules_version and cached[1] == grants_version:
                return cached[2], cached[3], cached[4], cached[5], cached[6]
        if any(not isinstance(item, dict) for item in raw_rules):
            raise RulesetRejected("host_context_unavailable", "host context is unavailable")
        if any(not isinstance(item, dict) for item in raw_grants):
            raise RulesetRejected("host_context_unavailable", "host context is unavailable")
        user_rules = load_user_rules({"spec": "agent-user-rules/v1", "rules": raw_rules})
        kept = []
        rejected = []
        for grant in raw_grants:
            if accept_grant(grant, subject_id=self._subject_id):
                kept.append(grant)
            else:
                rejected.append(grant)
        loaded = load_grants(kept)
        for grant in rejected:
            self.registry.record(
                "grant_rejected",
                ruleset_id=self.ruleset_id,
                subject_id=self._subject_id,
                grant_id=grant.get("id"),
            )
        for grant in kept:
            self.registry.record(
                "grant_accepted",
                ruleset_id=self.ruleset_id,
                subject_id=self._subject_id,
                grant_id=grant.get("id"),
                grant_object=grant.get("object"),
                provenance=grant.get("provenance"),
            )
        request_fingerprint = fingerprint({"user_rules": raw_rules, "grants": raw_grants})
        with self._lock:
            self._rule_cache = (
                rules_version,
                grants_version,
                user_rules,
                loaded,
                raw_rules,
                raw_grants,
                request_fingerprint,
            )
        return user_rules, loaded, raw_rules, raw_grants, request_fingerprint

    def _audit_decision(self, resolved, event: dict, settled: dict, request_fingerprint) -> None:
        fields = {
            "mode": "isolated" if self._isolated else "trusted",
            "ruleset_id": self.ruleset_id,
            "subject_id": self._subject_id,
            "task_id": self._task_id,
            "event_id": settled.get("event_id") or "",
            "winner_rule_id": settled.get("winner_rule_id"),
            "raw_action": settled.get("raw_action"),
            "pdp_action": settled.get("pdp_action"),
            "action": settled.get("action"),
            "unmatched": self.registry.unmatched,
        }
        if resolved.version:
            fields["version"] = resolved.version
            fields["fingerprint"] = resolved.fingerprint
        if request_fingerprint is not None:
            fields["request_fingerprint"] = request_fingerprint
        fields.update(effect_audit(event))
        self.registry.record("decide", **fields)

    def _ask(self, key: str, result: dict, event: dict) -> bool:
        with self._lock:
            if self._closed:
                return False
            gate = self._inflight.get(key)
            if gate is None:
                gate = _Gate()
                self._inflight[key] = gate
                leader = True
            else:
                leader = False
        if not leader:
            gate.event.wait()
            with self._lock:
                return bool(gate.result)
        try:
            answer = bool(self._host.request_approval(result, event))
        except Exception:
            answer = False
        with self._lock:
            if self._closed:
                answer = False
            gate.result = answer
            self._inflight.pop(key, None)
        gate.event.set()
        return answer


def _settle(result: dict, action: str) -> dict:
    settled = dict(result)
    settled["pdp_action"] = result["action"]
    settled["action"] = action
    return settled


def _hitl(event: dict, host: Host) -> bool:
    caps = event.get("host_capabilities")
    if isinstance(caps, dict) and "hitl" in caps:
        return caps.get("hitl") is True
    try:
        return host.capabilities().get("hitl") is True
    except Exception:
        return False


def _cache_key(event: dict) -> str:
    items = []
    for effect in (event.get("action") or {}).get("effects") or []:
        if not isinstance(effect, dict):
            continue
        items.append(
            {
                "type": effect.get("type"),
                "path": effect.get("path"),
                "argv": effect.get("argv"),
                "host": effect.get("host"),
                "ip": effect.get("ip"),
                "port": effect.get("port"),
                "path_kind": effect.get("path_kind"),
                "force": effect.get("force"),
                "bulk": effect.get("bulk"),
            }
        )
    return json.dumps(items, sort_keys=True, ensure_ascii=False, default=str)


def _cached_items(value) -> tuple[str | int | None, list]:
    if isinstance(value, VersionedRules):
        version = value.version
        items = value.items
        if isinstance(version, bool) or not isinstance(version, (str, int)) or not isinstance(items, list):
            raise RulesetRejected("host_context_unavailable", "host context is unavailable")
        return version, items
    if isinstance(value, list):
        return None, value
    raise RulesetRejected("host_context_unavailable", "host context is unavailable")
