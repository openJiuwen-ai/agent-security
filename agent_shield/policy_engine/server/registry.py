"""In-process ruleset registry: register, replace, and pin a version to a task."""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from dataclasses import dataclass

from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset
from agent_shield.policy_engine.core.ruleset_diff import classify_update
from agent_shield.policy_engine.core.envelope import decision_denied, evaluate_event
from agent_shield.policy_engine.core.grants import accept_grant
from agent_shield.policy_engine.core.request import parse_decision_request
from agent_shield.policy_engine.core.ruleset import Ruleset, load_grants, load_ruleset, load_user_rules
from agent_shield.policy_engine.errors import PolicyError

_IDLE_SECONDS = 30 * 60
_MAX_RULES = 500
_MAX_CATALOG = 2000
_MAX_BYTES = 1 << 20


class RulesetRejected(Exception):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


@dataclass(frozen=True)
class RulesetInfo:
    ruleset_id: str
    version: int
    fingerprint: str


@dataclass(frozen=True)
class RulesetUpdate:
    ruleset_id: str
    version: int
    fingerprint: str
    classification: str
    changes: tuple[str, ...]


@dataclass(frozen=True)
class RulesetStatus:
    ruleset_id: str
    version: int
    fingerprint: str
    updated_at: float
    task_count: int


@dataclass(frozen=True)
class TaskRuleset:
    error: str | None
    ruleset: Ruleset | None = None
    version: int | None = None
    fingerprint: str = ""
    ruleset_id: str = ""


@dataclass
class _Snapshot:
    number: int
    fingerprint: str
    document: dict
    ruleset: Ruleset
    updated_at: float


@dataclass
class _Binding:
    version: int
    last_used: float


@dataclass
class _Entry:
    current: _Snapshot
    versions: dict[int, _Snapshot]
    tasks: dict[tuple[str, str], _Binding]


class RulesetRegistry:
    def __init__(
        self,
        *,
        unmatched: str = "none",
        runtime_relax: str = "allow",
        idle_timeout: float = _IDLE_SECONDS,
        max_rules: int = _MAX_RULES,
        max_catalog: int = _MAX_CATALOG,
        max_bytes: int = _MAX_BYTES,
        clock=None,
        id_factory=None,
    ) -> None:
        if runtime_relax not in {"allow", "deny"}:
            raise PolicyError("runtime_relax must be allow or deny")
        if unmatched not in {"none", "allow", "ask", "deny"}:
            raise PolicyError(f"invalid unmatched: {unmatched}")
        builtin = load_builtin_ruleset()
        self._behaviors = builtin.behaviors
        self._catalogs = builtin.catalogs
        self._unmatched = unmatched
        self._runtime_relax = runtime_relax
        self._idle_timeout = idle_timeout
        self._max_rules = max_rules
        self._max_catalog = max_catalog
        self._max_bytes = max_bytes
        self._clock = clock or time.monotonic
        self._ids = id_factory or (lambda: secrets.token_hex(16))
        self._entries: dict[str, _Entry] = {}
        self._compiled: dict[str, tuple] = {}
        self._lock = threading.Lock()
        self.audit: list[dict] = []

    def register(self, document: dict, *, caller: str = "") -> RulesetInfo:
        with self._lock:
            try:
                snapshot = self._snapshot(1, document)
            except (PolicyError, RulesetRejected) as err:
                self._audit("register_failed", reason=str(err), caller=_caller(caller))
                raise RulesetRejected("invalid_ruleset", str(err)) from err
            ruleset_id = self._ids()
            self._entries[ruleset_id] = _Entry(snapshot, {1: snapshot}, {})
            self._audit(
                "register",
                ruleset_id=ruleset_id,
                version=1,
                fingerprint=snapshot.fingerprint,
                caller=_caller(caller),
            )
            return RulesetInfo(ruleset_id, 1, snapshot.fingerprint)

    def update(self, ruleset_id: str, document: dict, expected_version: int, *, caller: str = "") -> RulesetUpdate:
        with self._lock:
            entry = self._entry(ruleset_id)
            if entry.current.number != expected_version:
                self._audit(
                    "update_failed",
                    ruleset_id=ruleset_id,
                    version=entry.current.number,
                    code="version_conflict",
                    caller=_caller(caller),
                )
                raise RulesetRejected("version_conflict", "expected_version does not match")
            try:
                snapshot = self._snapshot(entry.current.number + 1, document)
                classified = classify_update(entry.current.document, snapshot.document)
                if classified.kind == "relax" and self._runtime_relax == "deny":
                    raise RulesetRejected("runtime_relax", "runtime relax is denied")
            except (PolicyError, RulesetRejected) as err:
                code = err.code if isinstance(err, RulesetRejected) else "invalid_ruleset"
                self._audit(
                    "update_failed",
                    ruleset_id=ruleset_id,
                    version=entry.current.number,
                    code=code,
                    reason=str(err),
                    caller=_caller(caller),
                )
                raise RulesetRejected(code, str(err)) from err
            self._sweep(entry)
            previous_version = entry.current.number
            previous_fingerprint = entry.current.fingerprint
            entry.versions[snapshot.number] = snapshot
            entry.current = snapshot
            if classified.kind == "tighten":
                for binding in entry.tasks.values():
                    binding.version = snapshot.number
            self._gc(entry)
            self._audit(
                "update",
                ruleset_id=ruleset_id,
                previous_version=previous_version,
                previous_fingerprint=previous_fingerprint,
                version=snapshot.number,
                fingerprint=snapshot.fingerprint,
                classification=classified.kind,
                changes=classified.changes,
                caller=_caller(caller),
            )
            return RulesetUpdate(ruleset_id, snapshot.number, snapshot.fingerprint, classified.kind, classified.changes)

    def status(self, ruleset_id: str) -> RulesetStatus:
        with self._lock:
            entry = self._entry(ruleset_id)
            self._sweep(entry)
            current = entry.current
            return RulesetStatus(ruleset_id, current.number, current.fingerprint, current.updated_at, len(entry.tasks))

    def close(self, ruleset_id: str, *, caller: str = "") -> None:
        with self._lock:
            entry = self._entry(ruleset_id)
            version = entry.current.number
            closed_fingerprint = entry.current.fingerprint
            del self._entries[ruleset_id]
            self._audit(
                "close",
                ruleset_id=ruleset_id,
                version=version,
                fingerprint=closed_fingerprint,
                caller=_caller(caller),
            )

    def open_task(self, ruleset_id: str, subject_id: str, task_id: str) -> int:
        with self._lock:
            entry = self._entry(ruleset_id)
            _names(subject_id, task_id)
            key = (subject_id, task_id)
            self._sweep(entry)
            if key in entry.tasks:
                raise RulesetRejected("task_id_in_use", "task is already open")
            entry.tasks[key] = _Binding(entry.current.number, self._clock())
            return entry.current.number

    def close_task(self, ruleset_id: str, subject_id: str, task_id: str) -> None:
        with self._lock:
            entry = self._entry(ruleset_id)
            _names(subject_id, task_id)
            key = (subject_id, task_id)
            self._sweep(entry)
            if key not in entry.tasks:
                raise RulesetRejected("unknown_task", "task is not open")
            del entry.tasks[key]
            self._gc(entry)

    def resolve(self, ruleset_id: str | None, subject_id: str, task_id: str) -> TaskRuleset:
        with self._lock:
            if not isinstance(ruleset_id, str) or not ruleset_id:
                return TaskRuleset("missing_ruleset")
            entry = self._entries.get(ruleset_id)
            if entry is None:
                return TaskRuleset("unknown_ruleset", ruleset_id=ruleset_id)
            _names(subject_id, task_id)
            self._sweep(entry)
            binding = entry.tasks.get((subject_id, task_id))
            if binding is None:
                return TaskRuleset("unknown_task", ruleset_id=ruleset_id)
            binding.last_used = self._clock()
            snapshot = entry.versions[binding.version]
            return TaskRuleset(None, snapshot.ruleset, snapshot.number, snapshot.fingerprint, ruleset_id)

    def evaluate_request(self, payload: dict, *, isolated: bool) -> tuple[int, dict]:
        parsed = parse_decision_request(payload)
        event_id = _event_id(parsed.event)
        if parsed.error == "missing_subject" and isolated:
            return 401, {"error": "missing_subject"}
        if parsed.error:
            return 200, decision_denied(event_id, parsed.error)
        if not parsed.ruleset_id:
            return 200, decision_denied(event_id, "missing_ruleset")
        resolved = self.resolve(parsed.ruleset_id, parsed.subject_id, parsed.task_id)
        if resolved.error == "unknown_ruleset":
            body = decision_denied(event_id, "unknown_ruleset")
            body["error"] = "unknown_ruleset"
            return 409, body
        if resolved.error:
            return 200, decision_denied(event_id, resolved.error)
        try:
            user_rules, grants = self._request_rules(parsed, resolved.ruleset_id)
        except PolicyError as err:
            self._audit("evaluate_rejected", ruleset_id=parsed.ruleset_id, reason=str(err))
            return 200, decision_denied(event_id, "invalid_ruleset")
        decision = evaluate_event(
            parsed.event,
            ruleset=resolved.ruleset,
            user_rules=user_rules,
            grants=grants,
            subject_id=parsed.subject_id,
        )
        self._audit(
            "evaluate",
            ruleset_id=resolved.ruleset_id,
            subject_id=parsed.subject_id,
            task_id=parsed.task_id,
            request_id=parsed.request_id,
            event_id=event_id,
            version=resolved.version,
            fingerprint=resolved.fingerprint,
            request_fingerprint=fingerprint({"user_rules": parsed.user_rules, "grants": parsed.grants}),
            mode="isolated" if isolated else "trusted",
            unmatched=self._unmatched,
            winner_rule_id=decision.get("winner_rule_id"),
            action=decision.get("action"),
            raw_action=decision.get("raw_action"),
            **effect_audit(parsed.event),
        )
        return 200, decision

    def _request_rules(self, parsed, ruleset_id: str):
        kept = []
        for grant in parsed.grants:
            if accept_grant(grant, subject_id=parsed.subject_id):
                kept.append(grant)
            else:
                self._audit(
                    "grant_rejected",
                    ruleset_id=ruleset_id,
                    subject_id=parsed.subject_id,
                    grant_id=grant.get("id"),
                )
        loaded = self._compiled_rules(parsed.user_rules, kept)
        for grant in kept:
            self._audit(
                "grant_accepted",
                ruleset_id=ruleset_id,
                subject_id=parsed.subject_id,
                grant_id=grant.get("id"),
                grant_object=grant.get("object"),
                provenance=grant.get("provenance"),
            )
        return loaded

    def _compiled_rules(self, user_rules: list, grants: list):
        key = fingerprint({"user_rules": user_rules, "grants": grants})
        with self._lock:
            cached = self._compiled.get(key)
            if cached is None:
                cached = (
                    load_user_rules({"spec": "agent-user-rules/v1", "rules": user_rules}),
                    load_grants(grants),
                )
                self._compiled[key] = cached
            return cached

    def _snapshot(self, number: int, document: dict) -> _Snapshot:
        stored = _copy(document)
        compiled = self._compile(stored)
        return _Snapshot(number, fingerprint(stored), stored, compiled, self._clock())

    def _compile(self, document: dict) -> Ruleset:
        self._limits(document)
        return load_ruleset(
            document,
            baseline=self._behaviors,
            catalogs=self._catalogs,
            unmatched=self._unmatched,
        )

    def _limits(self, document: dict) -> None:
        if len(json.dumps(document, ensure_ascii=False).encode("utf-8")) > self._max_bytes:
            raise PolicyError("ruleset exceeds size limit")
        for key in ("rules", "behavior_rules"):
            value = document.get(key) or []
            if isinstance(value, list) and len(value) > self._max_rules:
                raise PolicyError(f"{key} exceeds the rule limit")
        catalogs = document.get("catalogs") or {}
        if isinstance(catalogs, dict):
            for name, value in catalogs.items():
                if len(_entries(value)) > self._max_catalog:
                    raise PolicyError(f"{name} exceeds the catalog limit")

    def _entry(self, ruleset_id: str) -> _Entry:
        entry = self._entries.get(ruleset_id)
        if entry is None:
            raise RulesetRejected("unknown_ruleset", "unknown ruleset")
        return entry

    def _sweep(self, entry: _Entry) -> None:
        now = self._clock()
        expired = [key for key, binding in entry.tasks.items() if now - binding.last_used > self._idle_timeout]
        for key in expired:
            del entry.tasks[key]
        self._gc(entry)

    @staticmethod
    def _gc(entry: _Entry) -> None:
        live = {binding.version for binding in entry.tasks.values()}
        live.add(entry.current.number)
        for number in list(entry.versions):
            if number not in live:
                del entry.versions[number]

    @property
    def unmatched(self) -> str:
        return self._unmatched

    def record(self, op: str, **fields) -> None:
        self._audit(op, **fields)

    def _audit(self, op: str, **fields) -> None:
        self.audit.append({"op": op, **fields})


def _caller(value: str) -> str:
    return value if isinstance(value, str) else ""


def effect_audit(event: dict) -> dict:
    action = event.get("action") if isinstance(event, dict) else None
    if not isinstance(action, dict):
        return {}
    effects = action.get("effects") if isinstance(action.get("effects"), list) else []
    images: list[str] = []
    program = ""
    missing: list[list[str]] = []
    for effect in effects:
        if not isinstance(effect, dict) or effect.get("type") != "process.exec":
            continue
        image = effect.get("image")
        if isinstance(image, str) and image and image not in images:
            images.append(image)
        tokens = effect.get("command_tokens")
        if not program and isinstance(tokens, list) and tokens:
            if isinstance(tokens[0], str):
                program = tokens[0]
        argv = _argv_only(effect)
        if argv:
            missing.append(argv)
    recorded: dict = {}
    if images:
        recorded["images"] = images
    if missing:
        recorded["missing_command_line"] = missing
    normalization = action.get("normalization")
    warnings = normalization.get("warnings") if isinstance(normalization, dict) else []
    if images and program and isinstance(warnings, list):
        if "image_command_mismatch" in warnings:
            recorded["image_command_mismatch"] = {"image": images[0], "command": program}
    return recorded


def _argv_only(effect: dict) -> list[str]:
    tokens = effect.get("command_tokens")
    if isinstance(tokens, list) and tokens and all(isinstance(item, str) and item for item in tokens):
        return []
    line = effect.get("command_line")
    if isinstance(line, str) and line.strip():
        return []
    argv = effect.get("argv")
    if not isinstance(argv, list) or not argv or argv == ["__compound__"]:
        return []
    if not all(isinstance(item, str) and item for item in argv):
        return []
    return list(argv)


def fingerprint(document: dict) -> str:
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _entries(value) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        return [item for item in value.get("entries") or [] if isinstance(item, str)]
    return []


def _names(subject_id: str, task_id: str) -> None:
    if not isinstance(subject_id, str) or not subject_id:
        raise RulesetRejected("invalid_task", "subject_id and task_id are required")
    if not isinstance(task_id, str) or not task_id:
        raise RulesetRejected("invalid_task", "subject_id and task_id are required")


def _event_id(event: dict) -> str:
    if isinstance(event, dict) and isinstance(event.get("id"), str):
        return event["id"]
    return ""


def _copy(value):
    return json.loads(json.dumps(value))
