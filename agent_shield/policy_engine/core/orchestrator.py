"""Orchestrate one event: match rules, rank hits, and aggregate a decision."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

from agent_shield.policy_engine.core.adjudication import Decision, Hit, adjudicate, best_hit
from agent_shield.policy_engine.matchers.command import tokenize
from agent_shield.policy_engine.core.action_mapping import effective_action
from agent_shield.policy_engine.models.types import BehaviorRule, ObjectRule
from agent_shield.policy_engine.matchers.dispatch import matches_object
from agent_shield.policy_engine.matchers.tools import matches_agent_tool, native_program
from agent_shield.policy_engine.core.user_visible import (
    command_text,
    content_for_effect,
    domain_phrase,
    file_phrase,
    object_phrase,
)
from agent_shield.policy_engine.matchers.behavior import matches_when
from agent_shield.policy_engine.matchers.paths import event_os, normalize_path

_UNOBSERVED = "命令无法完整解析且没有运行时拦截"


def orchestrate(
    event: dict,
    effects: list[dict],
    *,
    behaviors: list[BehaviorRule] | tuple[BehaviorRule, ...] = (),
    objects: list[ObjectRule] | tuple[ObjectRule, ...] = (),
    action_mapping: dict[str, str] | None = None,
    baseline_mapping: dict[str, str] | None = None,
    catalogs: dict[str, Any] | None = None,
    unmatched: str = "none",
    intent_allows: bool = False,
) -> Decision:
    granted = _native_grants(objects, event)
    event_hits = _without_blocked_grants(_event_hits(event, objects))
    effect_hits = [
        _without_blocked_grants(
            _effect_hits(
                effect,
                event,
                behaviors,
                objects,
                action_mapping,
                baseline_mapping,
                catalogs,
                intent_allows,
                granted,
            )
        )
        for effect in effects
    ]
    decision = adjudicate(event_hits, effect_hits, unmatched=unmatched)
    if decision.action != "ask":
        return decision
    return replace(decision, grants=tuple(_suggested_grants(event, effects, event_hits, effect_hits)))


def _event_hits(event: dict, objects) -> list[Hit]:
    hits: list[Hit] = []
    if _unobserved(event):
        line = _event_command(event)
        hits.append(
            Hit(
                "builtin",
                "ask",
                "exec.unobserved",
                "behavior",
                "high",
                _UNOBSERVED,
                f"执行 {line}".strip(),
                user_grantable=False,
            )
        )
    for rule in objects:
        if not rule.enabled or rule.object != "agentTools" or not matches_agent_tool(rule, event):
            continue
        if rule.source == "user_grant" and rule.action == "allow":
            name = rule.names[0] if rule.names else ""
            hits.append(Hit("user_grant", "allow", rule.id, "grant", None, "", f"调用 {name}"))
            continue
        raw = (event.get("action") or {}).get("raw") or {}
        name = raw.get("name") if isinstance(raw, dict) else ""
        hits.append(
            Hit(
                rule.source,
                rule.action,
                rule.id,
                "object",
                None,
                object_phrase("agentTools"),
                f"调用 {name}",
                user_grantable=_grantable(rule),
            )
        )
    return hits


def _effect_hits(
    effect,
    event,
    behaviors,
    objects,
    action_mapping,
    baseline_mapping,
    catalogs,
    intent_allows,
    granted,
) -> list[Hit]:
    hits: list[Hit] = []
    for rule in behaviors:
        if matches_when(rule.when, effect, event, catalogs):
            hits.append(_behavior_hit(rule, effect, action_mapping, baseline_mapping, intent_allows))
    for rule in objects:
        if not rule.enabled or rule.object == "agentTools":
            continue
        granted_native = rule.object == "nativeTools" and rule.action == "ask"
        if granted_native and _grantable(rule) and native_program(effect, event) in granted:
            continue
        if rule.source == "user_grant" and rule.object == "nativeTools":
            continue
        if not matches_object(rule, effect, event):
            continue
        hits.append(_object_hit(rule, effect, event))
    return hits


def _behavior_hit(rule: BehaviorRule, effect: dict, action_mapping, baseline_mapping, intent_allows: bool) -> Hit:
    action = effective_action(rule.risk, baseline_mapping, action_mapping)
    if rule.risk == "medium" and action == "ask":
        if rule.auto_intent and intent_allows:
            action = "allow"
    return Hit(
        rule.source,
        action,
        rule.id,
        "behavior",
        rule.risk,
        rule.note,
        content_for_effect(effect),
        user_grantable=rule.user_grantable,
    )


def _object_hit(rule: ObjectRule, effect: dict, event: dict) -> Hit:
    content = _object_content(rule, effect, event)
    if rule.source == "user_grant":
        return Hit("user_grant", "allow", rule.id, "grant", None, "", content)
    return Hit(
        rule.source,
        rule.action,
        rule.id,
        "object",
        None,
        _object_phrase(rule, effect),
        content,
        user_grantable=_grantable(rule),
    )


def _object_phrase(rule: ObjectRule, effect: dict) -> str:
    if rule.object == "file":
        return file_phrase(str(effect.get("type") or ""))
    if rule.object == "domain":
        return domain_phrase(str(effect.get("type") or ""))
    return object_phrase(rule.object)


def _object_content(rule: ObjectRule, effect: dict, event: dict) -> str:
    if rule.object == "nativeTools":
        return f"启动 {native_program(effect, event)}".strip()
    if rule.object == "command":
        return "执行 " + command_text(effect)
    return content_for_effect(effect)


def _suggested_grants(
    event: dict,
    effects: list[dict],
    event_hits: list[Hit],
    effect_hits: list[list[Hit]],
) -> list[dict]:
    chosen: list[tuple[Hit, dict | None]] = []
    event_winner = _grantable_ask(event_hits)
    if event_winner is not None:
        chosen.append((event_winner, None))
    for effect, hits in zip(effects, effect_hits):
        winner = _grantable_ask(hits)
        if winner is not None:
            chosen.append((winner, effect))
    grants = []
    for index, (hit, effect) in enumerate(chosen):
        grant = _one_grant(hit, effect, event, index)
        if grant:
            grants.append(grant)
    return grants


def _grantable(rule: BehaviorRule | ObjectRule) -> bool:
    if rule.source == "user_custom":
        return True
    return rule.user_grantable


def _grantable_ask(hits: list[Hit]) -> Hit | None:
    if any(hit.action == "ask" and not hit.user_grantable for hit in hits):
        return None
    winner = best_hit(hits)
    if winner is None or winner.action != "ask" or not winner.user_grantable:
        return None
    return winner


def _without_blocked_grants(hits: list[Hit]) -> list[Hit]:
    if any(hit.action == "ask" and not hit.user_grantable for hit in hits):
        return [hit for hit in hits if hit.source != "user_grant"]
    return hits


def _one_grant(hit: Hit, effect: dict | None, event: dict, index: int) -> dict | None:
    if effect is None:
        raw = (event.get("action") or {}).get("raw") or {}
        name = raw.get("name") if isinstance(raw, dict) else ""
        if not isinstance(name, str) or not name:
            return None
        return {"id": f"suggested-{index}", "object": "agentTools", "names": [name]}
    if hit.rule_id.startswith("nativeTools"):
        program = native_program(effect, event)
        if not program:
            return None
        return {"id": f"suggested-{index}", "object": "nativeTools", "names": [program]}
    kind = effect.get("type")
    if kind in {"fs.read", "fs.write", "fs.delete"}:
        path = effect.get("path")
        if not isinstance(path, str) or not path:
            return None
        op = {"fs.read": "read", "fs.write": "write", "fs.delete": "delete"}[str(kind)]
        return {"id": f"suggested-{index}", "object": "file", "ops": [op], "path": normalize_path(path)}
    if kind in {"net.connect", "net.fetch", "net.egress"}:
        from agent_shield.policy_engine.matchers.network import endpoint_host, endpoint_ip

        host = endpoint_host(effect) or endpoint_ip(effect)
        if not host:
            return None
        op = {"net.connect": "connect", "net.fetch": "fetch", "net.egress": "egress"}[str(kind)]
        return {"id": f"suggested-{index}", "object": "domain", "ops": [op], "hosts": [host]}
    if kind == "process.exec":
        tokens = _command_tokens(effect)
        if not tokens:
            return None
        return {"id": f"suggested-{index}", "object": "command", "tokens": tokens}
    return None


def _command_tokens(effect: dict) -> list[str]:
    stored = effect.get("command_tokens")
    if isinstance(stored, list) and stored and all(isinstance(item, str) and item for item in stored):
        return list(stored)
    line = effect.get("command_line")
    if isinstance(line, str) and line.strip():
        return tokenize(line)
    return []


def _native_grants(objects, event: dict) -> set[str]:
    windows = event_os(event) == "windows"
    from agent_shield.policy_engine.matchers.command import normalize_program

    names: set[str] = set()
    for rule in objects:
        if rule.source == "user_grant" and rule.object == "nativeTools":
            names.update(normalize_program(name, windows) for name in rule.names)
    return names


def _unobserved(event: dict) -> bool:
    action = event.get("action") if isinstance(event.get("action"), dict) else {}
    status = (action.get("normalization") or {}).get("status", "ok")
    intercept = bool((event.get("execution") or {}).get("intercept"))
    return status in {"failed", "partial"} and not intercept


def _event_command(event: dict) -> str:
    action = event.get("action") if isinstance(event.get("action"), dict) else {}
    line = action.get("command_line")
    if isinstance(line, str) and line.strip():
        return line.strip()
    return ""
