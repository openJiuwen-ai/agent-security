"""Load an agent-pdp/v1 ruleset and decide one event with it."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any

from agent_shield.policy_engine.builtin.catalog import (
    CATALOG_KIND,
    DEFAULT_RISK,
    DISPLAY_NAME,
    FORBIDDEN_CATALOGS,
)
from agent_shield.policy_engine.matchers.command import argv_of, normalize_program, privilege_requested
from agent_shield.policy_engine.core.grants import grant_provenance
from agent_shield.policy_engine.core.orchestrator import orchestrate
from agent_shield.policy_engine.core.action_mapping import (
    check_override,
    reject_user_mapping,
    validate_action_mapping,
)
from agent_shield.policy_engine.models.types import BehaviorRule, ObjectRule
from agent_shield.policy_engine.core.behavior_schema import validate_behavior_clause
from agent_shield.policy_engine.matchers.paths import event_os
from agent_shield.policy_engine.errors import PolicyError

_UNMATCHED = {"none", "allow", "ask", "deny"}
_ACTIONS = {"allow", "ask", "deny"}
_OBJECTS = {"file", "domain", "command", "agentTools", "nativeTools"}
_FILE_OPS = {"read", "write", "delete"}
_NET_OPS = {"connect", "fetch", "egress"}
_GLOB_KEYS = {"path.glob_any", "local_files.glob_any"}
_BEHAVIOR_FIELDS = {"id", "risk", "when", "note", "auto_intent", "user_grantable"}
_OBJECT_FIELDS = {
    "id",
    "object",
    "action",
    "ops",
    "pattern",
    "path",
    "hosts",
    "cidrs",
    "match",
    "tokens",
    "names",
    "note",
    "enabled",
    "user_grantable",
}
_RULESET_FIELDS = {"spec", "rules", "catalogs", "behavior_rules", "action_mapping"}
_USER_FIELDS = {"spec", "rules"}


@dataclass(frozen=True)
class Ruleset:
    behaviors: tuple[BehaviorRule, ...]
    objects: tuple[ObjectRule, ...]
    catalogs: dict[str, Any]
    action_mapping: dict[str, str]
    unmatched: str = "none"

    def decide(
        self,
        event: dict,
        *,
        user_rules: list[ObjectRule] | tuple[ObjectRule, ...] = (),
        grants: list[ObjectRule] | tuple[ObjectRule, ...] = (),
        baseline_mapping: dict[str, str] | None = None,
        intent_allows: bool = False,
    ):
        action = event.get("action") if isinstance(event.get("action"), dict) else {}
        os_name = event_os(event)
        effects = [_with_privilege(effect, self.catalogs, os_name) for effect in action.get("effects") or []]
        return orchestrate(
            event,
            effects,
            behaviors=self.behaviors,
            objects=[*self.objects, *_native_tool_rules(self.catalogs, os_name), *user_rules, *grants],
            action_mapping=self.action_mapping,
            baseline_mapping=baseline_mapping,
            catalogs=self.catalogs,
            unmatched=self.unmatched,
            intent_allows=intent_allows,
        )


def load_ruleset(
    document: dict,
    *,
    baseline: list[BehaviorRule] | tuple[BehaviorRule, ...] = (),
    catalogs: dict[str, Any] | None = None,
    unmatched: str = "none",
) -> Ruleset:
    if unmatched not in _UNMATCHED:
        raise PolicyError(f"invalid unmatched: {unmatched}")
    if not isinstance(document, dict) or document.get("spec") != "agent-pdp/v1":
        raise PolicyError("ruleset spec must be agent-pdp/v1")
    if set(document) - _RULESET_FIELDS:
        raise PolicyError("ruleset has an unknown field")
    merged = _merge_catalogs(catalogs or {}, document.get("catalogs") or {})
    behaviors = _behaviors(document.get("behavior_rules") or [], baseline, merged)
    objects = _objects(document.get("rules") or [], "third_party")
    _unique_ids([*(rule.id for rule in behaviors), *(rule.id for rule in objects)])
    return Ruleset(
        behaviors=tuple(behaviors),
        objects=tuple(objects),
        catalogs=merged,
        action_mapping=validate_action_mapping(document.get("action_mapping")),
        unmatched=unmatched,
    )


def load_user_rules(document: dict) -> list[ObjectRule]:
    reject_user_mapping(document)
    if not isinstance(document, dict) or document.get("spec") != "agent-user-rules/v1":
        raise PolicyError("user rules spec must be agent-user-rules/v1")
    if "behavior_rules" in document or "catalogs" in document:
        raise PolicyError("user rules cannot include behavior_rules or catalogs")
    if set(document) - _USER_FIELDS:
        raise PolicyError("user rules have an unknown field")
    rules = _objects(document.get("rules") or [], "user_custom")
    _unique_ids(rule.id for rule in rules)
    return rules


def load_grants(items: list[dict]) -> list[ObjectRule]:
    if not isinstance(items, list):
        raise PolicyError("grants must be a list")
    if any(grant_provenance(item) is None for item in items):
        raise PolicyError("grant needs provenance")
    rules = _objects(items, "user_grant")
    for rule in rules:
        rule.validate()
    _unique_ids(rule.id for rule in rules)
    return rules


def _behaviors(
    raw: list,
    baseline: list[BehaviorRule] | tuple[BehaviorRule, ...],
    catalogs: dict,
) -> list[BehaviorRule]:
    if not isinstance(raw, list):
        raise PolicyError("behavior_rules must be a list")
    known = {rule.id: rule for rule in baseline}
    for rule_id in known:
        if rule_id not in DEFAULT_RISK:
            raise PolicyError(f"unknown builtin behavior: {rule_id}")
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, dict) or set(item) - _BEHAVIOR_FIELDS:
            raise PolicyError("behavior rule has an unknown field")
        rule_id = item.get("id")
        if not isinstance(rule_id, str) or not rule_id or rule_id in seen:
            raise PolicyError(f"invalid behavior id: {rule_id}")
        seen.add(rule_id)
        if rule_id in DEFAULT_RISK:
            known[rule_id] = _override(known.get(rule_id), item)
        else:
            known[rule_id] = _new_behavior(item)
    compiled = list(known.values())
    for rule in compiled:
        validate_behavior_clause(rule.when)
        _check_catalog_refs(rule.when, catalogs)
    return compiled


def _override(current: BehaviorRule | None, item: dict) -> BehaviorRule:
    if current is None:
        raise PolicyError(f"builtin behavior is absent: {item['id']}")
    if "when" in item or "note" in item or "action" in item:
        raise PolicyError(f"{item['id']} override cannot change when, note, or action")
    risk = item.get("risk", current.risk)
    check_override(current.id, DEFAULT_RISK[current.id], risk)
    auto_intent = current.auto_intent if "auto_intent" not in item else item["auto_intent"]
    if not isinstance(auto_intent, bool):
        raise PolicyError(f"{current.id} auto_intent must be true or false")
    return replace(
        current,
        risk=str(risk),
        auto_intent=auto_intent,
        user_grantable=_flag(item, "user_grantable", current.user_grantable),
        note=DISPLAY_NAME[current.id],
        source="builtin",
    )


def _new_behavior(item: dict) -> BehaviorRule:
    rule_id = str(item["id"])
    if not rule_id.startswith("tp.") or rule_id in DEFAULT_RISK:
        raise PolicyError(f"new behavior id must start with tp.: {rule_id}")
    if "action" in item:
        raise PolicyError(f"{rule_id} cannot set action")
    risk = item.get("risk")
    if risk not in {"none", "low", "medium", "high", "critical"}:
        raise PolicyError(f"{rule_id} has unknown risk")
    note = item.get("note")
    if not isinstance(note, str) or not note.strip():
        raise PolicyError(f"{rule_id} needs a note")
    when = item.get("when")
    if not isinstance(when, dict):
        raise PolicyError(f"{rule_id} needs a when")
    auto_intent = item.get("auto_intent", False)
    if not isinstance(auto_intent, bool):
        raise PolicyError(f"{rule_id} auto_intent must be true or false")
    return BehaviorRule(
        rule_id,
        str(risk),
        "third_party",
        note.strip(),
        when,
        auto_intent,
        _flag(item, "user_grantable", False),
    )


def _objects(raw: list, source: str) -> list[ObjectRule]:
    if not isinstance(raw, list):
        raise PolicyError("rules must be a list")
    return [_one_object(item, source) for item in raw]


def _one_object(item: dict, source: str) -> ObjectRule:
    if not isinstance(item, dict) or set(item) - _OBJECT_FIELDS - {"subject_id", "provenance"}:
        raise PolicyError("object rule has an unknown field")
    rule_id = item.get("id")
    kind = item.get("object")
    if source in {"user_custom", "user_grant"} and "user_grantable" in item:
        raise PolicyError("user rules cannot set user_grantable")
    if source == "user_grant" and "action" in item:
        raise PolicyError("grant cannot set action")
    action = "allow" if source == "user_grant" else item.get("action")
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyError("object rule needs an id")
    if kind not in _OBJECTS or action not in _ACTIONS:
        raise PolicyError(f"{rule_id} has an unknown object or action")
    rule = ObjectRule(
        id=rule_id,
        source=source,
        action=str(action),
        object=str(kind),
        ops=_ops(item.get("ops"), kind),
        pattern=_strings(item.get("pattern")) if source != "user_grant" else (),
        path=str(item["path"]) if isinstance(item.get("path"), str) else "",
        hosts=_strings(item.get("hosts")),
        cidrs=_strings(item.get("cidrs")),
        match=str(item["match"]) if isinstance(item.get("match"), str) else "",
        tokens=_strings(item.get("tokens")),
        names=_strings(item.get("names")),
        enabled=_enabled(item),
        user_grantable=source == "user_custom" or _flag(item, "user_grantable", False),
    )
    _check_object_shape(rule, source)
    return rule


def _check_object_shape(rule: ObjectRule, source: str) -> None:
    if source == "user_grant":
        rule.validate()
        return
    if rule.object == "file" and not rule.pattern:
        raise PolicyError(f"{rule.id} needs a pattern")
    if rule.object == "domain":
        rule.validate()
    if rule.object == "command" and not rule.match:
        raise PolicyError(f"{rule.id} needs a match")
    if rule.object in {"agentTools", "nativeTools"} and not rule.names:
        raise PolicyError(f"{rule.id} needs names")


def _flag(item: dict, name: str, default: bool) -> bool:
    if name not in item:
        return default
    if not isinstance(item[name], bool):
        raise PolicyError(f"{item.get('id')} {name} must be true or false")
    return item[name]


def _enabled(item: dict) -> bool:
    if "enabled" not in item:
        return True
    if not isinstance(item["enabled"], bool):
        raise PolicyError(f"{item.get('id')} enabled must be true or false")
    return item["enabled"]


def _ops(value, kind: str) -> tuple[str, ...]:
    if value is None:
        return ()
    allowed = _FILE_OPS if kind == "file" else _NET_OPS if kind == "domain" else set()
    names = _strings(value)
    if not allowed or any(name not in allowed for name in names):
        raise PolicyError(f"invalid ops for {kind}")
    return names


def _native_tool_rules(catalogs: dict, os_name: str) -> list[ObjectRule]:
    rules: list[ObjectRule] = []
    deny = _catalog_names(catalogs.get("nativeToolsDenyList"), os_name)
    ask = _catalog_names(catalogs.get("nativeToolsAskList"), os_name)
    if deny:
        rules.append(ObjectRule("nativeTools.deny", "builtin", "deny", "nativeTools", names=deny))
    if ask:
        rules.append(ObjectRule("nativeTools.ask", "builtin", "ask", "nativeTools", names=ask))
    return rules


def _catalog_names(catalog, os_name: str) -> tuple[str, ...]:
    if not isinstance(catalog, dict):
        return ()
    names = list(catalog.get("entries") or ())
    names.extend(catalog.get(os_name) or ())
    return _strings(names)


def _with_privilege(effect: dict, catalogs: dict, os_name: str) -> dict:
    if not isinstance(effect, dict):
        return effect
    copied = dict(effect)
    meta = dict(copied.get("shell_meta") or {})
    windows = os_name == "windows"
    names = {normalize_program(name, windows) for name in _catalog_names(catalogs.get("privilege_argv0"), os_name)}
    argv = argv_of(copied)
    if privilege_requested(copied, names):
        meta["privilege"] = True
    if meta.get("pipe_target") is True and argv:
        sink_names = _catalog_names(catalogs.get("interpreter_sinks"), os_name)
        sinks = {normalize_program(name, windows) for name in sink_names}
        if normalize_program(argv[0], windows) in sinks:
            meta["interpreter_sink"] = True
    copied["shell_meta"] = meta
    return copied


def _merge_catalogs(baseline: dict, extra: dict) -> dict[str, Any]:
    if not isinstance(extra, dict):
        raise PolicyError("catalogs must be a mapping")
    merged = {name: _copy_catalog(name, value) for name, value in baseline.items()}
    for name, value in extra.items():
        if name in FORBIDDEN_CATALOGS:
            raise PolicyError(f"{name} is not a catalog")
        if name in CATALOG_KIND:
            merged[name] = _append_builtin(name, merged.get(name), value)
        else:
            merged[name] = _new_catalog(name, value)
    return merged


def _copy_catalog(name: str, value: dict) -> dict:
    kind = value.get("kind") or CATALOG_KIND.get(name)
    copied = {"kind": kind, "entries": list(_strings(value.get("entries")))}
    for os_name in ("posix", "windows"):
        if os_name in value:
            copied[os_name] = list(_strings(value.get(os_name)))
    return copied


def _append_builtin(name: str, current: dict | None, value) -> dict:
    if isinstance(value, dict) and "kind" in value:
        raise PolicyError(f"{name} cannot set kind")
    entries = _entries_of(value)
    base = current or {"kind": CATALOG_KIND[name], "entries": []}
    base = _copy_catalog(name, base)
    seen = set(base["entries"])
    for item in entries:
        if item not in seen:
            base["entries"].append(item)
            seen.add(item)
    return base


def _new_catalog(name: str, value) -> dict:
    if not isinstance(value, dict) or set(value) != {"kind", "entries"}:
        raise PolicyError(f"{name} needs kind and entries")
    if value.get("kind") not in {"glob", "host", "cidr"}:
        raise PolicyError(f"{name} has unknown kind")
    entries = _strings(value.get("entries"))
    if not entries:
        raise PolicyError(f"{name} needs entries")
    return {"kind": value["kind"], "entries": list(entries)}


def _entries_of(value) -> tuple[str, ...]:
    if isinstance(value, list):
        return _strings(value)
    if isinstance(value, dict) and set(value) <= {"entries"}:
        return _strings(value.get("entries"))
    raise PolicyError("builtin catalog append must be a list or entries")


def _check_catalog_refs(when: dict, catalogs: dict) -> None:
    for node in _walk(when):
        for key, expected in node.items():
            if key in _GLOB_KEYS and isinstance(expected, str):
                _require_kind(expected, catalogs, {"glob"})
            elif key == "path.in_catalog":
                for name in _strings(expected) if not isinstance(expected, dict) else ():
                    _require_kind(name, catalogs, {"glob", "path", "prefix", "user"})
            elif key == "endpoint.in_any_catalog" and not isinstance(expected, dict):
                for name in _as_names(expected):
                    _require_kind(name, catalogs, {"host", "cidr"})


def _require_kind(name: str, catalogs: dict, kinds: set[str]) -> None:
    if name in FORBIDDEN_CATALOGS:
        raise PolicyError(f"{name} is not a catalog")
    catalog = catalogs.get(name)
    if not isinstance(catalog, dict) or catalog.get("kind") not in kinds:
        raise PolicyError(f"{name} cannot be used here")


def _as_names(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    return [str(item) for item in value]


def _walk(when: dict):
    yield when
    for branch in when.get("any") or []:
        if isinstance(branch, dict):
            yield from _walk(branch)
    inner = when.get("not")
    if isinstance(inner, dict):
        yield from _walk(inner)


def _strings(value) -> tuple[str, ...]:
    if value is None:
        return ()
    items = value if isinstance(value, (list, tuple)) else [value]
    if any(not isinstance(item, str) or not item for item in items):
        raise PolicyError("expected a list of strings")
    return tuple(items)


def _unique_ids(ids) -> None:
    seen: set[str] = set()
    for rule_id in ids:
        if rule_id in seen:
            raise PolicyError(f"duplicate id: {rule_id}")
        seen.add(rule_id)
