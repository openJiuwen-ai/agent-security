"""Semantic diff of two agent-pdp/v1 documents. One relax makes the update a relax."""

from __future__ import annotations

import json
from dataclasses import dataclass

from agent_shield.policy_engine.builtin.catalog import CATALOG_KIND, DEFAULT_RISK
from agent_shield.policy_engine.matchers.command import tokenize
from agent_shield.policy_engine.core.action_mapping import DEFAULT_ACTION
from agent_shield.policy_engine.builtin.policy import RISK_RANK

_STRENGTH = {"allow": 0, "ask": 1, "deny": 2}
_APPEND_TIGHTENS = {
    "protectedFiles",
    "protectedReadFiles",
    "sensitiveFiles",
    "nativeToolsDenyList",
    "nativeToolsAskList",
    "privilege_argv0",
    "interpreter_sinks",
    "systemPrefixes",
}
_APPEND_RELAXES = {"userFiles", "allowlist_hosts", "allowlist_cidrs"}
_FULL_OPS = {
    "file": {"read", "write", "delete"},
    "domain": {"connect", "fetch", "egress"},
}
_REF_KEYS = {"path.glob_any", "local_files.glob_any", "path.in_catalog", "endpoint.in_any_catalog"}


@dataclass(frozen=True)
class UpdateClass:
    kind: str
    changes: tuple[str, ...]


def classify_update(old: dict, new: dict) -> UpdateClass:
    changes: list[str] = []
    relaxed = False

    def add(kind: str, text: str) -> None:
        nonlocal relaxed
        changes.append(text)
        if kind == "relax":
            relaxed = True

    _rules(old, new, add)
    _behaviors(old, new, add)
    _catalogs(old, new, add)
    _mapping(old, new, add)
    return UpdateClass("relax" if relaxed else "tighten", tuple(changes))


def _rules(old: dict, new: dict, add) -> None:
    previous = _by_id(old.get("rules"))
    current = _by_id(new.get("rules"))
    for rule_id in sorted(set(previous) | set(current)):
        left = previous.get(rule_id)
        right = current.get(rule_id)
        if left is None:
            if _on(right):
                add("tighten", f"{rule_id} added")
            continue
        if right is None:
            if _on(left):
                add("relax" if left.get("action") in {"deny", "ask"} else "tighten", f"{rule_id} removed")
            continue
        _one_rule(rule_id, left, right, add)


def _one_rule(rule_id: str, left: dict, right: dict, add) -> None:
    _grantable_change(rule_id, left, right, add)
    enabled_changed = _on(left) != _on(right)
    action_changed = left.get("action") != right.get("action")
    surface = _matcher_surface(left, right)
    if enabled_changed and (action_changed or surface != "same"):
        add("relax", f"{rule_id} enable bit changed with the matcher")
        return
    if enabled_changed:
        add(_enabled_kind(right.get("action"), _on(right)), f"{rule_id} enabled {_on(left)}->{_on(right)}")
    if action_changed and surface != "same":
        add("relax", f"{rule_id} action and matcher both changed")
        return
    if action_changed:
        kind = "tighten" if _STRENGTH[right["action"]] > _STRENGTH[left["action"]] else "relax"
        add(kind, f"{rule_id} {left['action']}->{right['action']}")
    if surface == "same":
        return
    if surface == "unknown":
        add("relax", f"{rule_id} matcher changed")
        return
    action = right.get("action")
    strict = action in {"deny", "ask"}
    grew = surface == "larger"
    kind = "tighten" if grew == strict else "relax"
    add(kind, f"{rule_id} matcher {surface}")


def _behaviors(old: dict, new: dict, add) -> None:
    previous = _by_id(old.get("behavior_rules"))
    current = _by_id(new.get("behavior_rules"))
    for rule_id in sorted(set(previous) | set(current)):
        if rule_id in DEFAULT_RISK:
            _builtin(rule_id, previous.get(rule_id), current.get(rule_id), add)
        else:
            _third_party(rule_id, previous.get(rule_id), current.get(rule_id), old, new, add)


def _builtin(rule_id: str, left: dict | None, right: dict | None, add) -> None:
    old_risk, old_auto = _builtin_fields(rule_id, left)
    new_risk, new_auto = _builtin_fields(rule_id, right)
    if RISK_RANK[new_risk] > RISK_RANK[old_risk]:
        add("tighten", f"{rule_id} {old_risk}->{new_risk}")
    elif RISK_RANK[new_risk] < RISK_RANK[old_risk]:
        add("relax", f"{rule_id} {old_risk}->{new_risk}")
    if old_auto and not new_auto:
        add("tighten", f"{rule_id} auto_intent off")
    elif new_auto and not old_auto:
        add("relax", f"{rule_id} auto_intent on")
    _grantable_change(rule_id, left, right, add)


def _third_party(rule_id: str, left: dict | None, right: dict | None, old: dict, new: dict, add) -> None:
    if left is None and right is not None:
        kind = "relax" if _behavior_action(right, new) == "allow" else "tighten"
        add(kind, f"{rule_id} added")
        return
    if right is None and left is not None:
        kind = "tighten" if _behavior_action(left, old) == "allow" else "relax"
        add(kind, f"{rule_id} removed")
        return
    if left is None or right is None:
        return
    old_action = _behavior_action(left, old)
    new_action = _behavior_action(right, new)
    when_changed = left.get("when") != right.get("when")
    if old_action != new_action and when_changed:
        add("relax", f"{rule_id} action and when both changed")
    elif old_action != new_action:
        kind = "tighten" if _STRENGTH[new_action] > _STRENGTH[old_action] else "relax"
        add(kind, f"{rule_id} {old_action}->{new_action}")
    elif when_changed:
        surface = _when_surface(left.get("when"), right.get("when"))
        if surface != "same":
            add(_when_kind(new_action, surface), f"{rule_id} when {surface}")
    old_auto = bool(left.get("auto_intent", False))
    new_auto = bool(right.get("auto_intent", False))
    if old_auto and not new_auto:
        add("tighten", f"{rule_id} auto_intent off")
    elif new_auto and not old_auto:
        add("relax", f"{rule_id} auto_intent on")
    if left is not None and right is not None:
        _grantable_change(rule_id, left, right, add)


def _catalogs(old: dict, new: dict, add) -> None:
    previous = old.get("catalogs") or {}
    current = new.get("catalogs") or {}
    refs: dict[str, set[str]] = {}
    for source in (_catalog_actions(old), _catalog_actions(new)):
        for name, actions in source.items():
            refs.setdefault(name, set()).update(actions)
    for name in sorted(set(previous) | set(current)):
        old_entries = _entries(previous.get(name))
        new_entries = _entries(current.get(name))
        delta = _entry_delta(old_entries, new_entries)
        if name in CATALOG_KIND:
            _builtin_catalog(name, delta, add)
            continue
        both = name in previous and name in current
        if both and _kind(previous[name]) != _kind(current[name]):
            add("relax", f"{name} kind changed")
            continue
        actions = refs.get(name, set())
        if not actions or delta == "same":
            continue
        mixed = bool(actions - {"deny", "ask"}) and bool(actions - {"allow"})
        if delta == "unknown" or mixed:
            add("relax", f"{name} entries changed")
            continue
        strict = actions <= {"deny", "ask"}
        grew = delta == "append"
        add("tighten" if grew == strict else "relax", f"{name} {delta}")


def _builtin_catalog(name: str, delta: str, add) -> None:
    if delta == "same":
        return
    if delta == "unknown" or name not in _APPEND_TIGHTENS | _APPEND_RELAXES:
        add("relax", f"{name} entries changed")
        return
    grew = delta == "append"
    tightens = name in _APPEND_TIGHTENS
    add("tighten" if grew == tightens else "relax", f"{name} {delta}")


def _mapping(old: dict, new: dict, add) -> None:
    left = _filled(old.get("action_mapping"))
    right = _filled(new.get("action_mapping"))
    for risk in DEFAULT_ACTION:
        if left[risk] == right[risk]:
            continue
        kind = "tighten" if _STRENGTH[right[risk]] > _STRENGTH[left[risk]] else "relax"
        add(kind, f"action_mapping {risk} {left[risk]}->{right[risk]}")


def _grantable_change(rule_id: str, left: dict | None, right: dict | None, add) -> None:
    old = bool(left.get("user_grantable", False)) if isinstance(left, dict) else False
    new = bool(right.get("user_grantable", False)) if isinstance(right, dict) else False
    if old and not new:
        add("tighten", f"{rule_id} user_grantable off")
    elif new and not old:
        add("relax", f"{rule_id} user_grantable on")


def _builtin_fields(rule_id: str, item: dict | None) -> tuple[str, bool]:
    risk = DEFAULT_RISK[rule_id]
    auto = risk == "medium"
    if not item:
        return risk, auto
    if "risk" in item:
        risk = str(item["risk"])
    if "auto_intent" in item:
        auto = bool(item["auto_intent"])
    return risk, auto


def _behavior_action(item: dict, document: dict) -> str:
    mapping = document.get("action_mapping") or {}
    risk = str(item.get("risk"))
    action = mapping.get(risk)
    if action in _STRENGTH:
        return action
    return DEFAULT_ACTION[risk]


def _when_kind(action: str, surface: str) -> str:
    if surface == "unknown":
        return "relax"
    strict = action in {"deny", "ask"}
    grew = surface == "larger"
    if surface == "same":
        return "tighten"
    return "tighten" if grew == strict else "relax"


def _enabled_kind(action: str, turned_on: bool) -> str:
    strict = action in {"deny", "ask"}
    return "tighten" if turned_on == strict else "relax"


def _matcher_surface(left: dict, right: dict) -> str:
    if left.get("object") != right.get("object"):
        return "unknown"
    kind = left.get("object")
    directions = []
    if kind in _FULL_OPS:
        directions.append(_set_surface(_ops(left), _ops(right)))
    if kind == "file":
        directions.append(_set_surface(set(left.get("pattern") or []), set(right.get("pattern") or [])))
    if kind == "domain":
        directions.append(_set_surface(set(left.get("hosts") or []), set(right.get("hosts") or [])))
        directions.append(_set_surface(set(left.get("cidrs") or []), set(right.get("cidrs") or [])))
    if kind == "command":
        left_tokens = tokenize(str(left.get("match") or ""))
        right_tokens = tokenize(str(right.get("match") or ""))
        directions.append(_prefix_surface(left_tokens, right_tokens))
    if kind in {"agentTools", "nativeTools"}:
        directions.append(_set_surface(set(left.get("names") or []), set(right.get("names") or [])))
    return _combine(directions)


def _ops(rule: dict) -> set[str]:
    names = rule.get("ops")
    if not names:
        return set(_FULL_OPS.get(rule.get("object"), ()))
    return set(names)


def _when_surface(old, new) -> str:
    if old == new:
        return "same"
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "unknown"
    directions = []
    for key in set(old) - set(new):
        directions.append(_dropped_key(key))
    for key in set(new) - set(old):
        directions.append(_added_key(key))
    for key in set(old) & set(new):
        if old[key] != new[key]:
            directions.append(_key_surface(key, old[key], new[key]))
    return _combine(directions)


def _dropped_key(key: str) -> str:
    if key == "any":
        return "smaller"
    if key == "not":
        return "larger"
    return "larger"


def _added_key(key: str) -> str:
    if key == "any":
        return "larger"
    if key == "not":
        return "smaller"
    return "smaller"


def _key_surface(key: str, old, new) -> str:
    if key == "any":
        return _branch_surface(old, new)
    if key == "not":
        return _not_surface(old, new)
    if key == "argv_prefix":
        return _prefix_surface(list(old or []), list(new or []))
    if isinstance(old, list) and isinstance(new, list):
        return _list_surface(old, new)
    if isinstance(old, dict) and isinstance(new, dict):
        return _when_surface(old, new)
    return "unknown"


def _not_surface(old, new) -> str:
    if not isinstance(old, dict) or not isinstance(new, dict):
        return "unknown"
    directions = []
    for key in set(old) - set(new):
        directions.append("larger")
    for key in set(new) - set(old):
        directions.append("smaller")
    for key in set(old) & set(new):
        if old[key] == new[key]:
            continue
        if isinstance(old[key], list) and isinstance(new[key], list):
            directions.append(_invert(_list_surface(old[key], new[key])))
        else:
            directions.append("unknown")
    return _combine(directions)


def _branch_surface(old, new) -> str:
    if not isinstance(old, list) or not isinstance(new, list):
        return "unknown"
    left = {_canon(item) for item in old}
    right = {_canon(item) for item in new}
    return _set_surface(left, right)


def _list_surface(old: list, new: list) -> str:
    return _set_surface(set(_canon(item) for item in old), set(_canon(item) for item in new))


def _prefix_surface(old: list, new: list) -> str:
    if old == new:
        return "same"
    if len(new) > len(old) and new[: len(old)] == old:
        return "smaller"
    if len(old) > len(new) and old[: len(new)] == new:
        return "larger"
    return "unknown"


def _set_surface(old: set, new: set) -> str:
    if old == new:
        return "same"
    if old < new:
        return "larger"
    if new < old:
        return "smaller"
    return "unknown"


def _combine(directions: list[str]) -> str:
    if "unknown" in directions:
        return "unknown"
    found = {item for item in directions if item != "same"}
    if len(found) != 1:
        return "same" if not found else "unknown"
    return found.pop()


def _invert(surface: str) -> str:
    if surface == "larger":
        return "smaller"
    if surface == "smaller":
        return "larger"
    return surface


def _catalog_actions(document: dict) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for item in document.get("behavior_rules") or []:
        if not isinstance(item, dict):
            continue
        action = _behavior_action(item, document) if item.get("risk") else "ask"
        for name in _names_in(item.get("when")):
            if name not in CATALOG_KIND:
                found.setdefault(name, set()).add(action)
    return found


def _names_in(when) -> list[str]:
    if not isinstance(when, dict):
        return []
    names: list[str] = []
    for key, value in when.items():
        if key in _REF_KEYS and not isinstance(value, dict):
            if isinstance(value, str):
                names.append(value)
            elif isinstance(value, list):
                names.extend(item for item in value if isinstance(item, str))
        elif key == "any" and isinstance(value, list):
            for branch in value:
                names.extend(_names_in(branch))
        elif isinstance(value, dict):
            names.extend(_names_in(value))
    return names


def _entry_delta(old: list[str], new: list[str]) -> str:
    left, right = set(old), set(new)
    if left == right:
        return "same"
    if left < right:
        return "append"
    if right < left:
        return "delete"
    return "unknown"


def _entries(value) -> list[str]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    if isinstance(value, dict):
        return [item for item in value.get("entries") or [] if isinstance(item, str)]
    return []


def _kind(value) -> str | None:
    if isinstance(value, dict):
        return value.get("kind")
    return None


def _filled(mapping) -> dict[str, str]:
    filled = dict(DEFAULT_ACTION)
    if isinstance(mapping, dict):
        for risk, action in mapping.items():
            if risk in filled and action in _STRENGTH:
                filled[risk] = action
    return filled


def _by_id(items) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for item in items or []:
        if isinstance(item, dict) and isinstance(item.get("id"), str):
            found[item["id"]] = item
    return found


def _on(rule: dict | None) -> bool:
    return bool(rule) and rule.get("enabled", True) is not False


def _canon(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
