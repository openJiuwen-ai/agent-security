"""Load-time schema for a behavior-rule clause."""

from __future__ import annotations

from agent_shield.policy_engine.errors import PolicyError

_READ_KEYS = {"path.scope", "path.in_catalog", "path.glob_any", "path_kind", "exists"}
_EFFECT_KEYS = {
    "process.exec": {
        "argv0",
        "argv_prefix",
        "argv_contains",
        "argv_has_any",
        "argv_has_any_prefix",
        "shell_meta.privilege",
        "shell_meta.obfuscated",
        "shell_meta.interpreter_sink",
    },
    "fs.read": set(_READ_KEYS),
    "fs.write": set(_READ_KEYS) | {"device_class"},
    "fs.delete": set(_READ_KEYS) | {"force", "bulk"},
    "net.connect": {"endpoint.in_any_catalog"},
    "net.fetch": {"endpoint.in_any_catalog", "method"},
    "net.egress": {"endpoint.in_any_catalog", "secret_like", "local_file_attached", "local_files.glob_any"},
    "privilege.escalate": set(),
    "schedule.create": set(),
}
_COMBINATORS = {"any", "not"}
_STRING_OR_LIST = {"argv0", "method", "path_kind", "device_class", "path.scope"}
_BOOL_KEYS = {
    "shell_meta.privilege",
    "shell_meta.obfuscated",
    "shell_meta.interpreter_sink",
    "force",
    "bulk",
    "secret_like",
    "local_file_attached",
}
_SCOPES = {"workspace", "outside"}
_PATH_KINDS = {"file", "device", "named_pipe"}


def validate_behavior_clause(when: dict) -> None:
    if not isinstance(when, dict) or not when:
        raise PolicyError("when must be a non-empty object")
    effects = _effects_of(when)
    _check_object(when, effects, inside_not=False)


def _effects_of(when: dict) -> set[str]:
    if "effect" in when:
        return _effect_names(when["effect"])
    branches = when.get("any")
    if set(when) == {"any"} and isinstance(branches, list) and branches:
        names: set[str] = set()
        for branch in branches:
            if not isinstance(branch, dict) or "effect" not in branch:
                raise PolicyError("each any branch needs its own effect when the top level has none")
            names |= _effect_names(branch["effect"])
        return names
    raise PolicyError("when needs a top-level effect, or any with an effect on every branch")


def _effect_names(value) -> set[str]:
    names = value if isinstance(value, list) else [value]
    if not names or any(not isinstance(name, str) or name not in _EFFECT_KEYS for name in names):
        raise PolicyError(f"unknown effect: {value}")
    return set(names)


def _check_object(when: dict, effects: set[str], *, inside_not: bool) -> None:
    allowed = set.intersection(*(_EFFECT_KEYS[name] for name in effects)) | _COMBINATORS
    if not inside_not:
        allowed.add("effect")
    for key, value in when.items():
        if key not in allowed:
            raise PolicyError(f"{key} is not valid for {sorted(effects)}")
        if key == "effect":
            _effect_names(value)
        elif key == "any":
            _check_any(value, effects, inside_not=inside_not)
        elif key == "not":
            _check_not(value, effects)
        else:
            _check_value(key, value)


def _check_any(value, effects: set[str], *, inside_not: bool) -> None:
    if not isinstance(value, list) or not value or any(not isinstance(item, dict) or not item for item in value):
        raise PolicyError("any must be a list of when objects")
    for branch in value:
        branch_effects = _effect_names(branch["effect"]) if "effect" in branch else effects
        _check_object(branch, branch_effects, inside_not=inside_not)


def _check_not(value, effects: set[str]) -> None:
    if not isinstance(value, dict) or not value:
        raise PolicyError("not must be one when object")
    if "effect" in value or "not" in value:
        raise PolicyError("not cannot contain effect or not")
    _check_object(value, effects, inside_not=True)


def _check_value(key: str, value) -> None:
    if key in _BOOL_KEYS:
        if value is not True and value is not False:
            raise PolicyError(f"{key} must be true or false")
        return
    if key in {"argv_prefix", "argv_contains", "argv_has_any", "argv_has_any_prefix"}:
        _string_list(key, value)
        return
    if key in _STRING_OR_LIST:
        _one_or_list(key, value)
        if key == "path.scope":
            _members(key, value, _SCOPES)
        if key == "path_kind":
            _members(key, value, _PATH_KINDS)
        return
    if key == "exists":
        allowed = {True, False, None}
        values = value if isinstance(value, list) else [value]
        if not values or any(item not in allowed for item in values):
            raise PolicyError("exists must be true, false, null, or a list of those")
        return
    if key in {"path.glob_any", "local_files.glob_any", "path.in_catalog", "endpoint.in_any_catalog"}:
        _catalog_ref(key, value)
        return
    raise PolicyError(f"unchecked when key: {key}")


def _catalog_ref(key: str, value) -> None:
    if isinstance(value, str) and value.strip():
        return
    if isinstance(value, list) and value and all(isinstance(item, str) and item.strip() for item in value):
        return
    if key == "endpoint.in_any_catalog" and isinstance(value, dict):
        hosts = value.get("hosts") or []
        cidrs = value.get("cidrs") or []
        if set(value) <= {"hosts", "cidrs"} and (hosts or cidrs):
            return
    raise PolicyError(f"{key} must name a catalog, list catalogs, or use an inline glob list")


def _string_list(key: str, value) -> None:
    if not isinstance(value, list) or not value or any(not isinstance(item, str) or not item for item in value):
        raise PolicyError(f"{key} must be a non-empty list of strings")


def _one_or_list(key: str, value) -> None:
    if isinstance(value, str) and value:
        return
    _string_list(key, value)


def _members(key: str, value, allowed: set[str]) -> None:
    values = value if isinstance(value, list) else [value]
    if any(item not in allowed for item in values):
        raise PolicyError(f"{key} has a value outside {sorted(allowed)}")
