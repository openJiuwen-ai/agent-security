"""Strict administrator configuration for the policy-preview demo.

Loading a file does not establish its trust or authenticate a caller. The
privileged runner must load it from an administrator-owned location and verify
filesystem paths and operating-system identities before creating a sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import math
from pathlib import Path
import posixpath
from typing import Any

import yaml

from .policy import (
    AccessMode,
    CompileContext,
    InvalidRequest,
    LaunchPlan,
    LaunchRequest,
    Layer,
    Resource,
    compile_plan,
)
from .policy.errors import PolicyError
from .policy.authorization import RoleProfile, resolve_grants
from .runner import policy_digest, to_jiuwenbox_policy


class ConfigError(PolicyError):
    code = "INVALID_CONFIG"


class StrictLoader(yaml.SafeLoader):
    """Reject repeated keys instead of silently overwriting permissions."""

    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise ConfigError("all configuration keys must be strings")
            if key in result:
                raise ConfigError(f"duplicate key {key!r}")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def load_document(path: str | Path) -> dict[str, Any]:
    try:
        loader = StrictLoader(Path(path).read_text(encoding="utf-8"))
        try:
            data = loader.get_single_data()
        finally:
            loader.dispose()
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        # Do not echo YAML source lines, which could contain credentials.
        raise ConfigError(f"cannot read YAML document: {path}") from exc
    return _object(data, "document")


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(k, str) for k in value):
        raise ConfigError(f"{label} must be an object with string keys")
    return value


def _fields(data: dict, allowed: set[str], required: set[str], label: str) -> None:
    extra, missing = set(data) - allowed, required - set(data)
    if extra or missing:
        raise ConfigError(f"{label}: unknown fields {sorted(extra)}, missing fields {sorted(missing)}")


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise ConfigError(f"{label} must be a non-empty string without surrounding whitespace")
    return value


def _path(value: Any, label: str) -> str:
    value = _text(value, label)
    if not value.startswith("/") or ".." in value.split("/") or posixpath.normpath(value) != value:
        raise ConfigError(f"{label} must be a normalized absolute Linux path without '..'")
    if value == "/" or value.startswith("//") or "\x00" in value:
        raise ConfigError(f"{label} must name a specific path, not the host root")
    return value


def _modes(value: Any, label: str) -> dict[str, AccessMode]:
    data = _object(value, label)
    result = {}
    for rid, mode in data.items():
        _text(rid, label + " resource id")
        if mode not in ("none", "read", "read_write") or not isinstance(mode, str):
            raise ConfigError(f"{label}.{rid} must be none, read or read_write")
        result[rid] = AccessMode.parse(mode)
    return result


def _quotas(value: Any, label: str) -> dict[str, float]:
    data = _object(value, label)
    _fields(data, {"cpu", "memory_bytes", "pids"}, set(), label)
    for key, number in data.items():
        if isinstance(number, bool) or not isinstance(number, (int, float)):
            raise ConfigError(f"{label}.{key} must be a positive number")
        try:
            valid = math.isfinite(number) and number > 0
        except OverflowError:
            valid = False
        if not valid or (key != "cpu" and (not isinstance(number, int))):
            raise ConfigError(f"{label}.{key} must be positive and finite; counts must be integers")
        if key == "cpu" and number < 0.00001:
            raise ConfigError("cpu quota is below the backend's minimum precision")
        if number > 2**53 or (key == "cpu" and number > 1024):
            raise ConfigError(f"{label}.{key} exceeds the demo's supported numeric range")
    return data


@dataclass(frozen=True)
class UserProfile:
    login_uid: int
    run_as_user: str
    run_as_group: str
    grants: dict[str, AccessMode]
    required: dict[str, AccessMode]
    quotas: dict[str, float]
    roles: tuple[str, ...] = ()
    direct_grants: dict[str, AccessMode] = field(default_factory=dict)
    resource_limits: dict[str, AccessMode] = field(default_factory=dict)
    explanation: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AdminConfig:
    allowed_roots: tuple[str, ...]
    catalog: dict[str, Resource]
    users: dict[str, UserProfile]
    quotas: dict[str, float]
    roles: dict[str, RoleProfile] = field(default_factory=dict)
    version: int = 1

    @classmethod
    def load(cls, path: str | Path) -> AdminConfig:
        data = load_document(path)
        version = data.get("version")
        if type(version) is not int or version not in (1, 2):
            raise ConfigError("only configuration versions 1 and 2 are supported")
        _fields(
            data,
            {"version", "allowed_roots", "resources", "users", "quotas"} | ({"roles"} if version == 2 else set()),
            {"version", "allowed_roots", "resources", "users"},
            "config",
        )
        roots = data["allowed_roots"]
        if not isinstance(roots, list) or not roots:
            raise ConfigError("allowed_roots must be a non-empty list")
        roots = tuple(_path(p, "allowed_roots") for p in roots)
        catalog = {}
        for rid, raw in _object(data["resources"], "resources").items():
            _text(rid, "resource id")
            raw = _object(raw, f"resources.{rid}")
            _fields(
                raw,
                {"type", "host_path", "sandbox_path", "max_mode"},
                {"type", "host_path", "sandbox_path", "max_mode"},
                f"resources.{rid}",
            )
            if raw["type"] not in ("directory", "file"):
                raise ConfigError("this demo supports directory and file resources only")
            source = _path(raw["host_path"], "host_path")
            if not any(source == root or source.startswith(root + "/") for root in roots):
                raise ConfigError(f"resource {rid!r} is outside allowed_roots")
            mode = _modes({rid: raw["max_mode"]}, "max_mode")[rid]
            catalog[rid] = Resource(
                rid, raw["type"], source, max_mode=mode, sandbox_target=_path(raw["sandbox_path"], "sandbox_path")
            )

        def permissions(value, label, *, positive=False):
            modes = _modes(value, label)
            for rid, mode in modes.items():
                if rid not in catalog:
                    raise ConfigError(f"{label}: unknown resource {rid!r}")
                if positive and mode == AccessMode.NONE:
                    raise ConfigError(f"{label}: use resource_limits for none")
                if mode > catalog[rid].max_mode:
                    raise ConfigError(f"{label}: resource {rid!r} exceeds max_mode")
            return modes

        roles = {}
        for name, raw in _object(data.get("roles", {}), "roles").items():
            _text(name, "role id")
            raw = _object(raw, f"roles.{name}")
            _fields(raw, {"description", "grants"}, {"grants"}, f"roles.{name}")
            description = _text(raw["description"], "role description") if "description" in raw else ""
            roles[name] = RoleProfile(description, permissions(raw["grants"], f"roles.{name}.grants", positive=True))
        users = {}
        seen_uids = set()
        for name, raw in _object(data["users"], "users").items():
            _text(name, "user id")
            raw = _object(raw, f"users.{name}")
            _fields(
                raw,
                {"login_uid", "run_as_user", "run_as_group", "grants", "required", "quotas"}
                | ({"roles", "resource_limits"} if version == 2 else set()),
                {"login_uid", "run_as_user", "run_as_group"} | ({"grants"} if version == 1 else set()),
                f"users.{name}",
            )
            uid = raw["login_uid"]
            if type(uid) is not int or uid < 0 or uid in seen_uids:
                raise ConfigError("login_uid must be a unique non-negative integer")
            seen_uids.add(uid)
            selected = raw.get("roles", [])
            if not isinstance(selected, list) or not all(isinstance(role, str) for role in selected):
                raise ConfigError(f"users.{name}.roles must be a list of role ids")
            if len(set(selected)) != len(selected) or any(role not in roles for role in selected):
                raise ConfigError(f"users.{name}.roles contains unknown or duplicate roles")
            direct = permissions(raw.get("grants", {}), f"users.{name}.grants", positive=version == 2)
            limits = permissions(raw.get("resource_limits", {}), f"users.{name}.resource_limits")
            grants, explanation = resolve_grants(
                catalog, [("role:" + role, roles[role].grants) for role in sorted(selected)], direct, limits
            )
            # Preserve the v1 representation, including its historical none handling.
            user = UserProfile(
                uid,
                _text(raw["run_as_user"], "run_as_user"),
                _text(raw["run_as_group"], "run_as_group"),
                direct if version == 1 else grants,
                _modes(raw.get("required", {}), "required"),
                _quotas(raw.get("quotas", {}), "user quotas"),
                tuple(sorted(selected)),
                direct,
                limits,
                explanation,
            )
            if user.run_as_user in ("root", "0") or user.run_as_group in ("root", "0"):
                raise ConfigError("the workload must use a non-root identity")
            users[name] = user
        config = cls(roots, catalog, users, _quotas(data.get("quotas", {}), "quotas"), roles, version)
        # Validate every user's grants, even when previewing a different user.
        for name, user in users.items():
            config.compile(name, LaunchRequest(resources=user.grants))
        return config

    def explain(self, user_id: str, resource_id: str | None = None) -> dict[str, Any]:
        if user_id not in self.users:
            raise InvalidRequest("unknown user profile", user=user_id)
        if resource_id is not None and resource_id not in self.catalog:
            raise InvalidRequest("unknown resource id", resource=resource_id)
        user = self.users[user_id]
        resources = user.explanation
        if resource_id is not None:
            resources = {
                resource_id: resources.get(
                    resource_id, {"sources": [], "granted": "none", "limit": None, "effective": "none"}
                )
            }
        payload = {
            "grants": {rid: mode.name.lower() for rid, mode in sorted(user.grants.items())},
            "quotas": {key: min(value, self.quotas.get(key, value)) for key, value in user.quotas.items()},
            "boundary_quotas": self.quotas,
            "required": user.required,
        }
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        return {
            "user_id": user_id,
            "roles": list(user.roles),
            "resources": resources,
            "authorization_digest": digest,
            "scope": "authorized resources, not running sandbox mounts",
        }

    def user_for_uid(self, uid: int) -> str:
        for name, user in self.users.items():
            if user.login_uid == uid:
                return name
        raise InvalidRequest("caller UID is not registered", uid=uid)

    def compile(self, user_id: str, request: LaunchRequest) -> LaunchPlan:
        if user_id not in self.users:
            raise InvalidRequest("unknown user profile", user=user_id)
        user = self.users[user_id]
        return compile_plan(
            CompileContext(
                app_id="jiuwenswarm",
                catalog=self.catalog,
                boundary=Layer(resources={rid: r.max_mode for rid, r in self.catalog.items()}, quotas=self.quotas),
                grant=Layer(resources=user.grants, quotas=user.quotas),
                required=user.required,
            ),
            request,
        )

    def preview(self, user_id: str, request: LaunchRequest, *, simulated: bool) -> dict[str, Any]:
        plan = self.compile(user_id, request)
        user = self.users[user_id]
        policy = to_jiuwenbox_policy(
            plan, run_as_user=user.run_as_user, run_as_group=user.run_as_group, allowed_roots=self.allowed_roots
        )
        return {
            "mode": "preview",
            "deployed": False,
            "identity": {
                "user_id": user_id,
                "login_uid": user.login_uid,
                "source": "demo_selection" if simulated else "os_real_uid",
                "simulated": simulated,
            },
            "plan": {**plan.canonical(), "digest": plan.digest},
            "jiuwenbox_policy": policy,
            "policy_digest": policy_digest(policy),
            "limitations": [
                "No sandbox is created or security boundary enforced.",
                "Runtime users, paths, symlinks and backend capabilities are not verified.",
                "This is a workload-policy preview, not a complete deployable application bundle.",
            ],
        }
