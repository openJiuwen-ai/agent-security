"""The permission compiler: ``E = B ∩ G ∩ R ∩ T`` plus a LaunchPlan.

Only this module is allowed to turn a :class:`LaunchRequest` into concrete
mounts, egress rules and quotas. Everything downstream (runner, backend) must
consume the immutable :class:`LaunchPlan` and re-verify its digest; it must
never accept a user-supplied path, UID or policy fragment.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit

from .errors import (
    IncompatibleProfile,
    InvalidQuota,
    PermissionExceedsBoundary,
    UnknownResource,
    UnsupportedCapability,
)
from .model import (
    DIRECTORY,
    FILE,
    MODEL,
    SERVICE,
    AccessMode,
    LaunchPlan,
    LaunchRequest,
    Layer,
    Mount,
    NetworkRule,
    Resource,
)


def _require(condition, message=""):
    if not condition:
        raise AssertionError(message)


COMPILER_VERSION = "0.1.0"

#: Quota keys the first release understands. Unknown keys are rejected so a
#: typo can never silently remove a limit.
QUOTA_KEYS = ("cpu", "memory_bytes", "pids", "disk_bytes")


@dataclass(frozen=True, slots=True)
class CompileContext:
    """All trusted inputs of one compilation."""

    app_id: str
    catalog: Mapping[str, Resource]
    boundary: Layer
    grant: Layer
    user_restriction: Layer | None = None
    task_restriction: Layer | None = None
    required: Mapping[str, AccessMode] = None  # type: ignore[assignment]
    capabilities: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if self.required is None:
            object.__setattr__(self, "required", {})


def _min_mode(*modes: AccessMode) -> AccessMode:
    return AccessMode(min(int(m) for m in modes))


def effective_permissions(ctx: CompileContext) -> dict[str, AccessMode]:
    """Compute E, the only authoritative permission set.

    Rules:
    * a resource is considered only when it appears in the user's grants;
    * ``B`` absent for a resource means not allowed (organization upper bound);
    * ``R``/``T`` are ``None`` -> inherit, otherwise they act as a selection:
      a resource missing from an explicit map is not granted.
    """

    boundary = ctx.boundary.resources or {}
    grants = ctx.grant.resources or {}

    for rid in list(grants) + list(boundary) + list(ctx.required):
        if rid not in ctx.catalog:
            raise UnknownResource(f"unknown resource id {rid!r}", resource=rid)

    effective: dict[str, AccessMode] = {}
    for rid, granted in grants.items():
        if rid not in boundary:
            continue
        mode = _min_mode(granted, boundary[rid])
        for layer in (ctx.user_restriction, ctx.task_restriction):
            if layer is None:
                continue
            selected = layer.resources or {}
            if rid not in selected:
                mode = AccessMode.NONE
                break
            mode = _min_mode(mode, selected[rid])
        if mode > AccessMode.NONE:
            effective[rid] = mode
    return effective


def _validate_quota_value(key: str, value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise InvalidQuota(f"quota {key} must be a number", quota=key, value=repr(value))
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise InvalidQuota(f"quota {key} must be finite and > 0", quota=key, value=repr(value))
    return number


def effective_quotas(ctx: CompileContext) -> dict[str, float]:
    """Numeric limits are the minimum of every layer that sets them."""

    result: dict[str, float] = {}
    for layer in (ctx.boundary, ctx.grant, ctx.user_restriction, ctx.task_restriction):
        if layer is None or layer.quotas is None:
            continue
        for key, raw in layer.quotas.items():
            if key not in QUOTA_KEYS:
                raise InvalidQuota(f"unknown quota key {key!r}", quota=key)
            value = _validate_quota_value(key, raw)
            result[key] = min(result.get(key, value), value)
    return result


def _check_required(
    effective: Mapping[str, AccessMode],
    required: Mapping[str, AccessMode],
) -> None:
    missing = [rid for rid, mode in required.items() if rid not in effective or effective[rid] < mode]
    if missing:
        raise IncompatibleProfile(
            "application requires resources that the effective profile does not grant: " + ", ".join(sorted(missing)),
            missing=sorted(missing),
        )


def _resolve_mounts(
    ctx: CompileContext,
    selected: Mapping[str, AccessMode],
) -> tuple[Mount, ...]:
    mounts: list[Mount] = []
    targets: dict[str, str] = {}
    for rid, mode in sorted(selected.items()):
        resource = ctx.catalog[rid]
        if resource.kind not in (DIRECTORY, FILE):
            continue
        target = resource.sandbox_target
        _require(target is not None)
        if target in targets:
            raise UnsupportedCapability(
                f"resources {targets[target]} and {rid} map to the same sandbox target {target}",
                target=target,
            )
        targets[target] = rid
        mounts.append(
            Mount(
                resource_id=rid,
                source=resource.backend_ref,
                target=target,
                read_only=mode == AccessMode.READ,
            )
        )
    return tuple(mounts)


def _parse_service(resource: Resource) -> tuple[str, str, int]:
    """Return ``(kind, host, port)`` for a registered service/model."""

    ref = resource.backend_ref
    parsed = urlsplit(ref if "://" in ref else f"https://{ref}")
    if parsed.scheme not in ("http", "https", "tcp", "model"):
        raise UnsupportedCapability(
            f"resource {resource.id} uses unsupported scheme {parsed.scheme!r}",
            resource=resource.id,
        )
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme in ("https", "model") else 80)
    if not host:
        raise UnsupportedCapability(f"resource {resource.id} has no host", resource=resource.id)
    if any(ch in host for ch in "*[]") or "/" in host:
        raise UnsupportedCapability(
            f"resource {resource.id} must use an exact host, got {host!r}",
            resource=resource.id,
        )
    if parsed.scheme == "model":
        return "model", host, port
    if parsed.scheme == "tcp":
        return "direct_tcp", host, port
    return "http_connect", host, port


def _resolve_network(
    ctx: CompileContext,
    selected: Mapping[str, AccessMode],
    requested_services: tuple[str, ...],
) -> tuple[NetworkRule, ...]:
    rules: list[NetworkRule] = []
    allowed_services = {rid for rid in selected if ctx.catalog[rid].kind in (SERVICE, MODEL)}

    unknown = [sid for sid in requested_services if sid not in ctx.catalog]
    if unknown:
        raise UnknownResource("unknown service ids: " + ", ".join(sorted(unknown)), resources=sorted(unknown))
    denied = [sid for sid in requested_services if sid not in allowed_services]
    if denied:
        raise PermissionExceedsBoundary(
            "services requested beyond the effective profile: " + ", ".join(sorted(denied)),
            resources=sorted(denied),
        )

    for rid in sorted(allowed_services):
        kind, host, port = _parse_service(ctx.catalog[rid])
        rules.append(NetworkRule(resource_id=rid, kind=kind, host=host, port=port))
    return tuple(rules)


def _digest(payload: Mapping[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compile_plan(ctx: CompileContext, request: LaunchRequest) -> LaunchPlan:
    """Compile a request into an immutable LaunchPlan.

    Oversized requests are rejected **as a whole** (never silently trimmed),
    per architecture §5.4 step 3.
    """

    effective = effective_permissions(ctx)
    _check_required(effective, ctx.required)

    for rid, mode in request.resources.items():
        if rid not in ctx.catalog:
            raise UnknownResource(f"unknown resource id {rid!r}", resource=rid)
        if rid not in effective:
            raise PermissionExceedsBoundary(f"resource {rid!r} is not granted to this user", resource=rid)
        if mode > effective[rid]:
            raise PermissionExceedsBoundary(
                f"resource {rid!r} requested as {mode.name} but limit is {effective[rid].name}",
                resource=rid,
                requested=int(mode),
                allowed=int(effective[rid]),
            )

    selected = {rid: mode for rid, mode in request.resources.items() if mode > AccessMode.NONE}

    for rid, mode in ctx.required.items():
        if rid not in selected or selected[rid] < mode:
            raise IncompatibleProfile(f"required resource {rid!r} missing from the launch request", resource=rid)

    plan_without_digest = LaunchPlan(
        app_id=ctx.app_id,
        compiler_version=COMPILER_VERSION,
        resources=dict(sorted(selected.items())),
        mounts=_resolve_mounts(ctx, selected),
        network=_resolve_network(ctx, selected, request.services),
        quotas=effective_quotas(ctx),
    )
    return LaunchPlan(
        app_id=plan_without_digest.app_id,
        compiler_version=plan_without_digest.compiler_version,
        resources=plan_without_digest.resources,
        mounts=plan_without_digest.mounts,
        network=plan_without_digest.network,
        quotas=plan_without_digest.quotas,
        digest=_digest(plan_without_digest.canonical()),
    )
