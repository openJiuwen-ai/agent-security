"""Project an immutable LaunchPlan onto JiuwenBox's SecurityPolicy document.

This module is the only place that knows JiuwenBox's policy schema. It is
deliberately free of I/O: the runner passes the returned dict to the JiuwenBox
management API and then reads the sandbox back to verify that what the engine
holds matches the plan digest.

Field names follow ``jiuwenbox/src/jiuwenbox/models/policy.py``:

* ``filesystem_policy.bind_mounts[].{host_path,sandbox_path,mode}``
* ``network.egress.{allowed_domains,allowed_ips,allowed_ports}``
* ``cgroup.{memory_max,cpu_max,pids_max}`` with ``cpu_max = (quota_us, period_us)``
"""

from __future__ import annotations

import hashlib
import json
import posixpath
from typing import Any, Iterable, Mapping

from ..policy.errors import UnsupportedCapability
from ..policy.model import LaunchPlan

CPU_PERIOD_US = 100_000


def _normalize_root(root: str) -> str:
    if not root.startswith("/"):
        raise UnsupportedCapability(f"trusted root must be absolute: {root!r}")
    return posixpath.normpath(root)


def _check_host_path(host_path: str, allowed_roots: Iterable[str]) -> str:
    """Reject any path that is not inside an administrator-owned root.

    The runner must never mount a host path that merely *looks* like it came
    from the catalog: the catalog is re-read from the trusted store, and the
    resolved path is checked here again before it reaches the engine.
    """

    if not host_path.startswith("/"):
        raise UnsupportedCapability(f"mount source must be absolute: {host_path!r}")
    normalized = posixpath.normpath(host_path)
    if ".." in normalized.split("/"):
        raise UnsupportedCapability(f"mount source escapes its root: {host_path!r}")
    for root in allowed_roots:
        root_n = _normalize_root(root)
        if normalized == root_n or normalized.startswith(root_n.rstrip("/") + "/"):
            return normalized
    raise UnsupportedCapability(f"mount source {normalized!r} is outside every trusted root", path=normalized)


def _cpu_max(quota: float) -> tuple[int, int]:
    quota_us = int(round(quota * CPU_PERIOD_US))
    if quota_us <= 0:
        raise UnsupportedCapability(f"cpu quota must be > 0, got {quota!r}")
    return quota_us, CPU_PERIOD_US


def to_jiuwenbox_policy(
    plan: LaunchPlan,
    *,
    run_as_user: str,
    run_as_group: str,
    allowed_roots: Iterable[str],
    environment: Mapping[str, str] | None = None,
    landlock: str = "hard_requirement",
    network_mode: str = "isolated",
    drop_capabilities: bool = False,
) -> dict[str, Any]:
    """Build the complete policy document for one sandbox.

    ``landlock='hard_requirement'`` is the strict default from the design: if
    the kernel cannot provide the required ABI the sandbox must fail to start
    rather than silently run with a weaker boundary.
    """

    if not run_as_user or not run_as_group:
        raise UnsupportedCapability("run_as_user/run_as_group must be resolved before policy build")

    bind_mounts = []
    seen_targets: set[str] = set()
    for mount in plan.mounts:
        source = _check_host_path(mount.source, allowed_roots)
        target = posixpath.normpath(mount.target)
        if not target.startswith("/"):
            raise UnsupportedCapability(f"sandbox target must be absolute: {mount.target!r}")
        if target in seen_targets:
            raise UnsupportedCapability(f"duplicate sandbox target {target!r}")
        seen_targets.add(target)
        bind_mounts.append(
            {
                "host_path": source,
                "sandbox_path": target,
                "mode": "ro" if mount.read_only else "rw",
            }
        )

    allowed_domains: list[str] = []
    allowed_ips: list[str] = []
    allowed_ports: set[int] = set()
    for rule in plan.network:
        if rule.kind == "direct_tcp":
            allowed_ips.append(rule.host)
        else:  # http_connect / model: exact FQDN only
            if any(ch in rule.host for ch in "*[]"):
                raise UnsupportedCapability(f"wildcard host is not allowed: {rule.host!r}")
            allowed_domains.append(rule.host)
        allowed_ports.add(rule.port)

    cgroup: dict[str, Any] = {}
    if "memory_bytes" in plan.quotas:
        cgroup["memory_max"] = int(plan.quotas["memory_bytes"])
    if "cpu" in plan.quotas:
        cgroup["cpu_max"] = _cpu_max(plan.quotas["cpu"])
    if "pids" in plan.quotas:
        cgroup["pids_max"] = int(plan.quotas["pids"])

    return {
        "version": 1,
        "name": f"hypershell-{plan.app_id}",
        "environment": dict(environment or {}),
        "filesystem_policy": {
            "bind_mounts": bind_mounts,
            # A registered resource is the only way in; no blanket host reads.
            "directories": [],
            "files": [],
            "read_only": [],
            "read_write": [],
        },
        "process": {"run_as_user": run_as_user, "run_as_group": run_as_group},
        # The workload drops to a real per-user UID, so user namespaces stay
        # off; pid/ipc/cgroup/uts isolation is always on.
        "namespace": {"user": False, "pid": True, "ipc": True, "cgroup": True, "uts": True},
        # Do NOT --cap-drop ALL by default: JiuwenBox's in-sandbox daemon needs
        # CAP_SYS_ADMIN while it installs Landlock/seccomp *before* dropping to
        # the workload UID. Passing --cap-drop ALL makes that setup fail with
        # EPERM (verified on the G0 host). The workload still ends up with
        # CapEff=0, so this is setup ordering, not a weaker boundary.
        "capabilities": {"add": [], "drop": ["ALL"] if drop_capabilities else []},
        "landlock": {"compatibility": landlock},
        "network": {
            "mode": network_mode,
            "egress": {
                "default": "deny",
                "allowed_domains": allowed_domains,
                "allowed_ips": allowed_ips,
                "allowed_ports": sorted(allowed_ports),
            },
            "ingress": {"default": "deny"},
        },
        "cgroup": cgroup,
    }


def policy_digest(policy: Mapping[str, Any]) -> str:
    """Stable digest of the policy document, used for read-back verification."""

    canonical = json.dumps(policy, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()
