# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Policy capability validation (fail-closed; design doc section 5.3).

The validator checks a ``SecurityPolicy`` against the capabilities a
specific runtime backend advertises. Any *security* capability the policy
implicitly requires but the runtime cannot enforce raises
:class:`CapabilityUnsupportedError` — never silently downgraded.
"""

from __future__ import annotations

import logging

from jiuwenbox.logging_config import configure_logging
from jiuwenbox.models.policy import SecurityPolicy
from jiuwenbox.server.runtime.capabilities import (
    RuntimeCapabilities,
    SECURITY_CAPABILITIES,
)
from jiuwenbox.server.runtime.errors import CapabilityUnsupportedError

configure_logging()
logger = logging.getLogger(__name__)


def _filesystem_is_restricted(policy: SecurityPolicy) -> bool:
    """Return whether the policy asks for filesystem enforcement."""

    filesystem = policy.filesystem_policy
    if filesystem.read_only or filesystem.read_write:
        return True
    return bool(filesystem.bind_mounts or filesystem.bind_root_entries)


def _endpoint_is_restricted(endpoint) -> bool:
    """Return whether one egress or ingress block names a concrete target."""

    if endpoint.allowed_domains or endpoint.blocked_domains:
        return True
    if endpoint.allowed_ips or endpoint.blocked_ips:
        return True
    return bool(endpoint.allowed_ports or endpoint.blocked_ports)


def _required_capabilities(policy: SecurityPolicy) -> set[str]:
    """Derive the security capabilities a policy implicitly requests.

    The heuristic is intentionally coarse and *safe* (may over-report a
    requirement, never under-report):

    - filesystem ACL / soft delete: any filesystem ``read_only`` /
      ``read_write`` restriction or a Windows-specific policy block implies
      filesystem enforcement.
    - process_tree_containment: any process policy or cgroup pids limit.
    - egress_filter: any non-trivial ``network.egress`` / ``ingress`` rules.
    """
    required: set[str] = set()

    if _filesystem_is_restricted(policy):
        required.add("filesystem_acl")

    if policy.process != policy.process.model_validate({}):
        required.add("process_tree_containment")
    if policy.cgroup.pids_max is not None:
        required.add("process_tree_containment")

    net = policy.network
    if _endpoint_is_restricted(net.egress) or _endpoint_is_restricted(net.ingress):
        required.add("egress_filter")

    return required


def validate_policy_capabilities(
    policy: SecurityPolicy,
    capabilities: RuntimeCapabilities,
) -> list[str]:
    """Validate ``policy`` against ``capabilities`` (fail-closed).

    Returns a list of warnings (empty when everything is satisfied). Raises
    :class:`CapabilityUnsupportedError` for any *security* capability the
    runtime cannot enforce. Non-security capabilities are allowed to fall
    back and are appended as warnings.
    """
    required = _required_capabilities(policy)
    warnings: list[str] = []

    for capability_name in sorted(required):
        supported = getattr(capabilities, capability_name, False)
        if not supported:
            if capability_name in SECURITY_CAPABILITIES:
                raise CapabilityUnsupportedError(
                    f"policy requires capability {capability_name!r} which "
                    f"runtime {capabilities.runtime_name!r} does not support"
                )
            warnings.append(
                f"policy wants {capability_name!r}; runtime "
                f"{capabilities.runtime_name!r} will fall back"
            )

    return warnings