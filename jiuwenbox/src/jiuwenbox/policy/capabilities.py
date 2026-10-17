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

    fs = policy.filesystem_policy
    if fs.read_only or fs.read_write or fs.bind_mounts or fs.bind_root_entries:
        required.add("filesystem_acl")

    if policy.process != policy.process.model_validate({}):
        required.add("process_tree_containment")
    if policy.cgroup.pids_max is not None:
        required.add("process_tree_containment")

    net = policy.network
    egress = net.egress
    ingress = net.ingress
    if (
        egress.allowed_domains
        or egress.blocked_domains
        or egress.allowed_ips
        or egress.blocked_ips
        or egress.allowed_ports
        or egress.blocked_ports
        or ingress.allowed_domains
        or ingress.blocked_domains
        or ingress.allowed_ips
        or ingress.blocked_ips
        or ingress.allowed_ports
        or ingress.blocked_ports
    ):
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