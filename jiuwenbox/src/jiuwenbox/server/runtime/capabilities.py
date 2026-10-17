# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Runtime capability model (design doc section 5.3 "能力协商").

``RuntimeCapabilities`` describes what a runtime backend can and cannot
enforce. The policy engine consults it before applying a policy so that a
security control the backend cannot honour is *rejected* rather than
silently dropped (fail-closed). Non-security capabilities may fall back
with a log line.
"""

from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class RuntimeCapabilities:
    """Declarative capability flags for a runtime backend.

    All flags default to ``False``: a runtime that does not explicitly
    claim a capability is assumed not to support it. The capability names
    mirror the taxonomy in the design doc (section 5.3).
    """

    runtime_name: str
    #: The backend exposes a local OS pid for created sandboxes.
    local_pid: bool = False
    #: Long-running background jobs are supported.
    background_jobs: bool = False
    #: In-process file read/write/list fast paths (daemon IPC) exist.
    fast_file_io: bool = False
    #: Recursive filesystem search is supported.
    recursive_search: bool = False
    #: Policies can be hot-reloaded onto a running sandbox.
    live_policy_update: bool = False
    #: The sandbox has a discoverable network identity (ip address).
    network_identity: bool = False
    #: Filesystem ACL / read-write path enforcement.
    filesystem_acl: bool = False
    #: Process-tree containment (job object / pid namespace kill).
    process_tree_containment: bool = False
    #: Outbound network egress filtering (WFP / iptables / netns).
    egress_filter: bool = False
    #: Soft delete / recycle-bin interception.
    soft_delete: bool = False

    #: Human-readable notes for observability; not used for enforcement.
    notes: tuple[str, ...] = ()

    def with_note(self, note: str) -> "RuntimeCapabilities":
        return replace(self, notes=(*self.notes, note))


#: Capabilities that are *security* controls. If a policy requests one of
#: these and the runtime does not advertise it, the policy must fail closed.
SECURITY_CAPABILITIES: tuple[str, ...] = (
    "filesystem_acl",
    "process_tree_containment",
    "egress_filter",
    "soft_delete",
)


def capabilities_from_policy_requirements(policy_requirements: set[str]) -> frozenset[str]:
    """Normalize a set of requested capability names into a frozenset.

    Kept as a tiny helper so callers do not accidentally mutate a shared
    set while the policy engine walks the requirement list.
    """
    return frozenset(policy_requirements)
