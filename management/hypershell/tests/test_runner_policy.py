"""Tests for the JiuwenBox policy projection."""

from __future__ import annotations

import pytest

from hypershell.policy import AccessMode, CompileContext, LaunchRequest, Layer, Resource, compile_plan
from hypershell.policy.errors import UnsupportedCapability
from hypershell.runner import policy_digest, to_jiuwenbox_policy

RW = AccessMode.READ_WRITE
RO = AccessMode.READ


def catalog() -> dict[str, Resource]:
    return {
        "self.state": Resource(
            "self.state", "directory", "/srv/hs/u1/agent-state", max_mode=RW, sandbox_target="/data"
        ),
        "self.home": Resource("self.home", "directory", "/srv/hs/u1/home", max_mode=RW, sandbox_target="/home/agent"),
        "finance-knowledge": Resource(
            "finance-knowledge",
            "directory",
            "/srv/resources/finance",
            max_mode=RO,
            sandbox_target="/resources/finance-knowledge",
        ),
        "corporate-llm": Resource("corporate-llm", "model", "model://llm.internal.example", max_mode=RO),
        "search-service": Resource("search-service", "service", "https://search.example.com:443", max_mode=RO),
    }


def plan(**overrides):
    ctx = CompileContext(
        app_id="jiuwenswarm",
        catalog=catalog(),
        boundary=Layer(
            resources={
                "self.state": RW,
                "self.home": RW,
                "finance-knowledge": RO,
                "corporate-llm": RO,
                "search-service": RO,
            }
        ),
        grant=Layer(
            resources={
                "self.state": RW,
                "self.home": RW,
                "finance-knowledge": RO,
                "corporate-llm": RO,
            }
        ),
        required={"self.state": RW, "self.home": RW},
        **overrides,
    )
    request = LaunchRequest(
        resources={"self.state": RW, "self.home": RW, "finance-knowledge": RO, "corporate-llm": RO},
        services=("corporate-llm",),
    )
    return compile_plan(ctx, request)


def build(**kw):
    return to_jiuwenbox_policy(
        plan(),
        run_as_user="hs-u1",
        run_as_group="hs-u1",
        allowed_roots=["/srv/hs", "/srv/resources"],
        **kw,
    )


def test_mounts_become_bind_mounts_with_modes():
    policy = build()
    mounts = {m["sandbox_path"]: m for m in policy["filesystem_policy"]["bind_mounts"]}
    assert mounts["/data"]["mode"] == "rw"
    assert mounts["/resources/finance-knowledge"]["mode"] == "ro"
    assert mounts["/data"]["host_path"] == "/srv/hs/u1/agent-state"


def test_no_blanket_host_paths_are_injected():
    policy = build()
    fs = policy["filesystem_policy"]
    assert fs["directories"] == [] and fs["files"] == []
    assert fs["read_only"] == [] and fs["read_write"] == []


def test_host_path_outside_trusted_roots_is_refused():
    with pytest.raises(UnsupportedCapability):
        to_jiuwenbox_policy(plan(), run_as_user="hs-u1", run_as_group="hs-u1", allowed_roots=["/opt/somewhere-else"])


def test_network_splits_domains_from_direct_tcp():
    ctx_extra = plan()
    policy = to_jiuwenbox_policy(
        ctx_extra,
        run_as_user="hs-u1",
        run_as_group="hs-u1",
        allowed_roots=["/srv/hs", "/srv/resources"],
    )
    egress = policy["network"]["egress"]
    assert egress["default"] == "deny"
    assert "llm.internal.example" in egress["allowed_domains"]
    assert 443 in egress["allowed_ports"]


def test_cpu_quota_becomes_quota_period_pair():
    ctx = CompileContext(
        app_id="jiuwenswarm",
        catalog=catalog(),
        boundary=Layer(
            resources={"self.state": RW, "self.home": RW}, quotas={"cpu": 1.5, "memory_bytes": 2 * 1024**3, "pids": 128}
        ),
        grant=Layer(resources={"self.state": RW, "self.home": RW}),
        required={"self.state": RW, "self.home": RW},
    )
    request = LaunchRequest(resources={"self.state": RW, "self.home": RW})
    p = compile_plan(ctx, request)
    policy = to_jiuwenbox_policy(p, run_as_user="hs-u1", run_as_group="hs-u1", allowed_roots=["/srv/hs"])
    assert policy["cgroup"]["cpu_max"] == (150_000, 100_000)
    assert policy["cgroup"]["memory_max"] == 2 * 1024**3
    assert policy["cgroup"]["pids_max"] == 128


def test_strict_profile_defaults():
    policy = build()
    assert policy["landlock"]["compatibility"] == "hard_requirement"
    assert policy["namespace"] == {"user": False, "pid": True, "ipc": True, "cgroup": True, "uts": True}
    # bwrap's default already strips capabilities from the workload; an explicit
    # --cap-drop ALL breaks the in-sandbox daemon's Landlock/seccomp setup.
    assert policy["capabilities"]["drop"] == []
    assert policy["process"] == {"run_as_user": "hs-u1", "run_as_group": "hs-u1"}


def test_policy_digest_is_stable_and_sensitive():
    a = build()
    b = build()
    assert policy_digest(a) == policy_digest(b)
    b["cgroup"]["pids_max"] = 999
    assert policy_digest(a) != policy_digest(b)
