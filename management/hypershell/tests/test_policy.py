"""Contract tests for the permission compiler (P-01 .. P-10 in acceptance.md)."""

from __future__ import annotations

import random

import pytest

from hypershell.policy import (
    AccessMode,
    CompileContext,
    IncompatibleProfile,
    InvalidQuota,
    InvalidRequest,
    LaunchRequest,
    Layer,
    PermissionExceedsBoundary,
    Resource,
    UnknownResource,
    UnsupportedCapability,
    compile_plan,
    effective_permissions,
)

RW = AccessMode.READ_WRITE
RO = AccessMode.READ
NONE = AccessMode.NONE


def catalog() -> dict[str, Resource]:
    return {
        "self.state": Resource(
            "self.state",
            "directory",
            "/srv/hs/u1/agent-state",
            max_mode=RW,
            sandbox_target="/data",
        ),
        "self.home": Resource(
            "self.home",
            "directory",
            "/srv/hs/u1/home",
            max_mode=RW,
            sandbox_target="/home/agent",
        ),
        "self.project": Resource(
            "self.project",
            "directory",
            "/srv/hs/u1/project",
            max_mode=RW,
            sandbox_target="/workspace",
        ),
        "finance-knowledge": Resource(
            "finance-knowledge",
            "directory",
            "/srv/resources/finance",
            max_mode=RO,
            sandbox_target="/resources/finance-knowledge",
        ),
        "corporate-llm": Resource(
            "corporate-llm",
            "model",
            "model://llm.internal.example:443",
            max_mode=RO,
        ),
        "search-service": Resource(
            "search-service",
            "service",
            "https://search.example.com:443",
            max_mode=RO,
        ),
    }


def ctx(**overrides) -> CompileContext:
    base = dict(
        app_id="jiuwenswarm",
        catalog=catalog(),
        boundary=Layer(
            resources={
                "self.state": RW,
                "self.home": RW,
                "self.project": RW,
                "finance-knowledge": RO,
                "corporate-llm": RO,
                "search-service": RO,
            }
        ),
        grant=Layer(
            resources={
                "self.state": RW,
                "self.home": RW,
                "self.project": RW,
                "finance-knowledge": RO,
                "corporate-llm": RO,
            }
        ),
        required={"self.state": RW, "self.home": RW},
    )
    base.update(overrides)
    return CompileContext(**base)


def launch(*pairs: tuple[str, AccessMode], services: tuple[str, ...] = ()) -> LaunchRequest:
    return LaunchRequest(resources=dict(pairs), services=services)


BASE = (("self.state", RW), ("self.home", RW))


# --- subset / lattice -------------------------------------------------------


def test_effective_is_subset_of_boundary_and_grant():
    eff = effective_permissions(ctx())
    for rid, mode in eff.items():
        assert mode <= ctx().boundary.resources[rid]  # type: ignore[index]
        assert mode <= ctx().grant.resources[rid]  # type: ignore[index]


def test_boundary_caps_grant():
    c = ctx(grant=Layer(resources={"self.state": RW, "finance-knowledge": RW}))
    eff = effective_permissions(c)
    assert eff["finance-knowledge"] == RO


def test_grant_not_in_boundary_is_dropped():
    boundary = Layer(resources={"self.state": RW, "self.home": RW})
    grant = Layer(resources={"self.state": RW, "self.home": RW, "self.project": RW})
    eff = effective_permissions(ctx(boundary=boundary, grant=grant))
    assert "self.project" not in eff  # boundary lacks it -> organization denies


def test_user_restriction_none_inherits():
    assert effective_permissions(ctx(user_restriction=None)) == effective_permissions(ctx())


def test_user_restriction_empty_means_nothing():
    assert effective_permissions(ctx(user_restriction=Layer(resources={}))) == {}


def test_user_restriction_selects_only_listed():
    eff = effective_permissions(ctx(user_restriction=Layer(resources={"self.state": RW, "self.home": RW})))
    assert set(eff) == {"self.state", "self.home"}


def test_task_restriction_narrows_mode():
    eff = effective_permissions(ctx(task_restriction=Layer(resources={"self.state": RO, "self.home": RW})))
    assert eff["self.state"] == RO


def test_unknown_resource_in_grant_is_rejected():
    with pytest.raises(UnknownResource):
        effective_permissions(ctx(grant=Layer(resources={"made-up": RO})))


# --- request validation ----------------------------------------------------


def test_request_beyond_boundary_rejected_as_a_whole():
    c = ctx()
    with pytest.raises(PermissionExceedsBoundary) as err:
        compile_plan(c, launch(*BASE, ("finance-knowledge", RW)))
    assert err.value.details["resource"] == "finance-knowledge"
    assert err.value.details["allowed"] == int(RO)


def test_request_unknown_id_rejected():
    with pytest.raises(UnknownResource):
        compile_plan(ctx(), launch(*BASE, ("nope", RO)))


def test_request_unknown_field_rejected():
    with pytest.raises(InvalidRequest):
        LaunchRequest.from_dict(
            {
                "resources": [{"id": "self.state", "mode": "read_write", "host_path": "/etc"}],
            }
        )


def test_request_mount_field_rejected_at_top_level():
    with pytest.raises(InvalidRequest):
        LaunchRequest.from_dict({"resources": [], "mounts": ["/:/"]})


def test_required_resource_missing_is_incompatible():
    with pytest.raises(IncompatibleProfile):
        compile_plan(ctx(), launch(("self.state", RW)))


def test_required_resource_below_required_mode_is_incompatible():
    c = ctx(required={"self.state": RW, "self.home": RW})
    with pytest.raises(IncompatibleProfile):
        compile_plan(c, launch(("self.state", RO), ("self.home", RW)))


# --- plan projection ------------------------------------------------------


def test_mounts_are_derived_from_catalog_not_from_the_request():
    plan = compile_plan(ctx(), launch(*BASE, ("finance-knowledge", RO)))
    by_id = {m.resource_id: m for m in plan.mounts}
    assert by_id["finance-knowledge"].source == "/srv/resources/finance"
    assert by_id["finance-knowledge"].target == "/resources/finance-knowledge"
    assert by_id["finance-knowledge"].read_only is True
    assert by_id["self.state"].read_only is False


def test_network_rules_are_exact_host_port():
    c = ctx(
        grant=Layer(
            resources={
                "self.state": RW,
                "self.home": RW,
                "corporate-llm": RO,
                "search-service": RO,
            }
        )
    )
    plan = compile_plan(c, launch(*BASE, ("corporate-llm", RO), ("search-service", RO), services=("search-service",)))
    rules = {(r.resource_id): r for r in plan.network}
    assert rules["corporate-llm"].host == "llm.internal.example"
    assert rules["corporate-llm"].port == 443
    assert rules["search-service"].kind == "http_connect"


def test_wildcard_service_host_is_rejected():
    cat = catalog()
    cat["wild"] = Resource("wild", "service", "https://*.example.com:443", max_mode=RO)
    c = ctx(
        catalog=cat,
        boundary=Layer(resources={"self.state": RW, "self.home": RW, "wild": RO}),
        grant=Layer(resources={"self.state": RW, "self.home": RW, "wild": RO}),
    )
    with pytest.raises(UnsupportedCapability):
        compile_plan(c, launch(*BASE, ("wild", RO)))


def test_service_request_beyond_grant_rejected():
    with pytest.raises(PermissionExceedsBoundary):
        compile_plan(ctx(), launch(*BASE, services=("search-service",)))


# --- quotas ---------------------------------------------------------------


def test_quota_is_minimum_across_layers():
    c = ctx(
        boundary=Layer(resources={"self.state": RW, "self.home": RW}, quotas={"cpu": 4, "memory_bytes": 8 * 1024**3}),
        grant=Layer(resources={"self.state": RW, "self.home": RW}, quotas={"cpu": 2, "pids": 256}),
    )
    plan = compile_plan(c, launch(*BASE))
    assert plan.quotas["cpu"] == 2
    assert plan.quotas["memory_bytes"] == 8 * 1024**3
    assert plan.quotas["pids"] == 256


@pytest.mark.parametrize("bad", [0, -1, float("nan"), float("inf"), True, "8"])
def test_invalid_quota_rejected(bad):
    c = ctx(
        boundary=Layer(resources={"self.state": RW, "self.home": RW}, quotas={"cpu": bad}),
    )
    with pytest.raises(InvalidQuota):
        compile_plan(c, launch(*BASE))


def test_unknown_quota_key_rejected():
    c = ctx(boundary=Layer(resources={"self.state": RW, "self.home": RW}, quotas={"cpu_share": 1}))
    with pytest.raises(InvalidQuota):
        compile_plan(c, launch(*BASE))


# --- digest ---------------------------------------------------------------


def test_digest_is_stable_across_equivalent_inputs():
    a = compile_plan(ctx(), launch(*BASE))
    b = compile_plan(ctx(), launch(*reversed(BASE)))  # same set, different order
    assert a.digest == b.digest


def test_digest_changes_when_permissions_change():
    a = compile_plan(ctx(), launch(*BASE))
    b = compile_plan(ctx(), launch(*BASE, ("self.project", RW)))
    assert a.digest != b.digest


# --- property tests (P-01 / P-02) ----------------------------------------


def _random_layer(rng: random.Random, ids: list[str], allow_none: bool) -> Layer | None:
    if allow_none and rng.random() < 0.3:
        return None
    chosen = [rid for rid in ids if rng.random() < 0.7]
    return Layer(resources={rid: AccessMode(rng.randint(1, 2)) for rid in chosen})


def test_property_effective_is_always_subset_and_monotone():
    rng = random.Random(20261029)
    ids = list(catalog())
    for _ in range(300):
        boundary = Layer(resources={rid: AccessMode(rng.randint(1, 2)) for rid in ids})
        grant = Layer(resources={rid: AccessMode(rng.randint(1, 2)) for rid in ids})
        user = _random_layer(rng, ids, allow_none=True)
        task = _random_layer(rng, ids, allow_none=True)
        c = ctx(boundary=boundary, grant=grant, user_restriction=user, task_restriction=task, required={})
        eff = effective_permissions(c)
        for rid, mode in eff.items():
            assert mode <= boundary.resources[rid]  # type: ignore[index]
            assert mode <= grant.resources[rid]  # type: ignore[index]
            if user is not None:
                assert rid in (user.resources or {})
                assert mode <= user.resources[rid]  # type: ignore[index]

        # tightening any layer must never grow the effective set
        tightened = dict(user.resources or {}) if user is not None else None
        if tightened is not None:
            for rid in list(tightened):
                if tightened[rid] > AccessMode.READ and rng.random() < 0.5:
                    tightened[rid] = AccessMode.READ
        c2 = ctx(
            boundary=boundary,
            grant=grant,
            user_restriction=Layer(resources=tightened) if tightened is not None else None,
            task_restriction=task,
            required={},
        )
        eff2 = effective_permissions(c2)
        for rid, mode in eff2.items():
            assert mode <= eff.get(rid, AccessMode.NONE) or rid not in eff
