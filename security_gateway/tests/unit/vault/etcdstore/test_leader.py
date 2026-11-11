"""The host leader that owns a store's key minting.

A host may run several processes against one store. Exactly one of them
holds the host leader lease, and that one is allowed to mint the store's
first key.
"""

from __future__ import annotations

from security_gateway.vault.etcdstore.cluster_keys import host_leader_key
from security_gateway.vault.etcdstore.leader import acquire_host_leader

from .cluster_fakes import FakeKV


def _leader(kv: FakeKV, holder: str):
    """Acquire the host leader lease for ``host-a``."""
    return acquire_host_leader(kv, kv, "prod", "host-a", holder, ttl_seconds=30)


def test_a_host_has_one_leader() -> None:
    """Test a host has one leader."""
    kv = FakeKV()

    first = _leader(kv, "first")
    second = _leader(kv, "second")

    assert first is not None
    assert second is None
    assert kv.raw(host_leader_key("prod", "host-a")) == b"first"


def test_a_failed_leader_is_replaced_after_the_lease_expires() -> None:
    """Test a failed leader is replaced after the lease expires."""
    kv = FakeKV()
    first = _leader(kv, "first")
    assert first is not None
    first.start()
    try:
        second = _leader(kv, "second")
        assert second is None

        assert first.lease_id is not None
        kv.expire_lease(first.lease_id)

        third = _leader(kv, "third")
        assert third is not None
    finally:
        first.release()


def test_leadership_is_per_host_not_per_fleet() -> None:
    """Test leadership is per host not per fleet."""
    kv = FakeKV()

    a = _leader(kv, "a")
    b = acquire_host_leader(kv, kv, "prod", "host-b", "b", ttl_seconds=30)

    assert a is not None
    assert b is not None
    assert kv.raw(host_leader_key("prod", "host-a")) == b"a"
    assert kv.raw(host_leader_key("prod", "host-b")) == b"b"
    a.release()
    b.release()
