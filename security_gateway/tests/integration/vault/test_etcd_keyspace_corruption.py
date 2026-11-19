"""A damaged etcd keyspace must fail as a typed error, not a bare exception.

Someone with etcd write access can leave a generation, roster entry,
rotation marker or presence marker in a shape this package never wrote.
The read paths are the only defense between that damage and a process that
crashes with ``AttributeError`` or silently invents a generation.

These tests need a real etcd because the damage has to go through the same
client and keyspace the authority uses.
"""

from __future__ import annotations

import os
import uuid

import pytest

from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.etcdstore.cluster import Cluster, FencedError, generation_key
from security_gateway.vault.etcdstore.cluster_keys import (
    host_leader_key,
    mint_key,
    node_key,
    presence_key,
)
from security_gateway.vault.etcdstore.errors import InvalidValueError, NotFoundError
from security_gateway.vault.etcdstore.keys import rotation_key
from security_gateway.vault.etcdstore.leader import acquire_host_leader
from security_gateway.vault.etcdstore.store import Store

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"

pytestmark = pytest.mark.skipif(
    not os.environ.get(ETCD_ENDPOINT_ENV),
    reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
)


def _endpoint() -> tuple[str, int]:
    value = os.environ[ETCD_ENDPOINT_ENV].strip()
    for prefix in ("http://", "https://"):
        value = value.removeprefix(prefix)
    host, _, port = value.rstrip("/").partition(":")
    return host, int(port or 2379)


@pytest.fixture
def cluster():
    import etcd3

    namespace = "corrupt-" + uuid.uuid4().hex[:12]
    host, port = _endpoint()
    client = etcd3.Etcd3Client(host=host, port=port)
    store = Store.from_client(client, namespace)
    try:
        yield namespace, Cluster(store.kv, namespace, store.leases), store
    finally:
        client.delete_prefix(f"/security_gateway/{namespace}/")
        client.close()


@pytest.mark.parametrize("value", [b"", b"x", b"-1", b"1e3", b" 1", b"[]"])
def test_a_corrupt_generation_is_a_typed_error(cluster, value):
    namespace, control, store = cluster
    store.kv.put(generation_key(namespace), value)

    with pytest.raises((ValueError, InvalidValueError)):
        control.generation()


def test_advancing_a_generation_backwards_is_refused(cluster):
    namespace, control, store = cluster
    store.kv.put(generation_key(namespace), b"3")

    with pytest.raises(FencedError, match="moving a generation back"):
        control.advance_generation(2)


@pytest.mark.parametrize("value", [b"[]", b"null", b'"x"', b"{bad json"])
def test_a_corrupt_roster_entry_is_skipped_or_typed(cluster, value):
    namespace, control, store = cluster
    store.kv.put(node_key(namespace, "node-a"), value)

    assert control.list_nodes() == []
    with pytest.raises(InvalidValueError):
        control.get_node("node-a")


def test_a_corrupt_rotation_state_is_a_typed_error(cluster):
    namespace, _control, store = cluster
    store.kv.put(rotation_key(namespace), b"[]")

    with pytest.raises(InvalidValueError):
        KVClusterStore(store.kv, namespace, store.leases).get_rotation_state()


def test_a_corrupt_presence_marker_is_skipped(cluster):
    namespace, control, store = cluster
    store.kv.put(presence_key(namespace, "node-a"), b"not-a-generation")
    store.kv.put(presence_key(namespace, "node-b"), b"2")

    assert control.list_present() == {"node-b": 2}


def test_a_corrupt_mint_value_is_still_a_string(cluster):
    namespace, control, store = cluster
    store.kv.put(mint_key(namespace), b"")

    assert control.mint_owner() == ""


def test_a_tampered_leader_key_blocks_the_host_until_it_is_removed(cluster):
    namespace, _control, store = cluster
    key = host_leader_key(namespace, "host-a")
    store.kv.put(key, b"somebody-else")

    assert acquire_host_leader(store.kv, store.leases, namespace, "host-a", "leader") is None

    store.kv.delete(key)
    leader = acquire_host_leader(store.kv, store.leases, namespace, "host-a", "leader")
    assert leader is not None
    leader.release()


def test_random_damage_is_always_a_typed_error(cluster):
    """Random bytes in the control keys must not crash a reader."""
    import random

    namespace, control, store = cluster
    rng = random.Random(0xE7CD)
    keys = [
        generation_key(namespace),
        node_key(namespace, "node-a"),
        rotation_key(namespace),
        presence_key(namespace, "node-a"),
        mint_key(namespace),
        host_leader_key(namespace, "node-a"),
    ]
    for _ in range(40):
        key = rng.choice(keys)
        store.kv.put(key, bytes(rng.randrange(256) for _ in range(rng.randrange(0, 32))))
        try:
            control.generation()
        except (ValueError, InvalidValueError, NotFoundError):
            pass
        try:
            control.list_nodes()
        except (ValueError, InvalidValueError, NotFoundError):
            pass
        try:
            control.get_node("node-a")
        except (ValueError, InvalidValueError, NotFoundError):
            pass
        try:
            KVClusterStore(store.kv, namespace, store.leases).get_rotation_state()
        except (ValueError, InvalidValueError, NotFoundError):
            pass
