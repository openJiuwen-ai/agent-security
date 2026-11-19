"""The key a rotation leaves in the authority for the other nodes."""

from __future__ import annotations

from types import SimpleNamespace

from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.rotate_keys import publish_pending_key, read_pending_key

from .clusterkey.conftest import (
    handover_test_dek,
    make_test_node,
    make_test_roster,
)
from .etcdstore.cluster_fakes import FakeKV


def _store():
    kv = FakeKV()
    return KVClusterStore(kv, "rotate-keys", kv)


def _vault(member, anchor, store):
    return SimpleNamespace(
        _self_identity=member.identity(),
        _cluster_anchor=anchor,
        _cluster_store=store,
    )


def test_every_roster_node_can_open_the_rotation_key():
    store = _store()
    a = make_test_node("node-a")
    b = make_test_node("node-b")
    anchor = make_test_roster(store, [a, b])
    store.put_presence("node-a", 1)
    store.put_presence("node-b", 1)
    dek = handover_test_dek(2)

    published = publish_pending_key(_vault(a, anchor, store), store, 2, dek)
    assert published == 2

    assert read_pending_key(_vault(a, anchor, store), 2) == dek
    assert read_pending_key(_vault(b, anchor, store), 2) == dek


def test_a_node_outside_the_roster_gets_nothing():
    store = _store()
    a = make_test_node("node-a")
    outsider = make_test_node("node-c")
    anchor = make_test_roster(store, [a])
    store.put_presence("node-a", 1)
    dek = handover_test_dek(2)

    publish_pending_key(_vault(a, anchor, store), store, 2, dek)
    assert read_pending_key(_vault(outsider, anchor, store), 2) == b""


def test_a_vault_without_a_cluster_identity_does_not_publish():
    store = _store()
    vault = SimpleNamespace(_self_identity=None, _cluster_anchor=None)
    assert publish_pending_key(vault, store, 2, handover_test_dek(2)) == 0


def test_a_generation_without_a_seal_has_no_key():
    store = _store()
    a = make_test_node("node-a")
    anchor = make_test_roster(store, [a])
    assert read_pending_key(_vault(a, anchor, store), 7) == b""


def test_an_inactive_roster_node_does_not_get_the_key():
    store = _store()
    a = make_test_node("node-a")
    b = make_test_node("node-b")
    anchor = make_test_roster(store, [a, b])
    store.put_presence("node-a", 1)
    dek = handover_test_dek(2)

    published = publish_pending_key(_vault(a, anchor, store), store, 2, dek)

    assert published == 1
    assert read_pending_key(_vault(a, anchor, store), 2) == dek
    assert read_pending_key(_vault(b, anchor, store), 2) == b""
