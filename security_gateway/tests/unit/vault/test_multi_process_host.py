"""The host-level coordination a multi-process store runs on.

Every process that opens the same store may read, write and start a
rotation. Only one of them should mint the store's first key; a host
leader elected by the etcd lease key in ``leader.py`` does that.
"""

from __future__ import annotations

import pytest
from tests.unit.vault.etcdstore.cluster_fakes import FakeKV

from security_gateway.vault import (
    Config,
    KeySnapshot,
    Record,
    StaleGenerationError,
    Value,
    Vault,
    rotate,
)
from security_gateway.vault.errors import StoreNotReadyError
from security_gateway.vault.etcd import FencedWriteError
from security_gateway.vault.etcdstore.cluster_keys import host_leader_key
from security_gateway.vault.etcdstore.leader import acquire_host_leader
from security_gateway.vault.keys import KeyBytes, init_keys
from security_gateway.vault.model import Mode
from security_gateway.vault.store import bootstrap_schema, open_db


from .conftest import make_test_schema


def _leader(kv: FakeKV, holder: str):
    return acquire_host_leader(kv, kv, "prod", "host-a", holder, ttl_seconds=30)


def test_a_host_has_one_leader():
    kv = FakeKV()

    first = _leader(kv, "first")
    second = _leader(kv, "second")

    assert first is not None
    assert second is None
    assert kv.raw(host_leader_key("prod", "host-a")) == b"first"


def test_a_failed_leader_is_replaced_after_the_lease_expires():
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
        assert kv.raw(host_leader_key("prod", "host-a")) == b"third"
        third.stop()
        third.release()
    finally:
        first.stop()
        first.release()


def test_a_released_leader_frees_the_key_for_the_next_process():
    kv = FakeKV()
    first = _leader(kv, "first")
    assert first is not None
    first.release()

    second = _leader(kv, "second")

    assert second is not None
    assert kv.raw(host_leader_key("prod", "host-a")) == b"second"
    second.release()


def test_leadership_is_per_host_not_per_fleet():
    kv = FakeKV()

    a = _leader(kv, "a")
    b = acquire_host_leader(kv, kv, "prod", "host-b", "b", ttl_seconds=30)

    assert a is not None
    assert b is not None
    assert kv.raw(host_leader_key("prod", "host-a")) == b"a"
    assert kv.raw(host_leader_key("prod", "host-b")) == b"b"
    a.release()
    b.release()


def test_a_non_leader_does_not_mint_the_store_key(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        with pytest.raises(StoreNotReadyError):
            init_keys(
                db,
                str(tmp_path / "secrets"),
                Mode.AES,
                shared_key_meta=True,
                allow_create=False,
            )
    finally:
        db.close()


def test_multi_process_without_etcd_shares_one_directory(tmp_path):
    """A local store supports several processes on one data directory."""
    schema = make_test_schema()
    a = Vault.open(
        Config(data_dir=str(tmp_path), multi_process=True),
        schema,
    )
    b = Vault.open(
        Config(data_dir=str(tmp_path), multi_process=True),
        schema,
        _allow_duplicate=True,
    )
    try:
        a.put(
            Record(
                id="rec-1",
                fields={
                    "endpoint": Value.new_string("https://a.example.com"),
                    "api_key": Value.new_string("secret-1"),
                },
            )
        )
        assert b.get("rec-1").get_string("api_key") == "secret-1"

        # A rotation in one process moves the shared key metadata; the
        # other process must reload its snapshot when it sees a newer
        # generation, not report the record as unreadable.
        rotate.rotate_dek(a)
        a.put(
            Record(
                id="rec-2",
                fields={
                    "endpoint": Value.new_string("https://b.example.com"),
                    "api_key": Value.new_string("secret-2"),
                },
            )
        )
        assert b.get("rec-2").get_string("api_key") == "secret-2"

        b.put(
            Record(
                id="rec-3",
                fields={
                    "endpoint": Value.new_string("https://c.example.com"),
                    "api_key": Value.new_string("secret-3"),
                },
            )
        )
        assert a.get("rec-3").get_string("api_key") == "secret-3"
    finally:
        b.close()
        a.close()


class _FlakyAuthority:
    """An authority that loses the generation race exactly once."""

    def __init__(self) -> None:
        self.calls = 0
        self.generation_number = 1

    def generation(self) -> int:
        return self.generation_number

    def write_record(self, db, record_id, data, schema_version, generation) -> None:
        self.calls += 1
        if self.calls == 1:
            raise FencedWriteError("the generation moved under the writer")


def test_a_fenced_write_reloads_and_retries(tmp_path, schema):
    store = Vault.open(Config(data_dir=str(tmp_path)), schema)
    try:
        authority = _FlakyAuthority()
        store.authority = authority
        store.put(
            Record(id="cred-1", fields={"api_key": Value.new_string("sk-secret")})
        )

        assert authority.calls == 2
    finally:
        store.close()


class _AuthorityAt:
    def __init__(self, generation: int) -> None:
        self.generation_number = generation

    def generation(self) -> int:
        return self.generation_number


def test_the_write_snapshot_follows_the_authority_generation(tmp_path, schema):
    store = Vault.open(Config(data_dir=str(tmp_path)), schema)
    try:
        pending = KeySnapshot(
            dek=KeyBytes(b"p" * 32),
            version=2,
            mode=Mode.AES,
        )
        store.keys.set_pending(pending)
        store.authority = _AuthorityAt(2)

        snapshot, generation = getattr(store, "_authority_snapshot")()

        assert snapshot is pending
        assert generation == 2
    finally:
        store.close()


def test_an_unknown_authority_generation_is_stale(tmp_path, schema):
    store = Vault.open(Config(data_dir=str(tmp_path)), schema)
    try:
        store.authority = _AuthorityAt(9)
        with pytest.raises(StaleGenerationError):
            getattr(store, "_authority_snapshot")()
    finally:
        store.close()
