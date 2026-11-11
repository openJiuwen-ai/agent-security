"""The vault's etcd authority.

The Go counterpart is ``pkg/vault/etcd.go`` and its test file.

These tests run against the fake key-value seam the credential manager's
own tests use.  A real etcd *is* reachable — ``docs/ETCD_CLIENT_CONTRACT.md``
says how, and ``test_etcd_real.py`` is this package's suite against one —
but the fake is what these tests use, because it is deterministic and it can
be asked for things a live server cannot easily be asked for.  The
fake reproduces etcd's compare-and-swap faithfully — a comparison that does
not hold leaves the stored value untouched and reports ``succeeded=False``
— which is the behaviour the authority's rules are written against.
"""

from __future__ import annotations

import pytest

from security_gateway.vault.etcdstore.cluster import generation_key
from security_gateway.vault.etcdstore.errors import NotFoundError as StoreNotFoundError
from security_gateway.vault.etcdstore.store import Store
from security_gateway.crypto import (
    KeyBytes,
    Mode,
    decrypt_credential,
    encrypt_credential,
)
from security_gateway.crypto.errors import CryptoError
from security_gateway.vault import Schema, Type
from security_gateway.vault.codec import ContainerField, decode_container, encode_container
from security_gateway.vault.etcd import (
    EtcdAuthority,
    FencedWriteError,
    converge_authority,
    reencrypt_record_payload,
)
from security_gateway.vault.errors import StaleGenerationError, UndecryptableError
from security_gateway.vault.keys import KeySnapshot
from security_gateway.vault.store import bootstrap_schema, open_db

from tests.unit.vault.etcdstore.cluster_fakes import FakeKV

from .conftest import make_test_schema

#: The namespace the fake authority holds.
NS = "test"


def _snapshot(version: int) -> KeySnapshot:
    """A key snapshot for one generation."""
    return KeySnapshot(dek=KeyBytes.random(16), version=version, mode=Mode.AES)


def _payload(schema: Schema, snapshot: KeySnapshot, secret: bytes) -> bytes:
    """A record payload with one encrypted field, sealed under ``snapshot``."""
    return encode_container(
        [
            ContainerField(
                name="endpoint",
                type=Type.STRING,
                encrypted=False,
                data=b"https://x.test",
            ),
            ContainerField(
                name="api_key",
                type=Type.STRING,
                encrypted=True,
                data=encrypt_credential(snapshot.mode, snapshot.dek_bytes(), secret),
            ),
        ]
    )


@pytest.fixture
def db(tmp_path):
    """An empty vault database."""
    database = open_db(str(tmp_path / "vault.db"))
    bootstrap_schema(database)
    try:
        yield database
    finally:
        database.close()


@pytest.fixture
def fake():
    """An empty etcd."""
    return FakeKV()


@pytest.fixture
def authority(fake):
    """An authority over the fake, fenced by the generation record."""
    store = Store(kv=fake, ns=NS, generation_key=generation_key(NS))
    return EtcdAuthority.from_store(store)


class _Keys:
    """The key snapshots the convergence pass opens the records with."""

    def __init__(self, snapshots: dict[int, object]) -> None:
        self._snapshots = snapshots

    def by_version(self, version: int):
        return self._snapshots.get(version)

    def held_versions(self) -> list[int]:
        return sorted(self._snapshots)


class _SchemaLookup:
    """The bit of the store the convergence pass reads."""

    def __init__(
        self, schema: Schema, snapshots: dict[int, object] | None = None
    ) -> None:
        self._schema = schema
        self.keys = _Keys(snapshots or {})
        self.reloads = 0

    def schema_for_version(self, version: int) -> Schema | None:
        return self._schema if version == self._schema.version else None

    def reload_snapshot(self) -> None:
        self.reloads += 1


class RecordingKV(FakeKV):
    """A fake etcd that records the order of its writes."""

    def __init__(self) -> None:
        super().__init__()
        self.writes: list[str] = []

    def put(self, key: str, value: bytes, lease: int = 0) -> int:
        self.writes.append(key)
        return super().put(key, value, lease)


def test_write_record_is_readable_locally(db, authority, fake):
    """A record written through the authority is readable from the local
    database — and from the authority itself."""
    payload = _payload(make_test_schema(), _snapshot(1), b"secret")

    authority.write_record(db, "cred-1", payload, 1, 1)

    row = db.query_one("SELECT data FROM vault_record WHERE id = ?", ("cred-1",))
    assert row is not None
    assert bytes(row[0]) == payload
    assert authority.store.get_record("cred-1").data == payload


def test_delete_record_removes_it_locally(db, authority):
    """A record deleted through the authority is gone locally."""
    payload = _payload(make_test_schema(), _snapshot(1), b"secret")
    authority.write_record(db, "cred-1", payload, 1, 1)

    authority.delete_record(db, "cred-1")

    assert db.query_one("SELECT id FROM vault_record WHERE id = ?", ("cred-1",)) is None
    with pytest.raises(StoreNotFoundError):
        authority.store.get_record("cred-1")


def test_reencrypt_record_payload_reencrypts_under_the_new_key():
    """The payload comes out under the new key, and the old key no longer
    opens it."""
    schema = make_test_schema()
    prev = _snapshot(1)
    cur = _snapshot(2)
    payload = _payload(schema, prev, b"secret")

    rewritten = reencrypt_record_payload(payload, schema, prev, cur)

    fields = {f.name: f for f in decode_container(rewritten)}
    assert (
        decrypt_credential(cur.mode, cur.dek_bytes(), fields["api_key"].data)
        == b"secret"
    )
    with pytest.raises(CryptoError):
        decrypt_credential(prev.mode, prev.dek_bytes(), fields["api_key"].data)


def test_reencrypt_record_payload_refuses_a_payload_it_cannot_open():
    """A payload sealed under a key this store does not hold is refused."""
    schema = make_test_schema()
    payload = _payload(schema, _snapshot(9), b"secret")

    with pytest.raises(UndecryptableError):
        reencrypt_record_payload(payload, schema, _snapshot(1), _snapshot(2))


def test_authority_straggler_count_counts_the_records_under_the_old_key(db, authority):
    """The count is the records still under the older generation."""
    schema = make_test_schema()
    payload = _payload(schema, _snapshot(1), b"secret")
    authority.write_record(db, "cred-1", payload, 1, 1)
    authority.write_record(db, "cred-2", payload, 1, 1)

    # The fence has to move before a record can be stamped with the new
    # generation, and it never moves back.
    authority.advance_generation(2)
    authority.write_record(db, "cred-3", payload, 1, 2)

    assert authority.authority_straggler_count(2) == 2
    assert authority.authority_straggler_count(1) == 0


def test_the_convergence_pass_does_not_move_the_generation_fence(db):
    """The fence belongs to the rotation, not to the convergence pass.

    The Go's ``pkg/vault/etcd.go``'s ``convergeAuthority`` does not touch
    the generation: ``pkg/vault/rotate.go`` moves it before it calls the
    pass.  Moving it here as well would be a second place where the order
    of the fence and the ciphertext could drift apart.
    """
    fake = RecordingKV()
    store = Store(kv=fake, ns=NS, generation_key=generation_key(NS))
    authority = EtcdAuthority.from_store(store)
    schema = make_test_schema()
    prev = _snapshot(1)
    cur = _snapshot(2)

    authority.write_record(db, "cred-1", _payload(schema, prev, b"secret"), 1, 1)
    # The rotation leaves the fence on the generation it is converging to.
    authority.advance_generation(cur.version)
    fake.writes.clear()

    converge_authority(
        _SchemaLookup(schema, {prev.version: prev, cur.version: cur}),
        authority,
        cur,
    )

    record = f"/security_gateway/{NS}/records/cred-1"
    assert record in fake.writes
    assert generation_key(NS) not in fake.writes


def test_the_convergence_pass_opens_a_record_with_its_own_generation(db, authority):
    """A record is opened with the key it was written under.

    The rotation swaps the key before it re-encrypts anything, so a record
    written after the swap is already under the new key.  Opening every
    record with one fixed key fails on the first of them, and the rotation
    never commits.

    The Go's is ``pkg/vault/etcd.go``'s ``convergeAuthority``.
    """
    schema = make_test_schema()
    gen1 = _snapshot(1)
    gen2 = _snapshot(2)
    cur = _snapshot(3)

    authority.write_record(db, "cred-1", _payload(schema, gen1, b"one"), 1, 1)
    authority.advance_generation(2)
    authority.write_record(db, "cred-2", _payload(schema, gen2, b"two"), 1, 2)
    # The rotation moves the fence onto the generation it converges to
    # before it calls the pass; the pass itself leaves it alone.
    authority.advance_generation(cur.version)

    converge_authority(
        _SchemaLookup(
            schema, {gen1.version: gen1, gen2.version: gen2, cur.version: cur}
        ),
        authority,
        cur,
    )

    for record_id, secret in (("cred-1", b"one"), ("cred-2", b"two")):
        entry = authority.store.get_record(record_id)
        fields = {f.name: f for f in decode_container(entry.data)}
        assert (
            decrypt_credential(cur.mode, cur.dek_bytes(), fields["api_key"].data)
            == secret
        )
        assert entry.dek_version == cur.version


def test_the_convergence_pass_refuses_a_record_it_cannot_open(db, authority):
    """A record under a generation this store does not hold is refused.

    It is a stale generation rather than a fault: the record says which
    key wrote it, and this store holds no such key.  Saying that is what
    tells the caller to adopt the fleet's newer generation instead of
    trying to open the record with a key that cannot open it.
    """
    schema = make_test_schema()
    gen1 = _snapshot(1)
    cur = _snapshot(2)

    authority.write_record(db, "cred-1", _payload(schema, gen1, b"one"), 1, 1)

    with pytest.raises(StaleGenerationError):
        converge_authority(
            _SchemaLookup(schema, {cur.version: cur}),
            authority,
            cur,
        )


def test_a_fenced_write_is_not_a_transport_failure(db, authority):
    """A write from a superseded generation is refused, and refused as
    what it is: the writer is behind, not the network."""
    schema = make_test_schema()
    payload = _payload(schema, _snapshot(1), b"secret")
    authority.write_record(db, "cred-1", payload, 1, 1)
    authority.advance_generation(2)

    with pytest.raises(FencedWriteError):
        authority.write_record(db, "cred-2", payload, 1, 1)

    assert db.query_one("SELECT id FROM vault_record WHERE id = ?", ("cred-2",)) is None
