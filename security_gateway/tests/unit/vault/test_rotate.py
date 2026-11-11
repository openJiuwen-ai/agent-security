"""The vault's key rotation.

The Go counterpart is ``pkg/vault/rotate.go``, and the cases here come from
``tests/unit/vault/vault_test.go`` (``TestRotateDEKKeepsRecordsReadable``,
``TestRotateDEKRejectsRotationAlreadyInProgress``) and from the protocol
the rotation's own comments describe.

The rotation is not observable from the outside while it runs, so most of
these tests watch it from inside: they stand in for one of its steps and
record what the store looked like at that moment. That is the only way to
see the ordering the rotation depends on — that the key is swapped before
the records are re-encrypted, that the fleet lock is taken before
anything else happens, that the authority's fence moves before the
ciphertext does.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
import time
from dataclasses import replace
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from security_gateway.crypto import decrypt_credential, encrypt_credential
from security_gateway.vault import (
    Config,
    RotationInProgressError,
    Type,
    Vault,
    VaultError,
)
from security_gateway.vault import rotate as rotate_module
from security_gateway.vault.codec import ContainerField, decode_container, encode_container
from security_gateway.vault.etcdstore import ListedRecord, RecordEntry
from security_gateway.vault.keys import read_key_meta, update_key_meta
from security_gateway.vault.store import RecordRow
from security_gateway.vault.store import put_record as put_row

from .conftest import put_record, read_raw_data

_REPO_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)


def _encrypted_payload(vault, plaintext: str, snapshot) -> bytes:
    """A record payload with its secret sealed under ``snapshot``."""
    return encode_container(
        [
            ContainerField(
                name="endpoint",
                type=Type.STRING,
                encrypted=False,
                data=b"https://example.test",
            ),
            ContainerField(
                name="api_key",
                type=Type.STRING,
                encrypted=True,
                data=encrypt_credential(
                    snapshot.mode, snapshot.dek_bytes(), plaintext.encode("utf-8")
                ),
            ),
        ]
    )


def _read_secret(payload: bytes, snapshot) -> str:
    """The secret in a record payload, opened with ``snapshot``."""
    for field in decode_container(payload):
        if field.name == "api_key":
            return decrypt_credential(
                snapshot.mode, snapshot.dek_bytes(), field.data
            ).decode("utf-8")
    raise AssertionError("the payload holds no api_key")


# -- the rotation as a whole ------------------------------------------------


def test_a_rotation_keeps_every_record_readable(vault, data_dir):
    """The Go counterpart is ``TestRotateDEKKeepsRecordsReadable``."""
    for record_id in ("cred-1", "cred-2", "cred-3"):
        put_record(vault, record_id)

    before = read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1")

    rotate_module.rotate_dek(vault)

    for record_id in ("cred-1", "cred-2", "cred-3"):
        got = vault.get(record_id)
        assert got.get_string("api_key") == f"secret-for-{record_id}"

    after = read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1")
    assert before != after, "the stored ciphertext did not change across the rotation"

    status = vault.status()
    assert status.dek_version == 2
    assert status.straggler_count == 0


def test_the_straggler_count_drops_to_zero_after_a_full_pass(vault):
    """Every record the rotation rewrote is stamped with the new generation."""
    for i in range(5):
        put_record(vault, f"cred-{i}")

    assert vault.count_stragglers(2) == 5

    rotate_module.rotate_dek(vault)

    assert vault.count_stragglers(2) == 0
    assert vault.status().straggler_count == 0


def test_a_rotation_claims_the_pending_marker(vault, monkeypatch):
    """The pending marker is what makes a rotation exclusive.

    It is set while the rotation runs and cleared when the rotation
    commits, and the key metadata only moves on at the commit — a rotation
    that dies in between leaves the store exactly as it found it, with the
    marker still set.
    """
    put_record(vault, "cred-1")

    observed: dict[str, int] = {}
    real_converge = rotate_module.converge

    def spy(vault_, target, store=None, stop=None):
        meta = read_key_meta(vault_.db)
        observed["pending"] = meta.pending_dek_version
        observed["active"] = meta.active_dek_version
        real_converge(vault_, target, store, stop)

    monkeypatch.setattr(rotate_module, "converge", spy)
    rotate_module.rotate_dek(vault)

    assert observed["pending"] == 2, "the rotation did not claim the pending marker"
    assert observed["active"] == 1, (
        "the rotation committed before the records converged"
    )

    meta = read_key_meta(vault.db)
    assert meta.pending_dek_version == 0
    assert meta.active_dek_version == 2
    assert meta.superseded_dek_version == 1


def test_a_rotation_refuses_to_run_on_top_of_a_pending_one(vault, data_dir):
    """The Go counterpart is ``TestRotateDEKRejectsRotationAlreadyInProgress``.

    A rotation that is already under way owns the store until it either
    commits or dies; a second one running on top of it would mint a second
    key for the same generation.
    """
    import sqlite3

    conn = sqlite3.connect(os.path.join(data_dir, "vault.db"), isolation_level=None)
    try:
        conn.execute("UPDATE vault_key_metadata SET pending_dek_version = 99")
    finally:
        conn.close()

    with pytest.raises(RotationInProgressError):
        rotate_module.rotate_dek(vault)


# -- the order the rotation depends on ---------------------------------------


def test_the_new_key_is_in_place_before_the_records_are_re_encrypted(
    vault, monkeypatch
):
    """The new generation is installed before the records are re-encrypted.

    At the moment a record is rewritten the store already holds the new
    key — in the pending slot, which is where the local mode puts it — and
    the record that is being rewritten is still under the old one. That is
    what makes the reader that opens it able to find the right key: the
    generation is on the row, and the snapshot holds it.

    The pending slot rather than a swap is what makes it work: the
    generation is not the authoritative one until the rotation commits, but
    the write path stamps new records with it, and that is what keeps the
    other processes' writes from holding the rotation back.
    """
    put_record(vault, "cred-1")

    observed: dict[str, object] = {}
    real_update = rotate_module.update_record_cipher

    def spy(db, record_id, row_version, data, dek_version):
        pending = vault.keys.pend()
        assert pending is not None
        observed.setdefault("pending_version", pending.version)
        observed.setdefault("dek_version", dek_version)
        observed.setdefault("readable", vault.get(record_id).get_string("api_key"))
        return real_update(db, record_id, row_version, data, dek_version)

    monkeypatch.setattr(rotate_module, "update_record_cipher", spy)
    rotate_module.rotate_dek(vault)

    assert observed["pending_version"] == 2, (
        "the record was rewritten before the new key was in place"
    )
    assert observed["dek_version"] == 2
    assert observed["readable"] == "secret-for-cred-1", (
        "the record was unreadable while it was being re-encrypted"
    )


def test_a_record_written_under_the_old_key_during_the_pass_is_caught_by_the_next_attempt(
    vault, monkeypatch
):
    """A writer can slip a record in after the pass has scanned past it.

    The re-encryption and the commit are in a loop for exactly this: the
    final count happens under the write barrier, so it sees every write
    that was in flight, and if anything is still behind the re-encryption
    runs again rather than the rotation being abandoned with a record no
    key can open.
    """
    put_record(vault, "cred-1")

    real_converge = rotate_module.converge
    attempts: list[int] = []

    def spy(vault_, target, store=None, stop=None):
        attempts.append(len(attempts))
        real_converge(vault_, target, store, stop)
        if len(attempts) == 1:
            # A writer that captured the old key before the rotation and
            # lands after the pass has already scanned past it. In the
            # local mode the outgoing key is the current one: the rotation
            # puts the new generation in the pending slot and leaves the
            # active one alone until it commits.
            cur = vault_.keys.cur()
            assert cur is not None
            put_row(
                vault_.db,
                RecordRow(
                    "cred-late",
                    1,
                    _encrypted_payload(vault_, "sk-late", cur),
                    cur.version,
                ),
            )

    monkeypatch.setattr(rotate_module, "converge", spy)
    rotate_module.rotate_dek(vault)

    assert len(attempts) >= 2, "the rotation committed with a record left behind"
    assert vault.count_stragglers(2) == 0
    assert vault.get("cred-late").get_string("api_key") == "sk-late"


# -- a rotation that dies ----------------------------------------------------


def test_a_rotation_that_dies_leaves_the_pending_marker_set(vault, monkeypatch):
    """The error leaves the store readable.

    The pending marker stays set on purpose: a takeover finishes the job.
    Returning the error leaves the store readable, because the key the
    records were written with is still held.
    """

    def boom(vault_, target, store=None, stop=None):
        raise RuntimeError("the rotation died")

    put_record(vault, "cred-1")
    monkeypatch.setattr(rotate_module, "converge", boom)

    with pytest.raises(RuntimeError):
        rotate_module.rotate_dek(vault)

    meta = read_key_meta(vault.db)
    assert meta.pending_dek_version == 2, (
        "the pending marker was cleared by a failed rotation"
    )
    assert meta.active_dek_version == 1

    pending = vault.keys.pend()
    assert pending is not None, "the pending key was dropped"
    assert pending.version == 2
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"


def test_the_next_open_does_not_take_the_pending_rotation_away(
    data_dir, schema, monkeypatch
):
    """The pending generation belongs to the process that claimed it.

    The key metadata row is shared by every process that opens the store,
    so promoting the pending generation at open time takes the rotation
    away from the rotation that is still running — and leaves two
    generations with a DEK each.
    """

    def boom(vault_, target, store=None, stop=None):
        raise RuntimeError("the rotation died")

    store = Vault.open(Config(data_dir=data_dir), schema)
    try:
        put_record(store, "cred-1")
        monkeypatch.setattr(rotate_module, "converge", boom)
        with pytest.raises(RuntimeError):
            rotate_module.rotate_dek(store)
    finally:
        store.close()

    again = Vault.open(Config(data_dir=data_dir), schema)
    try:
        # The pending generation is not promoted: it goes into its own
        # slot, so that the read path can open the records written under
        # it and the write path can stamp new ones with it.
        assert again.keys.cur().version == 1
        pending = again.keys.pend()
        assert pending is not None
        assert pending.version == 2

        meta = read_key_meta(again.db)
        assert meta.pending_dek_version == 2
        assert meta.active_dek_version == 1

        # The store is still readable: it still holds the key the record
        # was written with.
        assert again.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        again.close()


# -- the fleet lock ---------------------------------------------------------


class _FakeLock:
    """A rotation lock that only remembers what it was asked to do."""

    def __init__(self, events: list[tuple]) -> None:
        self._events = events

    def renew(self) -> None:
        self._events.append(("renew",))

    def release(self) -> None:
        self._events.append(("release",))


class _FakeAuthority:
    """A stand-in for the authority's etcd store.

    It holds the records the authority would hold and records the order in
    which the rotation touched it.
    """

    def __init__(
        self,
        records: dict[str, RecordEntry] | None = None,
        events: list[tuple] | None = None,
    ) -> None:
        self.kv = object()
        self.ns = "test"
        # The authority carries the lease seam: the credential store's
        # handle does not, the cluster half does, and the rotation lock
        # lives on a lease.
        self.leases = object()
        self.records = dict(records or {})
        # The caller can hand in the list it wants the order in, so that
        # what the authority did and what the rotation did can be read
        # against each other.
        self.events: list[tuple] = [] if events is None else events

    def list_records(self, limit: int = 0):
        listed = [ListedRecord(rid, self.records[rid]) for rid in sorted(self.records)]
        if limit:
            listed = listed[:limit]
        return listed, 1

    def list_records_from(self, after_record_id: str, limit: int = 0):
        listed = [
            ListedRecord(rid, self.records[rid])
            for rid in sorted(self.records)
            if rid > after_record_id
        ]
        if limit:
            listed = listed[:limit]
        return listed

    def update_record_cas(self, record_id: str, entry: RecordEntry):
        self.events.append(("rewrite", record_id))
        self.records[record_id] = replace(entry)
        return entry


def _fake_generation(monkeypatch, generation: int = 1):
    """Make the authority report the generation it holds.

    The rotation reads the authority's generation before it claims: the
    target is that generation plus one, not the local row's plus one. The
    fake authority has no keyspace of its own, so the read is faked here.
    """

    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.read_generation",
        lambda kv, ns: (generation, True),
    )
    # The fleet's rotation gate: the fake authority has no keyspace, so the
    # read is faked too. A timestamp long past means the fleet is due.
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.last_rotation_at",
        lambda kv, ns: datetime(2020, 1, 1, tzinfo=timezone.utc),
    )


def _fake_acquire(events: list[tuple], fail: bool = False):
    def acquire(kv, leases, ns, holder, ttl_seconds):
        events.append(("lock", holder, ttl_seconds))
        if fail:
            raise RuntimeError("the rotation lock is held by another node")
        return _FakeLock(events)

    return acquire


def test_the_fleet_lock_is_taken_before_anything_else_happens(vault, monkeypatch):
    """In etcd mode the rotation is arbitrated across the fleet.

    Two nodes rotating at once would mint two keys for the same generation
    and leave records under one of them that no other node can open, so
    the lock comes first: a rotation that cannot take it must not have
    touched the store at all.
    """
    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events, fail=True),
    )

    with pytest.raises(VaultError):
        rotate_module.rotate_dek(vault, _FakeAuthority())

    assert events and events[0][0] == "lock"
    meta = read_key_meta(vault.db)
    assert meta.pending_dek_version == 0, (
        "the rotation claimed the store without the lock"
    )
    assert vault.keys.cur().version == 1, (
        "the rotation swapped the key without the lock"
    )


def test_rotate_dek_finds_the_authority_store_without_a_handle(vault, monkeypatch):
    """The public call is the same in both modes.

    A caller should not have to know that etcd mode needs the authority's
    store to take the fleet lock.  Leaving ``store`` out must still take
    the lock, not quietly run a local rotation against a fleet store.
    """
    events: list[tuple] = []
    vault.authority = SimpleNamespace(store=_FakeAuthority(events=events))
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.advance_generation",
        lambda kv, ns, target: (True, target),
    )
    _fake_generation(monkeypatch)

    rotate_module.rotate_dek(vault)

    assert events and events[0][0] == "lock"
    assert read_key_meta(vault.db).active_dek_version == 2


def test_the_fleet_lock_names_this_process_as_the_holder(vault, monkeypatch):
    """The holder is a process identity, not a node identity."""
    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.advance_generation",
        lambda kv, ns, target: (True, target),
    )
    _fake_generation(monkeypatch)

    rotate_module.rotate_dek(vault, _FakeAuthority())

    lock_event = next(event for event in events if event[0] == "lock")
    assert lock_event[1] == rotate_module.rotation_holder()
    assert lock_event[2] == rotate_module.ROTATION_LOCK_TTL_SECONDS


def test_the_fleet_lock_lease_is_kept_alive_for_the_length_of_the_rotation(
    vault, monkeypatch
):
    """The fleet's lock is renewed while the rotation runs.

    The lock lives on an etcd lease, and a lease that is not renewed
    expires.  A rotation of a large store can outlast the lease on its
    own, and a lock that lapses mid-rotation lets a second node start a
    rotation of its own — which is exactly the outcome the lock exists to
    prevent.

    The Go's is the heartbeat in ``pkg/vault/rotate.go``.
    """
    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.advance_generation",
        lambda kv, ns, target: (True, target),
    )
    _fake_generation(monkeypatch)
    # The heartbeat renews every third of the TTL.  A short TTL keeps the
    # test from having to wait half a minute for it.
    monkeypatch.setattr(rotate_module, "ROTATION_LOCK_TTL_SECONDS", 0.3)

    real_converge = rotate_module.converge

    def slow_converge(vault_, target, store=None, stop=None):
        time.sleep(0.5)
        real_converge(vault_, target, store, stop)

    monkeypatch.setattr(rotate_module, "converge", slow_converge)

    rotate_module.rotate_dek(vault, _FakeAuthority())

    renewals = [event for event in events if event[0] == "renew"]
    assert len(renewals) >= 2, (
        "the fleet's lock was not renewed while the rotation was running"
    )


def test_the_rotation_stops_when_the_fleet_lock_lease_is_lost(vault, monkeypatch):
    """A rotation that lost the fleet's lock stops.

    The lock is what keeps two nodes from rotating the fleet at once.  A
    rotation that lost its lease is no longer the only one rotating the
    fleet, so it stops rather than minting a key on top of the rotation
    that took the lock from it.
    """
    events: list[tuple] = []

    class _LosingLock(_FakeLock):
        def renew(self) -> None:
            raise RuntimeError("the lease is gone")

    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        lambda kv, leases, ns, holder, ttl_seconds: _LosingLock(events),
    )
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.advance_generation",
        lambda kv, ns, target: (True, target),
    )
    _fake_generation(monkeypatch)
    monkeypatch.setattr(rotate_module, "ROTATION_LOCK_TTL_SECONDS", 0.3)

    cur = vault.keys.cur()
    assert cur is not None
    authority = _FakeAuthority(
        {
            "cred-1": RecordEntry(
                data=_encrypted_payload(vault, "sk-secret", cur),
                schema_version=1,
                dek_version=cur.version,
                mod_revision=1,
            )
        },
        events,
    )

    def slow_converge(vault_, target, store=None, stop=None):
        # The pass is slow enough for the heartbeat to lose the lease, and
        # it rewrites nothing: the straggler stays, so the rotation comes
        # back for another pass and notices the loss.
        time.sleep(0.5)

    monkeypatch.setattr(rotate_module, "converge", slow_converge)

    with pytest.raises(VaultError) as excinfo:
        rotate_module.rotate_dek(vault, authority)

    assert "lease was lost" in str(excinfo.value), (
        f"the rotation did not stop on the lost lease: {excinfo.value}"
    )


def test_the_fence_moves_before_the_ciphertext(vault, monkeypatch):
    """The authority's fence moves before the records are re-written.

    Every record the pass is about to write is stamped with the target
    generation, so an authority still reading the old generation would
    reject its own rewrite.
    """
    cur = vault.keys.cur()
    assert cur is not None
    events: list[tuple] = []
    authority = _FakeAuthority(
        {
            "cred-1": RecordEntry(
                data=_encrypted_payload(vault, "sk-secret", cur),
                schema_version=1,
                dek_version=cur.version,
                mod_revision=1,
            )
        },
        events,
    )

    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    _fake_generation(monkeypatch)

    def advance(kv, ns, target):
        events.append(("fence", target))
        return True, target

    monkeypatch.setattr("security_gateway.vault.etcdstore.advance_generation", advance)

    rotate_module.rotate_dek(vault, authority)

    kinds = [event[0] for event in events]
    assert "rewrite" in kinds, "the rotation did not rewrite the record"
    assert kinds.index("fence") < kinds.index("rewrite"), (
        "the fence moved after the rotation had already started writing"
    )

    entry = authority.records["cred-1"]
    assert entry.dek_version == 2
    new_key = vault.keys.cur()
    assert new_key is not None
    assert _read_secret(entry.data, new_key) == "sk-secret"


# -- the holder identity -----------------------------------------------------


def test_the_holder_is_a_process_identity():
    """The holder is ``host:pid``."""
    holder = rotate_module.rotation_holder()
    host, _, pid = holder.rpartition(":")
    assert host == socket.gethostname()
    assert int(pid) == os.getpid()


def test_the_holder_is_a_different_process_after_a_restart():
    """A restarted process is a different holder."""
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [os.path.join(_REPO_ROOT, "src"), env.get("PYTHONPATH", "")]
    )
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from security_gateway.vault.rotate import rotation_holder;"
            " print(rotation_holder())",
        ],
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    other = result.stdout.strip()
    assert other != rotate_module.rotation_holder()
    assert other.rpartition(":")[2] != str(os.getpid())


# -- the attachable rotator -------------------------------------------------


def _rotator_threads() -> list[threading.Thread]:
    """The rotator threads that are running."""
    return [
        thread
        for thread in threading.enumerate()
        if thread.name == "cred-router-vault-auto-rotate"
    ]


def _set_the_local_gate(vault, when: int) -> None:
    """Set the store's own record of when it was last rotated."""
    meta = read_key_meta(vault.db)
    assert meta is not None
    meta.last_rotate_at = when
    update_key_meta(vault.db, meta)


def _open_the_gate(vault) -> None:
    """Make the store look like it was rotated long ago.

    The gate reads the store's own ``last_rotate_at``, so a test that
    wants a rotation to happen has to make that timestamp old.
    """
    _set_the_local_gate(vault, int(time.time()) - 3600)


def _wait_for_the_version(vault, version: int, timeout: float = 5.0) -> int:
    """Wait for the store's key generation to reach ``version``."""
    deadline = time.monotonic() + timeout
    current = vault.keys.cur()
    while (
        current is not None
        and current.version < version
        and time.monotonic() < deadline
    ):
        time.sleep(0.02)
        current = vault.keys.cur()
    return current.version if current is not None else 0


def test_the_init_seeds_the_rotation_timestamp(vault):
    """A store that was just minted has just been rotated.

    Without the seed, attaching a rotator to a fresh store would rotate a
    DEK that was minted seconds ago, which has no security benefit.
    """
    meta = read_key_meta(vault.db)
    assert meta is not None
    assert meta.last_rotate_at > 0
    assert meta.last_rotate_at <= int(time.time())


def test_the_rotator_does_not_rotate_before_the_period_has_elapsed(vault):
    """The first tick of a fresh store is a no-op.

    The store was rotated when it was initialised, so the period has not
    elapsed yet and the tick does nothing.
    """
    stop = rotate_module.start_auto_rotate(vault, 3600.0)
    try:
        time.sleep(0.2)
        assert vault.keys.cur().version == 1, "the store rotated before its period"
    finally:
        stop()


def test_the_rotator_rotates_once_the_period_has_elapsed(vault):
    """The gate opens, and the store's key generation moves."""
    _open_the_gate(vault)

    stop = rotate_module.start_auto_rotate(vault, 0.2)
    try:
        assert _wait_for_the_version(vault, 2) >= 2, "the rotator never rotated"
    finally:
        stop()

    meta = read_key_meta(vault.db)
    assert meta is not None
    assert meta.last_rotate_at > 0, "the rotation did not stamp the gate"


def test_the_stop_callable_stops_the_ticker(vault):
    """Nothing rotates once the ticker has been stopped."""
    _open_the_gate(vault)

    stop = rotate_module.start_auto_rotate(vault, 0.2)
    try:
        assert _wait_for_the_version(vault, 2) >= 2, "the rotator never rotated"
    finally:
        stop()

    assert _rotator_threads() == [], "the ticker outlived its stop callable"

    # The gate is open again, so a ticker that were still running would
    # rotate: the version must stay where the stop left it.
    version = vault.keys.cur().version
    _open_the_gate(vault)
    time.sleep(0.3)
    assert vault.keys.cur().version == version, "the ticker rotated after it stopped"


def test_a_period_of_zero_schedules_nothing(vault):
    """The capability exists, and nobody has attached it.

    A period of zero is not a fast rotation: it is no rotation at all, so
    no thread is started and the stop callable has nothing to do.
    """
    before = len(_rotator_threads())

    stop = rotate_module.start_auto_rotate(vault, 0.0)
    stop()

    assert len(_rotator_threads()) == before, "a thread was started for a zero period"
    time.sleep(0.1)
    assert vault.keys.cur().version == 1, "the store rotated with no schedule"


def test_a_negative_period_schedules_nothing(vault):
    """A negative period is no period."""
    before = len(_rotator_threads())

    stop = rotate_module.start_auto_rotate(vault, -1.0)
    stop()

    assert len(_rotator_threads()) == before, (
        "a thread was started for a negative period"
    )
    assert vault.keys.cur().version == 1


def test_a_failing_tick_does_not_stop_the_schedule(vault, monkeypatch):
    """One bad tick must not cost the schedule the rest of its life."""
    _open_the_gate(vault)

    calls: list[int] = []
    real_rotate = rotate_module.rotate_dek

    def flaky(vault_, store=None, *, leases=None, cancel=None):
        calls.append(len(calls))
        if len(calls) == 1:
            raise RuntimeError("the rotation died")
        real_rotate(vault_)

    monkeypatch.setattr(rotate_module, "rotate_dek", flaky)

    stop = rotate_module.start_auto_rotate(vault, 0.2)
    try:
        assert _wait_for_the_version(vault, 2) >= 2, (
            "the schedule stopped after a failed tick"
        )
    finally:
        stop()

    assert len(calls) >= 2, "the ticker did not tick again after the failure"


def test_the_schedule_takes_the_fleet_lock_when_the_store_has_an_authority(
    vault, monkeypatch
):
    """A clustered store's rotation is arbitrated across the fleet.

    The schedule rotates the store it was attached to, so it has to rotate
    it the way that store is rotated: with the authority's lock taken
    first, or two nodes would mint two keys for the same generation and
    leave records under one of them that no other node can open.

    The Go's ``(*Vault).RotateDEK`` takes that lock itself, because the
    lock is part of rotating that store.  Here the rotation is a free
    function, so the store it belongs to has to be handed over — and the
    schedule is the one that has to hand it over.
    """
    from types import SimpleNamespace

    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events, fail=True),
    )
    _fake_generation(monkeypatch)
    vault.authority = SimpleNamespace(store=_FakeAuthority())

    with pytest.raises(VaultError):
        rotate_module._rotate_once(vault, 0.0)

    assert events and events[0][0] == "lock", (
        "the schedule rotated a clustered store without the fleet lock"
    )
    meta = read_key_meta(vault.db)
    assert meta.pending_dek_version == 0, (
        "the rotation claimed the store without the lock"
    )
    assert vault.keys.cur().version == 1, (
        "the rotation swapped the key without the lock"
    )


def test_the_schedule_takes_no_lock_for_a_standalone_store(vault, monkeypatch):
    """A plain file store has no fleet to arbitrate with."""
    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )

    rotate_module._rotate_once(vault, 0.0)

    assert events == [], "a standalone store has no fleet lock to take"
    assert vault.keys.cur().version == 2, "the standalone store did not rotate"


def test_the_schedule_gate_is_the_fleets_not_the_local_rows(vault, monkeypatch):
    """A clustered node's gate is the fleet's timestamp, not its own row.

    The local row is the node's own bookkeeping: a node that read it would
    see "this node has never rotated" on a fleet that rotates every minute,
    and would rotate on every one of its ticks — the fleet's rotation
    period multiplied by the number of nodes. The authority keeps one
    timestamp for the whole fleet, and that is the one the schedule reads.
    """
    from types import SimpleNamespace

    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    _fake_generation(monkeypatch)
    # The fleet rotated a moment ago. This node's own row says it has not
    # rotated for an hour.
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.last_rotation_at",
        lambda kv, ns: datetime.now(timezone.utc),
    )
    _open_the_gate(vault)
    vault.authority = SimpleNamespace(store=_FakeAuthority())

    rotate_module._rotate_once(vault, 60.0)

    assert events == [], (
        "the schedule rotated although the fleet had just rotated: "
        "it read its own row instead of the fleet's timestamp"
    )
    meta = read_key_meta(vault.db)
    assert meta.active_dek_version == 1, "the store rotated although the gate was fresh"


def test_a_clustered_node_follows_the_fleet_even_when_its_own_row_is_fresh(
    vault, monkeypatch
):
    """The other direction: a fresh local row does not close the gate.

    The gate answers "when did the fleet last rotate", and the fleet is the
    thing that rotates. A node whose own row was written a moment ago —
    because it adopted a generation, or because it was initialised then —
    still has to rotate when the fleet's own timestamp says it is due.
    """
    from types import SimpleNamespace

    events: list[tuple] = []
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.acquire_rotation_lock",
        _fake_acquire(events),
    )
    _fake_generation(monkeypatch)
    # The fleet's timestamp is long past, so the fleet is due. The node's
    # own row says it rotated a moment ago.
    _set_the_local_gate(vault, int(time.time()))
    monkeypatch.setattr(
        "security_gateway.vault.etcdstore.advance_generation",
        lambda kv, ns, target: (True, target),
    )
    vault.authority = SimpleNamespace(store=_FakeAuthority())

    rotate_module._rotate_once(vault, 60.0)

    assert events and events[0][0] == "lock", (
        "the schedule skipped a rotation the fleet was due for: "
        "it read its own row instead of the fleet's timestamp"
    )
    meta = read_key_meta(vault.db)
    assert meta.active_dek_version == 2, "the clustered store did not rotate"
