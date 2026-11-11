"""The vault's local mirror of the authority's records.

The Go counterpart is ``pkg/vault/mirror.go`` and the mirror helpers it
holds. The Go has no unit test file for the mirror itself — the coverage
lives in the credential manager's sibling applier
(``tests/unit/credmgr/sqliteapplier/applier_test.go``) and in the vault's
etcd integration test (``tests/integration/vault_etcd_test.go``). The
cases here are the ones both of those pin, restated against the vault's
own tables.
"""

from __future__ import annotations

import pytest
from security_gateway.vault import open_db
from security_gateway.vault.errors import InvalidError
from security_gateway.vault.etcdstore.entry import RecordEntry
from security_gateway.vault.mirror import (
    PURGE_ALL_REVISIONS,
    MirrorApplier,
    MirrorRevisionStore,
    apply_mirrored_record,
    delete_mirrored_record,
    list_mirrored_record_ids,
    read_sync_state,
    write_sync_state,
)
from security_gateway.vault.store import Database, bootstrap_schema, get_record
from security_gateway.vault.sync import Applier, Listed, RevisionStore


@pytest.fixture
def db(tmp_path) -> Database:
    """An open vault database with the vault's tables."""
    database = open_db(str(tmp_path / "vault.db"))
    bootstrap_schema(database)
    try:
        yield database
    finally:
        database.close()


def entry(
    record_id: str,
    data: bytes = b"cipher",
    schema_version: int = 1,
    dek_version: int = 1,
    mod_revision: int = 100,
) -> RecordEntry:
    """An authority record as the mirror receives it."""
    return RecordEntry(
        data=data,
        schema_version=schema_version,
        dek_version=dek_version,
        mod_revision=mod_revision,
    )


def listed(record_id: str, item: RecordEntry) -> Listed[RecordEntry]:
    """One item of a full listing."""
    return Listed(key=record_id, value=item)


def mirrored_revision(db: Database, record_id: str) -> int:
    """The authority revision a row was mirrored from.

    It is read straight out of the column rather than through
    ``get_record``: the store's row projection does not select
    ``source_revision``, so ``RecordRow.source_revision`` reads zero.
    """
    row = db.query_one(
        "SELECT source_revision FROM vault_record WHERE id = ?", (record_id,)
    )
    assert row is not None, f"the mirror holds no record {record_id!r}"
    return int(row[0])


def test_applying_a_record_writes_the_row(db):
    """A record the authority holds lands in the local mirror."""
    apply_mirrored_record(db, "cred-1", b"cipher-1", 1, 1, 42)

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"cipher-1"
    assert row.schema_version == 1
    assert row.dek_version == 1
    assert mirrored_revision(db, "cred-1") == 42
    assert row.row_version == 1


def test_applying_a_record_over_an_existing_one_replaces_it(db):
    """A later revision replaces the row and bumps its version."""
    apply_mirrored_record(db, "cred-1", b"old", 1, 1, 10)
    apply_mirrored_record(db, "cred-1", b"new", 2, 3, 20)

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"new"
    assert row.schema_version == 2
    assert row.dek_version == 3
    assert mirrored_revision(db, "cred-1") == 20
    assert row.row_version == 2


def test_applying_a_record_at_the_same_revision_changes_nothing(db):
    """A re-delivered watch event must not bump the row's version.

    The row's own optimistic guard would otherwise fire against the
    mirror's own write.
    """
    apply_mirrored_record(db, "cred-1", b"cipher-1", 1, 1, 42)
    apply_mirrored_record(db, "cred-1", b"cipher-1-again", 1, 1, 42)

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"cipher-1"
    assert row.row_version == 1


def test_applying_an_older_revision_leaves_the_row_alone(db):
    """A stale revision is stale whether or not the row exists."""
    apply_mirrored_record(db, "cred-1", b"new", 1, 1, 42)
    apply_mirrored_record(db, "cred-1", b"old", 1, 1, 41)

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"new"
    assert mirrored_revision(db, "cred-1") == 42


def test_deleting_a_record_removes_it(db):
    apply_mirrored_record(db, "cred-1", b"cipher-1", 1, 1, 42)
    delete_mirrored_record(db, "cred-1", 42)
    assert get_record(db, "cred-1") is None


def test_deleting_an_absent_record_is_not_an_error(db):
    """The caller may be replaying an event the mirror already applied."""
    delete_mirrored_record(db, "never-there", 42)
    assert get_record(db, "never-there") is None


def test_a_late_delete_does_not_remove_a_record_written_again(db):
    """The delete only applies to a row mirrored at or before its revision."""
    apply_mirrored_record(db, "cred-1", b"old", 1, 1, 10)
    apply_mirrored_record(db, "cred-1", b"new", 1, 1, 20)

    # The deletion happened at revision 10; the row was written again at 20.
    delete_mirrored_record(db, "cred-1", 10)
    assert get_record(db, "cred-1") is not None

    # A deletion at the row's own revision does remove it.
    delete_mirrored_record(db, "cred-1", 20)
    assert get_record(db, "cred-1") is None


def test_the_mirror_lists_the_ids_it_holds(db):
    apply_mirrored_record(db, "cred-1", b"a", 1, 1, 1)
    apply_mirrored_record(db, "cred-2", b"b", 1, 1, 1)
    assert list_mirrored_record_ids(db) == {"cred-1", "cred-2"}


def test_the_applied_revision_round_trips(db):
    assert read_sync_state(db) == 0
    write_sync_state(db, 42)
    assert read_sync_state(db) == 42


def test_the_applied_revision_only_moves_forward(db):
    """A watch that re-delivers an older event must not drag it back."""
    write_sync_state(db, 42)
    write_sync_state(db, 7)
    assert read_sync_state(db) == 42
    write_sync_state(db, 43)
    assert read_sync_state(db) == 43


def test_the_revision_store_round_trips(db):
    store = MirrorRevisionStore(db)
    assert store.load_applied_rev() == 0
    store.save_applied_rev(42)
    assert store.load_applied_rev() == 42


def test_the_revision_store_satisfies_the_protocol(db):
    assert isinstance(MirrorRevisionStore(db), RevisionStore)


def test_the_applier_satisfies_the_protocol(db):
    assert isinstance(MirrorApplier(db, lambda: 1), Applier)


def test_an_upsert_materialises_the_record(db):
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-1", entry("cred-1", b"cipher-1", mod_revision=42))

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"cipher-1"
    assert mirrored_revision(db, "cred-1") == 42


def test_an_upsert_of_nothing_is_an_error(db):
    applier = MirrorApplier(db, lambda: 1)
    with pytest.raises(InvalidError):
        applier.apply_upsert("cred-1", None)


def test_a_delete_removes_the_row_and_is_idempotent(db):
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-1", entry("cred-1", mod_revision=42))

    applier.apply_delete("cred-1", 42)
    assert get_record(db, "cred-1") is None

    # A replayed delete succeeds: the row is already gone.
    applier.apply_delete("cred-1", 42)
    assert get_record(db, "cred-1") is None


def test_a_reconcile_makes_the_mirror_match_the_authority(db):
    """A record the authority no longer holds must be removed locally.

    A record deleted in etcd while this node was disconnected would
    otherwise survive locally forever, keeping a revoked record alive.
    """
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-stale", entry("cred-stale", mod_revision=10))

    applier.reconcile([listed("cred-1", entry("cred-1", b"cipher-1", mod_revision=42))])

    assert get_record(db, "cred-stale") is None
    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"cipher-1"


def test_a_reconcile_with_an_empty_listing_empties_the_mirror(db):
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-1", entry("cred-1", mod_revision=42))

    applier.reconcile([])

    assert list_mirrored_record_ids(db) == set()


def test_a_reconcile_skips_an_item_without_a_value(db):
    """A listing entry with no value carries nothing to materialise."""
    applier = MirrorApplier(db, lambda: 1)
    applier.reconcile([Listed(key="cred-1", value=None)])
    assert list_mirrored_record_ids(db) == set()


def test_a_record_under_a_newer_key_is_withheld(db):
    """A record this node cannot open is not written.

    The node holds version 1 of the data-encryption key; the authority
    holds the record under version 2. Writing it would leave a row the
    node cannot decrypt — a row it cannot serve — so the record is
    withheld instead.
    """
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-1", entry("cred-1", dek_version=2, mod_revision=42))

    assert get_record(db, "cred-1") is None
    assert list_mirrored_record_ids(db) == set()


def test_a_record_under_the_local_key_version_is_applied(db):
    """The boundary is inclusive: the local version is openable."""
    applier = MirrorApplier(db, lambda: 2)
    applier.apply_upsert("cred-1", entry("cred-1", dek_version=2, mod_revision=42))

    assert get_record(db, "cred-1") is not None


def test_a_record_under_the_local_key_version_is_withheld_when_newer(db):
    """One version above the local one is already out of reach."""
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert("cred-1", entry("cred-1", dek_version=2, mod_revision=42))

    assert get_record(db, "cred-1") is None


def test_a_reconcile_withholds_a_newer_key_but_spares_the_older_row(db):
    """The withheld record still counts as present.

    Deleting the older local row would turn a benign "this node is
    behind the rotation" into an outage for a record the node can still
    open.
    """
    applier = MirrorApplier(db, lambda: 1)
    applier.apply_upsert(
        "cred-1", entry("cred-1", b"v1", dek_version=1, mod_revision=10)
    )

    applier.reconcile(
        [listed("cred-1", entry("cred-1", b"v2", dek_version=2, mod_revision=42))]
    )

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"v1"
    assert row.dek_version == 1


def test_a_reconcile_catches_up_once_the_node_adopts_the_newer_key(db):
    """The recovery half: the same listing applies cleanly afterwards."""
    local = [1]
    applier = MirrorApplier(db, lambda: local[0])

    applier.reconcile(
        [listed("cred-1", entry("cred-1", b"v2", dek_version=2, mod_revision=42))]
    )
    assert get_record(db, "cred-1") is None

    local[0] = 2
    applier.reconcile(
        [listed("cred-1", entry("cred-1", b"v2", dek_version=2, mod_revision=42))]
    )

    row = get_record(db, "cred-1")
    assert row is not None
    assert row.data == b"v2"
    assert row.dek_version == 2


def test_the_purge_sentinel_covers_every_revision(db):
    """The purge must remove a row whatever revision it was mirrored from."""
    apply_mirrored_record(db, "cred-1", b"cipher-1", 1, 1, 42)
    delete_mirrored_record(db, "cred-1", PURGE_ALL_REVISIONS)
    assert get_record(db, "cred-1") is None
