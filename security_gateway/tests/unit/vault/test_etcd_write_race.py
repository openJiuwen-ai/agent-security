"""The etcd write path must survive a delete that races the create.

The write is create-then-update: a record that is not there yet is created,
and one that is there is replaced under a compare-and-swap.  When the record
is created by somebody else in the window between the read and the create,
the create's compare-and-swap fails — and the record may be *gone* again by
the time the write looks, because a delete took it.

The old answer was an error that said nothing useful ("read the record after
a conflict"), when the record was simply not there and the write wanted it
there.  The right answer is another try at the create.
"""

from __future__ import annotations

from security_gateway.vault.etcd import EtcdAuthority
from security_gateway.vault.etcdstore.entry import RecordEntry
from security_gateway.vault.etcdstore.errors import (
    ConflictError as StoreConflictError,
)
from security_gateway.vault.etcdstore.errors import (
    NotFoundError as StoreNotFoundError,
)


def test_a_create_that_loses_to_a_delete_tries_again(tmp_path):
    """A create that conflicts because the record was deleted tries again."""
    from security_gateway.vault import open_db

    class RacingStore:
        """A store whose first create loses to a delete."""

        def __init__(self) -> None:
            self.records: dict[str, RecordEntry] = {}
            self.creates = 0

        def get_record(self, record_id: str) -> RecordEntry:
            try:
                return self.records[record_id]
            except KeyError:
                raise StoreNotFoundError(
                    f"etcdstore: no record under {record_id!r}"
                ) from None

        def create_record(self, record_id: str, entry: RecordEntry) -> RecordEntry:
            self.creates += 1
            if self.creates == 1:
                # Somebody else created it and then deleted it: the
                # compare-and-swap fails and the record is not there.
                raise StoreConflictError(
                    "etcdstore: the record was created by another writer"
                )
            created = RecordEntry(
                data=bytes(entry.data),
                schema_version=int(entry.schema_version),
                dek_version=int(entry.dek_version),
                created_at=entry.created_at,
                updated_at=entry.updated_at,
                mod_revision=1,
            )
            self.records[record_id] = created
            return created

        def update_record_cas(self, record_id: str, entry: RecordEntry) -> RecordEntry:
            raise AssertionError("the write should not have reached the update path")

        def generation(self) -> int:
            return 1

    class UnfencedAuthority(EtcdAuthority):
        """An authority whose generation never moves."""

        def _fenced(self, dek_version: int) -> bool:
            return False

    from security_gateway.vault.store import bootstrap_schema

    database = open_db(str(tmp_path / "vault.db"))
    bootstrap_schema(database)
    store = RacingStore()
    authority = UnfencedAuthority(None, store, "ns")

    authority.write_record(
        database,
        "rec-1",
        b"payload",
        1,
        1,
    )

    assert store.creates == 2, (
        f"the write created the record {store.creates} times, want 2: the first "
        "create lost to a delete and the write gave up instead of trying again"
    )
    assert "rec-1" in store.records
