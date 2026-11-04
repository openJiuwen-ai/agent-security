"""The vault's local copy of what the authority holds.

In single-node mode the ``vault_record`` table is the store. In etcd
mode it is a mirror: etcd is the authority, the table is what the
store reads from, and a watch keeps the two in step. Each mirrored
row carries the authority revision it came from, so a re-delivered
watch event changes nothing. The gap handling and the reconnect
belong to ``etcdsync``.
"""

from __future__ import annotations

import time
import threading
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Callable, Sequence

from .errors import InvalidError
from .store import MIRROR_SYNC_STATE_ID, Database, ensure_mirror_columns

if TYPE_CHECKING:
    # The etcd side of the mirror needs two names from the credential
    # manager, and both are needed for annotations only, so they are
    # imported for the type checker rather than at run time: importing
    # the credential manager here would close a cycle.
    from cred_router.credmgr.etcdstore.entry import RecordEntry
    from cred_router.credmgr.etcdsync.etcdsync import Listed, Listing
    from cred_router.credmgr.etcdstore.watch import Watcher

__all__ = [
    "PURGE_ALL_REVISIONS",
    "MirrorApplier",
    "MirrorRevisionStore",
    "RecordSource",
    "serve_mirror",
    "apply_mirrored_record",
    "delete_mirrored_record",
    "ensure_mirror_columns",
    "list_mirrored_record_ids",
    "read_sync_state",
    "write_sync_state",
]

#: The revision that stands for "any revision" when the mirror purges a row.
#:
#: The purge is a delete of a row the authority no longer holds, so the
#: revision guard the ordinary delete path uses has to let it through. The
#: Go original passes ``^int64(0)`` there, which is ``-1`` and not the
#: largest revision, so its purge matched nothing and the revoked records
#: survived locally forever.
PURGE_ALL_REVISIONS = (1 << 63) - 1


def apply_mirrored_record(
    db: Database,
    record_id: str,
    data: bytes,
    schema_version: int,
    dek_version: int,
    source_revision: int,
) -> None:
    """Write a record the authority holds into the local mirror."""
    now = int(time.time())
    db.execute(
        """
        INSERT INTO vault_record (id, schema_version, data, dek_version,
                                  row_version, source_revision, created_at,
                                  updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            schema_version  = excluded.schema_version,
            data            = excluded.data,
            dek_version     = excluded.dek_version,
            source_revision = excluded.source_revision,
            row_version     = vault_record.row_version + 1,
            updated_at      = excluded.updated_at
        WHERE vault_record.source_revision < excluded.source_revision""",
        (
            record_id,
            int(schema_version),
            data,
            int(dek_version),
            int(source_revision),
            now,
            now,
        ),
    )


def delete_mirrored_record(db: Database, record_id: str, source_revision: int) -> None:
    """Remove a record the authority has deleted."""
    db.execute(
        "DELETE FROM vault_record WHERE id = ? AND source_revision <= ?",
        (record_id, int(source_revision)),
    )


def list_mirrored_record_ids(db: Database) -> set[str]:
    """The ids the local mirror holds."""
    return {str(row[0]) for row in db.query_all("SELECT id FROM vault_record")}


def read_sync_state(db: Database) -> int:
    """The last authority revision the mirror applied.

    A revision of zero means "never synced": the caller must then do a
    full listing, because watching from revision zero would replay the
    entire etcd history.
    """
    row = db.query_one(
        "SELECT last_applied_rev FROM vault_sync_state WHERE id = ?",
        (MIRROR_SYNC_STATE_ID,),
    )
    if row is None:
        return 0
    return int(row[0])


def write_sync_state(db: Database, rev: int) -> None:
    """Record the last authority revision the mirror applied.

    The revision is only ever moved forward; a watch that re-delivers an
    older event must not drag the position back.
    """
    db.execute(
        """
        INSERT INTO vault_sync_state (id, last_applied_rev, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            last_applied_rev = MAX(vault_sync_state.last_applied_rev, excluded.last_applied_rev),
            updated_at      = excluded.updated_at""",
        (MIRROR_SYNC_STATE_ID, int(rev), int(time.time())),
    )


class MirrorApplier:
    """Materialises the authority's records into the local mirror.

    ``local_dek_version`` reports which data-encryption key version this
    node holds. A record written under a *newer* version than that is
    *withheld*: it is not written, but it still counts as present, so
    the reconciliation's purge spares the older local row that is still
    good.
    """

    def __init__(
        self,
        db: Database,
        local_dek_version: Callable[[], int],
    ) -> None:
        self._db = db
        self._local_dek_version = local_dek_version

    def reconcile(self, listed: Sequence[Listed[RecordEntry]]) -> None:
        """Make the local mirror match the authority's contents.

        It is a set operation, not a series of upserts: a record the
        authority no longer holds must be removed locally, or a revoked
        record survives forever.
        """
        present: set[str] = set()
        for item in listed:
            if item.value is None:
                continue
            present.add(item.key)
            if not self._can_decrypt(item.value.dek_version):
                # Withheld: the key still counts as present, so the purge
                # below spares the older local row this node can still open.
                continue
            apply_mirrored_record(
                self._db,
                item.key,
                item.value.data,
                item.value.schema_version,
                item.value.dek_version,
                item.value.mod_revision,
            )

        local = list_mirrored_record_ids(self._db)
        for record_id in local - present:
            delete_mirrored_record(self._db, record_id, PURGE_ALL_REVISIONS)

    def apply_upsert(self, key: str, item: RecordEntry) -> None:
        """Materialise one record."""
        if item is None:
            raise InvalidError("vault: nil authority record")
        if not self._can_decrypt(item.dek_version):
            return
        apply_mirrored_record(
            self._db,
            key,
            item.data,
            item.schema_version,
            item.dek_version,
            item.mod_revision,
        )

    def apply_delete(self, key: str, mod_revision: int) -> None:
        """Remove the local materialisation of a record."""
        delete_mirrored_record(self._db, key, mod_revision)

    def _can_decrypt(self, dek_version: int) -> bool:
        """Whether this node can open a record written under that key."""
        return int(dek_version) <= int(self._local_dek_version())


class MirrorRevisionStore:
    """Persists how far the mirror has got.

    A restart resumes from a known revision instead of re-listing the
    whole namespace.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def load_applied_rev(self) -> int:
        """The last revision fully applied, or 0 when nothing has."""
        return read_sync_state(self._db)

    def save_applied_rev(self, rev: int) -> None:
        """Record ``rev`` as fully applied."""
        write_sync_state(self._db, rev)


# -- the mirror's own source ------------------------------------------------


class RecordSource:
    """The authority's record subtree, as a sync source.

    The watch capability is separate from the store: a store built
    without one can still list, and asking it for a watch is a wiring
    bug rather than a runtime condition.
    """

    def __init__(self, store: Any, watch_source: Any | None = None) -> None:
        self._store = store
        self._watch_source = watch_source

    def namespace(self) -> str:
        """The namespace this source reads."""
        return str(self._store.ns)

    def list_entries(self, limit: int = 0) -> "Listing[RecordEntry]":
        """Every record in the namespace, plus the snapshot revision."""
        from cred_router.credmgr.etcdsync.etcdsync import Listed, Listing

        listed, revision = self._store.list_records(limit)
        return Listing(
            items=tuple(
                Listed(key=item.record_id, value=item.entry)
                for item in listed
            ),
            revision=revision,
        )

    def watch(self, rev: int) -> "Watcher":
        """Stream changes after ``rev``.

        Raises :class:`~cred_router.credmgr.etcdstore.watch.ErrNoWatch`
        when the source was built without a watch capability.
        """
        from cred_router.credmgr.etcdstore.watch import ErrNoWatch

        if self._watch_source is None:
            raise ErrNoWatch()
        return self._watch_source.watch_records(self.namespace(), rev)

    def key_of(self, key: str) -> str:
        """Turn a watch event's key back into the record's id."""
        from cred_router.credmgr.etcdstore.keys import record_id_from_key

        return record_id_from_key(self.namespace(), key)

    @staticmethod
    def decode(value: bytes, mod_revision: int) -> "RecordEntry":
        """Parse a value the authority wrote."""
        from cred_router.credmgr.etcdstore.entry import unmarshal_record

        entry = unmarshal_record(value)
        if entry.mod_revision:
            return entry
        return replace(entry, mod_revision=int(mod_revision))


# -- the mirror's own loop -------------------------------------------------


def serve_mirror(
    stop: threading.Event,
    store: Any,
    db: Database,
    local_dek_version: Callable[[], int],
    watch_source: Any | None = None,
    cfg: Any = None,
) -> None:
    """Keep the local database in step with the authority."""
    from cred_router.credmgr.etcdsync import Config as SyncConfig
    from cred_router.credmgr.etcdsync import Syncer

    source = RecordSource(store, watch_source=watch_source)
    applier = MirrorApplier(db, local_dek_version)
    revisions = MirrorRevisionStore(db)
    syncer = Syncer(source, applier, revisions, cfg or SyncConfig())
    syncer.run(stop)
