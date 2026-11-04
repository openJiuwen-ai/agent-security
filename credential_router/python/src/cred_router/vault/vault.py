"""The vault: an open encrypted-field store.

The store holds records that are addressed by an indexed id. Each record
carries N fields described by a schema the host declares in code; a
field is either stored as-is or encrypted under the store's data
encryption key.

Two rules shape everything below.

The first is that the *write barrier* is taken before the key snapshot
is captured and held until the row is written. A write that captured its
snapshot before a rotation's swap but landed after the rotation's check
would leave a row labelled with a generation its ciphertext was not
encrypted under — a record no key could ever open.

The second is that "absent" and "present but unreadable" are different
answers. A record that exists and merely cannot be decrypted is reported
as :class:`~cred_router.vault.errors.UndecryptableError`, never as
:class:`~cred_router.vault.errors.NotFoundError`.

What is here is the store itself: its records, its keys, its writes and
its read path. The parts that are not the store's own behaviour live
beside it — the settings and the shapes the store hands back in
:mod:`.model`, the cluster's authority in :mod:`.authority`, the checks
between what was stored and what was declared in :mod:`.schema_check`,
and the data directory's own check in :mod:`.datadir`.
"""

from __future__ import annotations

import logging
import os
import stat  # noqa: F401
import threading
import time  # noqa: F401
from dataclasses import dataclass, field  # noqa: F401
from typing import Any, Callable

from cred_router.crypto import Mode, decrypt_credential, encrypt_credential
from cred_router.crypto.errors import CryptoError

from .authority import AuthorityMixin
from .codec import ContainerField, encode_container
from .datadir import check_data_dir
from .errors import (
    ClosedError,
    InvalidError,
    InvalidRecordError,
    KeyMismatchError,
    NotFoundError,
    SchemaMismatchError,
    StaleGenerationError,
    UndecryptableError,
)
from .format import format_held_versions
from .keys import (
    KeyManager,
    KeySnapshot,
    init_keys,
    load_snapshot,
    mkdir_all_secure,
    read_key_meta,
)
from .model import (
    DEFAULT_DATA_DIR_PERM,
    DEFAULT_DB_NAME,
    DEFAULT_SECRETS_SUBDIR,
    ROTATION_BATCH_SIZE,
    Config,
    Entry,
    Status,
)
from .record import Record, Value
from .schema import FieldDef, Schema, parse_schema
from .schema_check import _decode_row, is_additive, verify_against_schema
from .store import (
    Database,
    RecordRow,
    SchemaEntry,
    bootstrap_schema,
    count_records,
    count_stragglers,
    delete_record,
    get_record,
    insert_schema_entry,
    list_records,
    open_db,
    put_record,
    read_schema_entries,
    run_with_busy_retry,
)

# The names below are not used by the module. They were importable from
# it before the store was split across several modules, and they are
# kept importable from here so that nothing that reached for them here
# stops working.
from .codec import decode_container  # noqa: F401
from .errors import VaultError  # noqa: F401

_log = logging.getLogger(__name__)

__all__ = [
    "DEFAULT_DATA_DIR_PERM",
    "DEFAULT_DB_NAME",
    "DEFAULT_SECRETS_SUBDIR",
    "ROTATION_BATCH_SIZE",
    "Config",
    "Entry",
    "Status",
    "Vault",
    "check_data_dir",
    "is_additive",
    "set_put_before_write_hook",
]


class _GenerationNotHeld(Exception):
    """The snapshot does not hold the generation the store is on.

    The write path reloads the key metadata and tries again.
    """

# The write seam. It is called inside Put, after the record's values have
# been encrypted and before the row is written, so a test can hold a write
# open at exactly the point where a concurrent key rotation would change
# the key underneath it. It runs on the calling thread, so a test that
# blocks inside it blocks the write.
_put_before_write_hook: Callable[[], None] | None = None


def set_put_before_write_hook(fn: Callable[[], None] | None) -> None:
    """Install the hook Put calls before it writes the row."""
    global _put_before_write_hook
    _put_before_write_hook = fn


class Vault(AuthorityMixin):
    """An open encrypted-field store.

    A Vault is safe for concurrent use.
    """

    def __init__(
        self,
        db: Database,
        keys: KeyManager,
        secrets_dir: str,
        schema: Schema,
        schemas: dict[int, Schema],
        fields: dict[str, FieldDef],
        authority: Any = None,
    ) -> None:
        self.db = db
        self.keys = keys
        self.secrets_dir = secrets_dir

        #: The etcd authority, when the store has one. Its presence is what
        #: makes a write go to etcd rather than to the local database; the
        #: local copy is a mirror that catches up through a watch.
        self.authority = authority

        self._schema = schema
        self._schemas = schemas
        self._fields = fields

        # The write barrier. Readers and ordinary writers take it while
        # they work; a key rotation takes it for writing while it performs
        # the final straggler check and swaps the key.
        #
        # Python has no reader-writer lock in the standard library, so this
        # is an exclusive lock: writes serialise with each other, which
        # costs throughput but keeps the ordering the rotation depends on.
        self.wmu = threading.RLock()

        # Serialises rotations inside this process.
        self.rotate_mu = threading.Lock()

        # Serialises the reloads of the key snapshot. Several readers can
        # find a generation missing at the same time; without this, each of
        # them would unpack the key material again.
        self._reload_lock = threading.Lock()

        self._close_lock = threading.Lock()
        self._closed = False

        # The authority's background loops, and the event that stops them.
        self._mirror_stop: threading.Event | None = None
        self._mirror_thread: threading.Thread | None = None
        self._wrap_thread: threading.Thread | None = None

    # -- construction ---------------------------------------------------

    @classmethod
    def open(cls, cfg: Config, schema: Schema) -> "Vault":
        """Open or initialise a store."""
        schema.validate()
        if not cfg.data_dir:
            raise InvalidError("vault: config: DataDir is required")
        mode = cfg.crypto_mode
        if mode not in (Mode.AES, Mode.SM4):
            mode = Mode.AES
        db_path = cfg.db_path or os.path.join(cfg.data_dir, DEFAULT_DB_NAME)
        secrets_dir = os.path.join(cfg.data_dir, DEFAULT_SECRETS_SUBDIR)

        mkdir_all_secure(cfg.data_dir, DEFAULT_DATA_DIR_PERM)
        mkdir_all_secure(secrets_dir, DEFAULT_DATA_DIR_PERM)
        check_data_dir(cfg.data_dir)

        db = open_db(db_path)
        # The authority is declared outside the try so that the error path
        # can close it: a connection that is opened and then abandoned on
        # the way out is a connection the process keeps until it exits.
        authority = None
        try:
            bootstrap_schema(db)

            # The authority comes up before the key material, because the
            # key material depends on it: a node joining a fleet adopts
            # the fleet's key rather than minting one of its own, and
            # "the fleet's key" is what the authority holds.
            adopt = None
            self_identity = None
            anchor = None
            cluster_store = None
            if cfg.etcd is not None:
                from .cluster import (
                    cluster_anchor_for,
                    load_cluster_identity,
                    obtain_cluster_dek,
                )
                from .etcd import dial_etcd
                from cred_router.credmgr.clusterkey.authority import (
                    KVClusterStore,
                )

                authority = dial_etcd(cfg.etcd)
                if getattr(cfg.etcd, "node_id", ""):
                    self_identity = load_cluster_identity(cfg.etcd)
                    anchor = cluster_anchor_for(cfg.etcd)
                    # The cluster store is the roster, the mint election
                    # and the handover log; the record store is a
                    # different half of the same namespace.
                    cluster_store = KVClusterStore(
                        authority.store.kv, authority.ns)
                    adopt = obtain_cluster_dek(
                        cfg.etcd, cluster_store, self_identity, anchor)

            keys, _km = init_keys(
                db, secrets_dir, mode, adopt, shared_key_meta=authority is None
            )
            vault = cls(db, keys, secrets_dir, schema, {}, {}, authority)
            try:
                vault._load_and_validate_schema(schema)
            except BaseException:
                vault.close()
                raise

            # A store that came up with a previous key still in hand was
            # recovering from an interrupted rotation. The records that were
            # not re-encrypted yet are still under the old key; finish that
            # work now, before any caller sees the store.
            #
            # An etcd-backed store is the exception: there the rewrite
            # belongs to the node holding the rotation lock.
            if authority is None and vault.keys.prev() is not None:
                vault.converge_stragglers()

            if authority is not None:
                vault.start_authority(
                    cfg.etcd, self_identity, anchor, cluster_store)
            return vault
        except BaseException:
            if authority is not None:
                try:
                    authority.close()
                except Exception as exc:  # noqa: BLE001 - shutting down anyway
                    _log.warning(
                        "could not close the etcd authority", extra={"error": exc})
            db.close()
            raise

    # -- state ----------------------------------------------------------

    @property
    def schema(self) -> Schema:
        """The schema the store writes with."""
        return self._schema

    @property
    def schemas(self) -> dict[int, Schema]:
        """Every schema version the store knows, keyed by version."""
        return dict(self._schemas)

    def schema_for_version(self, version: int) -> Schema | None:
        """The schema a record with that version was written with."""
        return self._schemas.get(version)

    # -- reading --------------------------------------------------------

    def get(self, record_id: str) -> Record:
        """Load a record by its id."""
        if not record_id:
            raise InvalidRecordError("id is empty")
        row = get_record(self.db, record_id)
        if row is None:
            raise NotFoundError(f'"{record_id}"')
        sch = self.schema_for_version(row.schema_version)
        if sch is None:
            raise SchemaMismatchError(
                f'record "{record_id}" was written with schema v{row.schema_version}, which this store does not know'
            )
        return self._decode_record(row, sch)

    def list(self, prefix: str) -> list[Entry]:
        """The records whose id begins with prefix.

        An empty prefix lists every record. The entries carry the
        records' plaintext fields; the encrypted ones are omitted, so a
        listing never decrypts anything.
        """
        rows = list_records(self.db, prefix)
        out: list[Entry] = []
        for row in rows:
            sch = self.schema_for_version(row.schema_version)
            if sch is None:
                raise SchemaMismatchError(
                    f'record "{row.id}" was written with schema v{row.schema_version}, which this store does not know'
                )
            out.append(self._plain_entry(row, sch))
        return out

    # -- writing --------------------------------------------------------

    def put(self, rec: Record) -> None:
        """Write a record.

        The record's fields must all be declared by the current schema,
        and each value must have the type the schema declares. Whether a
        field is stored encrypted is decided by the schema, not by the
        caller.
        """
        if rec is None:
            raise InvalidRecordError("record is nil")
        if not rec.id:
            raise InvalidRecordError("id is empty")

        # A field the schema does not declare would be silently dropped,
        # which is worse than refusing it.
        for name in rec.fields:
            if name not in self._fields:
                raise InvalidRecordError(
                    f'field "{name}" is not declared by the schema'
                )

        if self.authority is not None:
            self._put_through_authority(rec)
            return
        self._put_local(rec)

    def _put_through_authority(self, rec: Record) -> None:
        """Write a record to the authority.

        The generation is the node's own current one. The authority
        fences writes by generation, so a node whose generation the
        authority has left behind is refused there rather than here.
        """
        # The write barrier is taken before the key snapshot is captured,
        # and held until the row is written. That ordering is what keeps a
        # concurrent rotation from landing between the two: the rotation's
        # final straggler check waits for this writer, so a row this call
        # writes is always counted.
        with self.wmu:
            # The key snapshot is captured once and used for both the
            # encryption and the version the row is labelled with. Reading
            # it twice would let a rotation slip in between.
            cur = self.keys.cur()
            if cur is None:
                raise ClosedError("the store has no key", whole=True)

            encoded = self._encode_record(rec, cur)

            if _put_before_write_hook is not None:
                _put_before_write_hook()

            # With an authority the write goes to it, and only to it: the
            # local copy is a mirror that catches up through a watch, and
            # writing to both would leave the two disagreeing for as long
            # as the watch takes.
            self.authority.write_record(
                self.db,
                rec.id,
                encoded,
                self._schema.version,
                cur.version,
            )

    def _put_local(self, rec: Record) -> None:
        """Write a record to the local database.

        The transaction holds the write lock from the moment the
        generation is read to the moment the row is written, so no other
        writer can change the generation in between.
        """
        for _attempt in range(2):
            try:
                run_with_busy_retry(lambda: self._put_local_once(rec))
                return
            except _GenerationNotHeld:
                # The snapshot does not hold the generation the store is
                # on. Reload and try once more.
                km = read_key_meta(self.db)
                target = 0
                if km is not None:
                    target = km.active_dek_version
                    if km.pending_dek_version != 0:
                        target = km.pending_dek_version
                self._reload_keys(target)
                continue
        raise StaleGenerationError(
            "the store is on a generation this process does not hold"
        )

    def _put_local_once(self, rec: Record) -> None:
        """Write a record in one write transaction."""
        with self.wmu:
            with self.db.transaction(immediate=True):
                km = read_key_meta(self.db)
                if km is None:
                    raise KeyMismatchError("the store has no key metadata")

                # The generation to write under. While a rotation is in
                # flight the pending generation is the authoritative one —
                # that is the local equivalent of the authority's generation
                # moving ahead of the ciphertext.
                target = km.active_dek_version
                if km.pending_dek_version != 0:
                    target = km.pending_dek_version

                snap = self.keys.by_version(target)
                if snap is None:
                    raise _GenerationNotHeld()

                # The encryption happens inside the transaction, so that a
                # retry does not encrypt twice and the ciphertext and the
                # generation on the row always agree.
                encoded = self._encode_record(rec, snap)

                if _put_before_write_hook is not None:
                    _put_before_write_hook()

                put_record(
                    self.db,
                    RecordRow(
                        id=rec.id,
                        schema_version=self._schema.version,
                        data=encoded,
                        dek_version=target,
                    ),
                )

    def _encode_record(self, rec: Record, snap: KeySnapshot) -> bytes:
        """Seal a record's fields and encode the container."""
        container: list[ContainerField] = []
        for definition in self._schema.fields:
            if definition.name not in rec.fields:
                continue
            val = rec.fields[definition.name]
            if val.type != definition.type:
                raise InvalidRecordError(
                    f'field "{definition.name}" has type {val.type} but the schema says {definition.type}'
                )
            val.validate()
            data = val.data
            if definition.encrypted:
                data = self._encrypt_with(snap, data)
            container.append(
                ContainerField(
                    name=definition.name,
                    type=definition.type,
                    encrypted=definition.encrypted,
                    data=data,
                )
            )
        return encode_container(container)

    def delete(self, record_id: str) -> None:
        """Remove a record.

        It raises :class:`~cred_router.vault.errors.NotFoundError` when
        the id is unknown.
        """
        if not record_id:
            raise InvalidRecordError("id is empty")
        with self.wmu:
            # With an authority the delete goes to it, and only to it: the
            # local copy is a mirror, and the watch brings the deletion
            # here.
            if self.authority is not None:
                self.authority.delete_record(self.db, record_id)
                return
            if not delete_record(self.db, record_id):
                raise NotFoundError(f'"{record_id}"')

    # -- housekeeping ---------------------------------------------------

    def status(self) -> Status:
        """The store's current state."""
        digest = self._schema.hash()
        status = Status(
            schema_version=self._schema.version,
            schema_hash=digest.hex(),
            record_count=count_records(self.db),
        )
        cur = self.keys.cur()
        if cur is None:
            return status
        status.crypto_mode = str(cur.mode)
        # The generation the store is on. While a rotation is in flight that
        # is the pending one: the new records are stamped with it, so it is
        # the generation in use, even though the committed active generation
        # has not moved yet.
        target = cur.version
        if self.authority is None:
            km = read_key_meta(self.db)
            if km is not None:
                if km.pending_dek_version != 0:
                    target = km.pending_dek_version
                elif km.active_dek_version > target:
                    # Another process committed a rotation since this one
                    # last looked. The store is on that generation and this
                    # process's snapshot is behind, so the status must not
                    # report a generation the store has already left behind.
                    target = km.active_dek_version
        # The stragglers are measured against the same generation: while a
        # rotation is in flight the count is what says whether the rotation
        # can commit.
        status.dek_version = target
        status.straggler_count = count_stragglers(self.db, target)
        return status

    def close(self) -> None:
        """Release the store's resources and zero its key material."""
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        try:
            self._close_extra()
        finally:
            self.keys.zero_all()
            self.db.close()

    def _close_extra(self) -> None:
        """The hook an etcd-backed store uses to release its authority."""
        # The background loops come down before the authority does: they
        # read and write through it, and a loop still running against a
        # closed connection is a loop writing to a handle nobody owns.
        stop = self._mirror_stop
        self._mirror_stop = None
        if stop is not None:
            stop.set()
        thread = self._mirror_thread
        self._mirror_thread = None
        if thread is not None:
            thread.join(timeout=5.0)

        authority = self.authority
        if authority is None:
            return
        self.authority = None
        close = getattr(authority, "close", None)
        if callable(close):
            close()

    def _local_dek_version(self) -> int:
        """The generation this node can open, read live."""
        cur = self.keys.cur()
        if cur is None:
            return 0
        return int(cur.version)

    # -- internals ------------------------------------------------------

    def _encrypt_with(self, snap: KeySnapshot, plaintext: bytes) -> bytes:
        """Seal a value under a given key snapshot."""
        if snap is None:
            raise ClosedError("the store has no key", whole=True)
        return encrypt_credential(snap.mode, snap.dek_bytes(), plaintext)

    def _decrypt_for(self, version: int, blob: bytes) -> bytes:
        """Open a ciphertext with the key that holds the generation the record was written with.
        """
        snap = self.keys.by_version(version)
        if snap is not None:
            return self._decrypt_with(snap, version, blob)

        # The snapshot does not hold that generation. Another process may
        # have rotated the store since this one last looked.
        if self.authority is None:
            self._reload_keys(version)
            snap = self.keys.by_version(version)
            if snap is not None:
                return self._decrypt_with(snap, version, blob)

        # The generation is not one this store holds. As a last resort try
        # every key the snapshot does hold: a record that opens is a record
        # the caller can use, and the version a row carries can disagree
        # with the key that opens it after a store was copied around.
        for candidate in (self.keys.cur(), self.keys.prev(), self.keys.pend()):
            if candidate is None:
                continue
            try:
                return decrypt_credential(
                    candidate.mode, candidate.dek_bytes(), blob
                )
            except CryptoError:
                pass

        raise StaleGenerationError(
            f"the record is under generation {version}, and this store holds "
            f"{format_held_versions(self.keys.held_versions())}"
        )

    def _decrypt_with(self, snap: KeySnapshot, version: int, blob: bytes) -> bytes:
        """Open a ciphertext with one particular key."""
        try:
            return decrypt_credential(snap.mode, snap.dek_bytes(), blob)
        except CryptoError as exc:
            raise UndecryptableError(
                f"the ciphertext does not open with the key for generation {version}: {exc}",
                whole=True,
            ) from exc

    def _reload_keys(self, version: int) -> None:
        """Replace the key snapshot with one read from the store.

        The reload lock is what keeps a burst of readers that all miss
        the same generation from unpacking the key material once each.
        """
        with self._reload_lock:
            # Another reader may have reloaded while this one waited for
            # the lock. Reloading again would be the same work twice.
            if self.keys.by_version(version) is not None:
                return
            mgr, _km = load_snapshot(self.db, self.secrets_dir)
            self.keys.replace(mgr.cur(), mgr.prev(), mgr.pend())

    def reload_snapshot(self) -> None:
        """Replace the key snapshot with one read from the store, unconditionally."""
        with self._reload_lock:
            mgr, _km = load_snapshot(self.db, self.secrets_dir)
            self.keys.replace(mgr.cur(), mgr.prev(), mgr.pend())

    def _plain_entry(self, row: RecordRow, sch: Schema) -> Entry:
        """Decode a stored row into an entry that carries only the fields the schema does not mark encrypted.
        """
        fields = _decode_row(row)
        defs = sch.field_lookup()
        verify_against_schema(row.id, sch, defs, fields)
        entry = Entry(id=row.id, fields={})
        for f in fields:
            if defs[f.name].encrypted:
                continue
            entry.fields[f.name] = Value(type=f.type, data=f.data)
        return entry

    def _decode_record(self, row: RecordRow, sch: Schema) -> Record:
        """Turn a stored row back into a record."""
        fields = _decode_row(row)
        defs = sch.field_lookup()
        verify_against_schema(row.id, sch, defs, fields)

        rec = Record(id=row.id, fields={})
        for f in fields:
            definition = defs[f.name]
            data = f.data
            if definition.encrypted:
                try:
                    data = self._decrypt_for(row.dek_version, data)
                except StaleGenerationError as exc:
                    raise StaleGenerationError(
                        f'record "{row.id}" field "{f.name}": {exc}'
                    ) from exc
                except UndecryptableError as exc:
                    raise UndecryptableError(
                        f'record "{row.id}" field "{f.name}": {exc}'
                    ) from exc
            rec.fields[f.name] = Value(type=f.type, data=data)
        return rec

    def _load_and_validate_schema(self, declared: Schema) -> None:
        """Reconcile the declared schema with the store's."""
        entries = read_schema_entries(self.db)
        declared_hash = declared.hash()

        registry: dict[int, Schema] = {}
        for e in entries:
            s = parse_schema(e.definition)
            registry[e.version] = s

        if not entries:
            canonical = declared.canonical_json()
            insert_schema_entry(
                self.db,
                SchemaEntry(
                    version=declared.version,
                    hash=declared_hash,
                    definition=canonical.decode("utf-8"),
                ),
            )
            registry[declared.version] = declared
            self._schemas = registry
            self._schema = declared
            self._fields = declared.field_lookup()
            return

        latest = entries[-1]
        if latest.version > declared.version:
            raise SchemaMismatchError(
                f"the store was initialised with schema v{latest.version} but the declared schema "
                f"is v{declared.version}; the data is newer than the code"
            )

        if latest.version == declared.version:
            if latest.hash != declared_hash:
                raise SchemaMismatchError(
                    f"the store's schema v{latest.version} does not match the declared schema "
                    f"v{declared.version}; the schema changed without its version being bumped"
                )
        else:
            # The declared schema is newer. That is only safe when the change
            # is additive: every field the store knows about must still exist
            # with the same type and the same encryption state. A changed
            # type, a changed encryption state, a rename or a removal would
            # leave existing records unreadable, so those are refused.
            stored = registry.get(latest.version)
            if stored is None:
                raise SchemaMismatchError(
                    f"the store's schema v{latest.version} is missing from its registry"
                )
            if not is_additive(stored, declared):
                raise SchemaMismatchError(
                    f"schema v{stored.version} -> v{declared.version} changes an existing field; that "
                    f"needs an explicit migration"
                )
            canonical = declared.canonical_json()
            insert_schema_entry(
                self.db,
                SchemaEntry(
                    version=declared.version,
                    hash=declared_hash,
                    definition=canonical.decode("utf-8"),
                ),
            )
            registry[declared.version] = declared

        self._schemas = registry
        self._schema = declared
        self._fields = declared.field_lookup()
