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
as :class:`~security_gateway.vault.errors.UndecryptableError`, never as
:class:`~security_gateway.vault.errors.NotFoundError`.

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
import threading
from contextlib import nullcontext
import time
from collections.abc import Mapping
from typing import Any, Callable

from security_gateway.crypto import Mode, decrypt_credential, encrypt_credential
from security_gateway.crypto.errors import CryptoError

from .authority import AuthorityMixin
from .cache import RecordCache
from .codec import ContainerField, encode_container
from .datadir import check_data_dir
from .errors import (
    ClosedError,
    ConflictError,
    InvalidError,
    InvalidRecordError,
    KeyMismatchError,
    NotFoundError,
    SchemaMismatchError,
    StaleGenerationError,
    StoreNotReadyError,
    UndecryptableError,
)
from .format import format_held_versions
from .mode import DataDirGuard, initialization_lock
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
    delete_record_cas,
    get_record,
    get_records,
    insert_schema_entry,
    list_records,
    open_db,
    put_record,
    put_record_cas,
    read_schema_entries,
    run_with_busy_retry,
)


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


class _RowConflict(Exception):
    """The row moved between the expected check and the conditional write."""


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


_OPEN_REGISTRY_LOCK = threading.Lock()
_OPEN_BY_DB: dict[str, str] = {}
_OPEN_BY_DIR: dict[str, str] = {}
_OPEN_BY_NAMESPACE: dict[tuple[tuple[str, ...], str], str] = {}


def _namespace_registry_key(cfg: Config) -> tuple[tuple[str, ...], str] | None:
    etcd = cfg.etcd
    if etcd is None:
        return None
    endpoints = tuple(sorted(str(endpoint) for endpoint in (getattr(etcd, "endpoints", ()) or ())))
    namespace = str(getattr(etcd, "namespace", "") or "default")
    return (endpoints, namespace)


def _reserve_registry(db_path: str, data_dir: str, cfg: Config) -> tuple[str, str, tuple[tuple[str, ...], str] | None]:
    db_key = os.path.realpath(db_path)
    dir_key = os.path.realpath(data_dir)
    namespace_key = _namespace_registry_key(cfg)
    with _OPEN_REGISTRY_LOCK:
        for label, table, key in (
            ("database", _OPEN_BY_DB, db_key),
            ("data directory", _OPEN_BY_DIR, dir_key),
            ("etcd namespace", _OPEN_BY_NAMESPACE, namespace_key),
        ):
            if key is not None and key in table:
                raise InvalidError(f"vault: this {label} is already open in this process")
        _OPEN_BY_DB[db_key] = dir_key
        _OPEN_BY_DIR[dir_key] = db_key
        if namespace_key is not None:
            _OPEN_BY_NAMESPACE[namespace_key] = db_key
    return db_key, dir_key, namespace_key


def _release_registry(
    key: tuple[str, str, tuple[tuple[str, ...], str] | None] | None,
) -> None:
    if key is None:
        return
    db_key, dir_key, namespace_key = key
    with _OPEN_REGISTRY_LOCK:
        _OPEN_BY_DB.pop(db_key, None)
        _OPEN_BY_DIR.pop(dir_key, None)
        if namespace_key is not None:
            _OPEN_BY_NAMESPACE.pop(namespace_key, None)


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
        self._presence_stop: threading.Event | None = None
        self._presence_thread: threading.Thread | None = None
        self._presence_lease = 0
        self._presence_leases: Any = None
        self._presence_node_id = ""
        self._wrap_stop: threading.Event | None = None
        self._wrap_thread: threading.Thread | None = None
        self._leader: Any = None
        self._key_stop: threading.Event | None = None
        self._key_thread: threading.Thread | None = None
        self._shared_key_meta = False
        self._registry_key: tuple[str, str, tuple[tuple[str, ...], str] | None] | None = None
        self._dir_guard: DataDirGuard | None = None
        self.rotation_period = 0.0
        self._auto_rotate_stop: Callable[[], None] | None = None

        # Fleet identity saved at open; a stale rotation asks through it.
        self._etcd_cfg: Any = None
        self._self_identity: Any = None
        self._cluster_anchor: Any = None
        self._cluster_store: Any = None

        # The optional plaintext read cache. It is installed by open()
        # from the configuration; None means the store reads through to
        # SQLite every time.
        self._cache: RecordCache | None = None
        self._cache_data_version = -1

    # -- construction ---------------------------------------------------

    @classmethod
    def open(cls, cfg: Config, schema: Schema, *, _allow_duplicate: bool = False) -> "Vault":
        """Open or initialise a store."""
        schema.validate()
        if not cfg.data_dir:
            raise InvalidError("vault: config: DataDir is required")
        if cfg.rotation_period < 0:
            raise InvalidError("vault: rotation_period must not be negative")
        if cfg.etcd is not None and cfg.etcd.endpoints and not cfg.etcd.node_id.strip():
            raise InvalidError(
                "vault: etcd requires a node_id; an etcd authority without a node identity cannot share the DEK"
            )
        mode = cfg.crypto_mode
        if mode not in (Mode.AES, Mode.SM4):
            mode = Mode.AES
        db_path = cfg.db_path or os.path.join(cfg.data_dir, DEFAULT_DB_NAME)
        secrets_dir = os.path.join(cfg.data_dir, DEFAULT_SECRETS_SUBDIR)

        mkdir_all_secure(cfg.data_dir, DEFAULT_DATA_DIR_PERM)
        check_data_dir(cfg.data_dir)

        dir_guard = None
        registry_key = None
        if not _allow_duplicate:
            registry_key = _reserve_registry(db_path, cfg.data_dir, cfg)
            try:
                dir_guard = DataDirGuard.acquire(cfg.data_dir, cfg, schema)
            except BaseException:
                _release_registry(registry_key)
                raise
        try:
            return cls._open(cfg, schema, db_path, secrets_dir, mode, registry_key, dir_guard)
        except BaseException:
            if dir_guard is not None:
                dir_guard.close()
            _release_registry(registry_key)
            raise

    @classmethod
    def _open(
        cls,
        cfg: Config,
        schema: Schema,
        db_path: str,
        secrets_dir: str,
        mode: Mode,
        registry_key: tuple[str, str, tuple[tuple[str, ...], str] | None] | None,
        dir_guard: DataDirGuard | None,
    ) -> "Vault":

        mkdir_all_secure(cfg.data_dir, DEFAULT_DATA_DIR_PERM)
        mkdir_all_secure(secrets_dir, DEFAULT_DATA_DIR_PERM)
        check_data_dir(cfg.data_dir)

        multi_process = bool(cfg.multi_process)
        db = open_db(db_path)
        # The authority is declared outside the try so that the error path
        # can close it: a connection that is opened and then abandoned on
        # the way out is a connection the process keeps until it exits.
        authority = None
        leader = None
        node_id = ""
        vault = None

        def _lead_host() -> Any:
            if not multi_process or not node_id:
                return None
            from security_gateway.vault.etcdstore.leader import acquire_host_leader

            candidate = acquire_host_leader(
                authority.store.kv,
                authority.store.leases,
                authority.ns,
                node_id,
                f"{node_id}:{os.getpid()}",
            )
            if candidate is not None:
                candidate.start()
            return candidate

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
                from security_gateway.vault.clusterkey.authority import (
                    KVClusterStore,
                )

                authority = dial_etcd(cfg.etcd)
                node_id = getattr(cfg.etcd, "node_id", "")
                if multi_process and not node_id:
                    raise InvalidError("vault: multi_process requires cluster.node_id")
                if node_id:
                    leader = _lead_host()
                    # Every process serves the handover log; leadership is
                    # only needed to create the store's first key.
                    self_identity = load_cluster_identity(cfg.etcd)
                    anchor = cluster_anchor_for(cfg.etcd)
                    # The cluster store is the roster, the mint election
                    # and the handover log; the record store is a
                    # different half of the same namespace.
                    cluster_store = KVClusterStore(authority.store.kv, authority.ns)
                    local_key = read_key_meta(db)
                    behind = local_key is None or int(local_key.active_dek_version) < int(authority.generation())
                    if not multi_process or (leader is not None and behind):
                        adopt = obtain_cluster_dek(cfg.etcd, cluster_store, self_identity, anchor)

            keys = None
            deadline = time.monotonic() + max(float(getattr(cfg.etcd, "fetch_timeout", 0.0) or 0.0), 30.0)
            while keys is None:
                try:
                    # Every process registers the same data directory, so
                    # the initialise-or-load step has to be serialized: two
                    # processes minting at once would point one metadata row
                    # at the other process's shard file.
                    with initialization_lock(cfg.data_dir) if multi_process else nullcontext():
                        keys, _km = init_keys(
                            db,
                            secrets_dir,
                            mode,
                            adopt,
                            shared_key_meta=authority is None or multi_process,
                            allow_create=authority is None or not multi_process or leader is not None,
                            rotation_period=cfg.rotation_period,
                        )
                except StoreNotReadyError:
                    if leader is None and multi_process:
                        leader = _lead_host()
                        if leader is not None:
                            continue
                    if leader is not None or time.monotonic() > deadline:
                        raise
                    time.sleep(0.05)
            vault = cls(db, keys, secrets_dir, schema, {}, {}, authority)
            vault.activate(
                schema=schema,
                dir_guard=dir_guard,
                registry_key=registry_key,
                cfg=cfg,
                leader=leader,
                multi_process=multi_process,
                self_identity=self_identity,
                anchor=anchor,
                cluster_store=cluster_store,
            )
            return vault
        except BaseException:
            if vault is not None:
                try:
                    vault.close()
                except Exception as exc:  # noqa: BLE001 - shutting down anyway
                    _log.warning("could not close the half-open vault", extra={"error": exc})
                raise
            if leader is not None:
                try:
                    leader.stop()
                    leader.release()
                except Exception:  # noqa: BLE001 - shutting down anyway
                    pass
            if authority is not None:
                try:
                    authority.close()
                except Exception as exc:  # noqa: BLE001 - shutting down anyway
                    _log.warning("could not close the etcd authority", extra={"error": exc})
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

    def activate(
        self,
        *,
        schema: Schema,
        dir_guard: DataDirGuard,
        registry_key: tuple[str, str, str | None],
        cfg: Config,
        leader: Any,
        multi_process: bool,
        self_identity: Any,
        anchor: Any,
        cluster_store: Any,
    ) -> None:
        """Finish opening a store that has its keys and its database."""
        self._dir_guard = dir_guard
        self._registry_key = registry_key
        self.rotation_period = cfg.rotation_period
        if cfg.cache_max_entries > 0:
            self._cache = RecordCache(cfg.cache_max_entries, cfg.cache_ttl)
        self._leader = leader
        self._shared_key_meta = multi_process
        self._etcd_cfg = cfg.etcd
        self._self_identity = self_identity
        self._cluster_anchor = anchor
        self._cluster_store = cluster_store
        self._load_and_validate_schema(schema)
        if self.authority is None and self.keys.prev() is not None:
            self.converge_stragglers()
        if self.authority is not None:
            self._start_authority(cfg.etcd, self_identity, anchor, cluster_store, leader)
            self._start_presence(getattr(cfg.etcd, "node_id", "") or getattr(self_identity, "node_id", ""))
        if cfg.rotation_period > 0:
            from .rotate import start_auto_rotate

            self._auto_rotate_stop = start_auto_rotate(self, cfg.rotation_period)

    # -- reading --------------------------------------------------------

    def get(self, record_id: str) -> Record:
        """Load a record by id."""
        if not record_id:
            raise InvalidRecordError("id is empty")
        self._cache_check()
        if self._cache is not None:
            cached = self._cache.get(record_id)
            if cached is not None:
                return cached
        for attempt in range(2):
            row = get_record(self.db, record_id)
            if row is None:
                raise NotFoundError(f'"{record_id}"')
            sch = self.schema_for_version(row.schema_version)
            if sch is None:
                raise SchemaMismatchError(
                    f'record "{record_id}" was written with schema '
                    f'v{row.schema_version}, which this store does not know'
                )
            try:
                record = self._decode_record(row, sch)
                self._cache_put(record)
                return record
            except StaleGenerationError:
                # The store can hold a row from a generation this process
                # skipped while another process rotated.  The shared key
                # metadata has the newer key (and the one it replaced), so
                # reload once before declaring the record unreadable.
                if attempt == 1:
                    raise
                if self.authority is None and not self._shared_key_meta:
                    raise
                self.reload_snapshot()
                if self.authority is not None:
                    self._reconcile_mirror()
        raise AssertionError("unreachable")

    def get_many(self, ids: list[str]) -> dict[str, Record]:
        """Return the records that exist, keyed by id."""
        return self._get_many(ids)

    def _get_many(self, ids: list[str]) -> dict[str, Record]:
        if any(not record_id for record_id in ids):
            raise InvalidRecordError("id is empty")
        self._cache_check()
        out: dict[str, Record] = {}
        missing: list[str] = []
        for record_id in ids:
            if record_id in out:
                continue
            cached = self._cache.get(record_id) if self._cache is not None else None
            if cached is not None:
                out[record_id] = cached
            elif record_id not in missing:
                missing.append(record_id)
        if not missing:
            return {record_id: out[record_id] for record_id in ids if record_id in out}

        for attempt in range(2):
            rows = get_records(self.db, missing)
            try:
                for record_id in missing:
                    row = rows.get(record_id)
                    if row is None:
                        continue
                    schema = self.schema_for_version(row.schema_version)
                    if schema is None:
                        raise SchemaMismatchError(
                            f'record "{record_id}" was written with schema '
                            f"v{row.schema_version}, which this store does not know"
                        )
                    record = self._decode_record(row, schema)
                    self._cache_put(record)
                    out[record_id] = record
            except StaleGenerationError:
                if attempt == 1:
                    raise
                if self.authority is None and not self._shared_key_meta:
                    raise
                self.reload_snapshot()
                if self.authority is not None:
                    self._reconcile_mirror()
                continue
            return {record_id: out[record_id] for record_id in ids if record_id in out}
        raise AssertionError("unreachable")

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

    def put(self, rec: Record, *, expected: Mapping[str, Value] | None = None) -> None:
        """Write a record.

        The record's fields must all be declared by the current schema,
        and each value must have the type the schema declares. Whether a
        field is stored encrypted is decided by the schema, not by the
        caller.

        ``expected`` is an optional map of field names to the values the
        caller believes are current. Only those fields are guarded: the
        write is refused with :class:`ConflictError` when one of them has
        moved. Passing every field is therefore a record-level CAS; the
        version itself stays internal and is never exposed.
        """
        if rec is None:
            raise InvalidRecordError("record is nil")
        if not rec.id:
            raise InvalidRecordError("id is empty")

        # A field the schema does not declare would be silently dropped,
        # which is worse than refusing it.
        for name in rec.fields:
            if name not in self._fields:
                raise InvalidRecordError(f'field "{name}" is not declared by the schema')
        self._validate_expected(expected)
        if expected is not None and not expected:
            expected = None

        if self.authority is not None:
            self._put_through_authority(rec, expected)
            self._cache_put(rec)
            return
        self._put_local(rec, expected)
        self._cache_put(rec)

    def _put_through_authority(self, rec: Record, expected: Mapping[str, Value] | None = None) -> None:
        """Write a record to the authority under the generation it holds.

        A committed rotation can fence this writer. Reload, ask the fleet
        for a key this process does not hold, and retry a few times.
        """
        from .etcd import FencedWriteError

        last: Exception | None = None
        for attempt in range(5):
            try:
                self._put_through_authority_once(rec, expected)
                return
            except (FencedWriteError, StaleGenerationError) as exc:
                last = exc
                self.reload_snapshot()
                generation = 0
                try:
                    generation = int(self.authority.generation()) if self.authority else 0
                except Exception:  # noqa: BLE001 - absent generation is zero
                    generation = 0
                if generation and self.keys.by_version(generation) is None:
                    self.refresh_from_fleet()
                if attempt < 4:
                    time.sleep(0.1)
        if last is None:
            raise RuntimeError("the authority write was never attempted")
        raise last

    def _put_through_authority_once(self, rec: Record, expected: Mapping[str, Value] | None = None) -> None:
        # The write barrier is taken before the key snapshot is captured,
        # and held until the row is written. That ordering is what keeps a
        # concurrent rotation from landing between the two: the rotation's
        # final straggler check waits for this writer, so a row this call
        # writes is always counted.
        with self.wmu:
            snap, version = self._authority_snapshot(fallback=True)

            encoded = self._encode_record(rec, snap)

            if _put_before_write_hook is not None:
                _put_before_write_hook()

            # With an authority the write goes to it, and only to it: the
            # local copy is a mirror that catches up through a watch, and
            # writing to both would leave the two disagreeing for as long
            # as the watch takes.
            if expected is None:
                self.authority.write_record(
                    self.db,
                    rec.id,
                    encoded,
                    self._schema.version,
                    version,
                )
            else:
                self.authority.write_record(
                    self.db,
                    rec.id,
                    encoded,
                    self._schema.version,
                    version,
                    expected=self._expected_guard(expected),
                )

    def _delete_through_authority(self, record_id: str, expected: Mapping[str, Value] | None) -> None:
        """Delete through the authority, refreshing a stale key once."""
        from .etcd import FencedWriteError

        last: Exception | None = None
        for attempt in range(5):
            try:
                if expected is None:
                    self.authority.delete_record(self.db, record_id)
                else:
                    self.authority.delete_record(self.db, record_id, expected=self._expected_guard(expected))
                return
            except (FencedWriteError, StaleGenerationError) as exc:
                last = exc
                self.reload_snapshot()
                generation = 0
                try:
                    generation = int(self.authority.generation()) if self.authority else 0
                except Exception:  # noqa: BLE001 - absent generation is zero
                    generation = 0
                if generation and self.keys.by_version(generation) is None:
                    self.refresh_from_fleet()
                if attempt < 4:
                    time.sleep(0.1)
        if last is None:
            raise RuntimeError("the authority write was never attempted")
        raise last

    def _authority_snapshot(self, *, fallback: bool = False) -> tuple[KeySnapshot, int]:
        """The key snapshot matching the authority's generation.

        ``fallback`` writes under the key this process holds when the
        authority's generation is not available locally; the fence then
        refuses it. Callers that must distinguish stale from fenced leave
        it false.
        """
        try:
            generation = int(self.authority.generation())
        except Exception:  # noqa: BLE001 - an absent generation is zero
            generation = 0
        if generation:
            snap = self.keys.by_version(generation)
            if snap is None:
                self._reload_keys(generation)
                snap = self.keys.by_version(generation)
            if snap is not None:
                return snap, generation
            if not fallback:
                raise StaleGenerationError(
                    f"the authority is on generation {generation}, which this store does not hold yet"
                )
        cur = self.keys.cur()
        if cur is None:
            raise ClosedError("the store has no key", whole=True)
        return cur, int(cur.version)

    def _put_local(self, rec: Record, expected: Mapping[str, Value] | None = None) -> None:
        """Write a record to the local database.

        The transaction holds the write lock from the moment the
        generation is read to the moment the row is written, so no other
        writer can change the generation in between.
        """
        for attempt in range(8):
            try:
                run_with_busy_retry(lambda: self._put_local_once(rec, expected))
                return
            except _RowConflict:
                if attempt == 7:
                    raise ConflictError(f'the record "{rec.id}" kept changing') from None
                continue
            except StaleGenerationError:
                if attempt == 7:
                    raise
                self.reload_snapshot()
                continue
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
        raise StaleGenerationError("the store is on a generation this process does not hold")

    def _put_local_once(self, rec: Record, expected: Mapping[str, Value] | None = None) -> None:
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

                row = RecordRow(
                    id=rec.id,
                    schema_version=self._schema.version,
                    data=encoded,
                    dek_version=target,
                )
                if expected is None:
                    put_record(self.db, row)
                    return
                current = get_record(self.db, rec.id)
                if current is None:
                    raise NotFoundError(f'"{rec.id}"')
                self._assert_expected(self._decode_current(current), expected)
                if not put_record_cas(self.db, row, current.row_version):
                    raise _RowConflict()

    def _validate_expected(self, expected: Mapping[str, Value] | None) -> None:
        """Refuse an expected map the schema could not have produced."""
        if expected is None:
            return
        if not isinstance(expected, Mapping):
            raise InvalidRecordError("expected must be a mapping of field values")
        for name, value in expected.items():
            definition = self._fields.get(name)
            if definition is None:
                raise InvalidRecordError(f'expected field "{name}" is not declared by the schema')
            if not isinstance(value, Value):
                raise InvalidRecordError(f'expected field "{name}" is not a Value')
            if value.type != definition.type:
                raise InvalidRecordError(
                    f'expected field "{name}" has type {value.type} but the schema says {definition.type}'
                )
            value.validate()

    def _assert_expected(self, current: Record, expected: Mapping[str, Value] | None) -> None:
        """Raise a conflict when a guarded field no longer matches."""
        if expected is None:
            return
        changed: list[str] = []
        for name, wanted in expected.items():
            present = current.fields.get(name)
            if present is None or present.type != wanted.type or present.data != wanted.data:
                changed.append(name)
        changed.sort()
        if changed:
            raise ConflictError(f"expected field(s) {', '.join(changed)} no longer match")

    def _decode_current(self, row: RecordRow) -> Record:
        """Decode a row using the schema it was written with."""
        schema = self.schema_for_version(row.schema_version)
        if schema is None:
            raise SchemaMismatchError(
                f'record "{row.id}" was written with schema v{row.schema_version}, which this store does not know'
            )
        return self._decode_record(row, schema)

    def _record_from_entry(self, record_id: str, entry: Any) -> Record:
        """Decode an authority entry into a plaintext record."""
        return self._decode_current(
            RecordRow(
                id=record_id,
                schema_version=int(entry.schema_version),
                data=bytes(entry.data),
                dek_version=int(entry.dek_version),
            )
        )

    def _expected_guard(self, expected: Mapping[str, Value] | None) -> Callable[[str, Any], None] | None:
        """Build the check the authority runs against its current entry."""
        if expected is None:
            return None

        def guard(record_id: str, entry: Any) -> None:
            self._assert_expected(self._record_from_entry(record_id, entry), expected)

        return guard

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

    def delete(self, record_id: str, *, expected: Mapping[str, Value] | None = None) -> None:
        """Remove a record.

        It raises :class:`~security_gateway.vault.errors.NotFoundError` when
        the id is unknown. ``expected`` guards the same fields as
        :meth:`put`; a mismatch refuses the delete with
        :class:`ConflictError`.
        """
        if not record_id:
            raise InvalidRecordError("id is empty")
        self._validate_expected(expected)
        # With an authority the delete goes to it, and only to it: the
        # local copy is a mirror, and the watch brings the deletion here.
        # It must not hold the local write lock while it waits for etcd.
        if self.authority is not None:
            self._delete_through_authority(record_id, expected)
            self._cache_delete(record_id)
            return
        with self.wmu:
            if expected is None:
                if not run_with_busy_retry(lambda: delete_record(self.db, record_id)):
                    raise NotFoundError(f'"{record_id}"')
                self._cache_delete(record_id)
                return
            for attempt in range(8):
                current = run_with_busy_retry(lambda: get_record(self.db, record_id))
                if current is None:
                    raise NotFoundError(f'"{record_id}"')
                try:
                    self._assert_expected(self._decode_current(current), expected)
                except StaleGenerationError:
                    if attempt == 7:
                        raise
                    self.reload_snapshot()
                    continue
                if run_with_busy_retry(lambda: delete_record_cas(self.db, record_id, current.row_version)):
                    self._cache_delete(record_id)
                    return
            raise ConflictError(f'the record "{record_id}" kept changing')

    # -- housekeeping ---------------------------------------------------

    def status(self) -> Status:
        """The store's current state."""
        digest = self._schema.hash()
        status = Status(
            schema_version=self._schema.version,
            schema_hash=digest.hex(),
            record_count=count_records(self.db),
        )
        km = read_key_meta(self.db)
        if km is not None:
            status.last_rotate_at = km.last_rotate_at
        status.rotation_period = self.rotation_period
        cur = self.keys.cur()
        if cur is None:
            return status
        status.crypto_mode = str(cur.mode)
        # The generation the store is on. While a rotation is in flight that
        # is the pending one: the new records are stamped with it, so it is
        # the generation in use, even though the committed active generation
        # has not moved yet.
        target = cur.version
        if self.authority is None or self._shared_key_meta:
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
            self._cache_clear()
            stop = self._auto_rotate_stop
            self._auto_rotate_stop = None
            if stop is not None:
                stop()
            self._close_extra()
        finally:
            try:
                self.keys.zero_all()
                self.db.close()
            finally:
                _release_registry(self._registry_key)
                self._registry_key = None
                guard = self._dir_guard
                self._dir_guard = None
                if guard is not None:
                    guard.close()

    # -- the read cache ---------------------------------------------------

    def _cache_check(self) -> None:
        """Drop the cache when another connection committed since the last read.

        SQLite's ``data_version`` changes when a *different* connection
        commits, which is exactly the case a process-local invalidation
        cannot see: another process sharing the directory.  The check is a
        single pragma, cheap next to a row lookup and a decrypt.
        """
        if self._cache is None:
            return
        row = self.db.query_one("PRAGMA data_version")
        version = int(row[0]) if row else 0
        if self._cache_data_version < 0:
            self._cache_data_version = version
            return
        if version != self._cache_data_version:
            self._cache.clear()
            self._cache_data_version = version

    def _cache_put(self, record: Record) -> None:
        if self._cache is not None:
            self._cache.put(record.id, record)

    def _cache_delete(self, record_id: str) -> None:
        if self._cache is not None:
            self._cache.delete(record_id)

    def _cache_clear(self) -> None:
        if self._cache is not None:
            self._cache.clear()

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

        wrap_stop = self._wrap_stop
        self._wrap_stop = None
        if wrap_stop is not None:
            wrap_stop.set()
        wrap_thread = self._wrap_thread
        self._wrap_thread = None
        if wrap_thread is not None:
            wrap_thread.join(timeout=5.0)

        key_stop = self._key_stop
        self._key_stop = None
        if key_stop is not None:
            key_stop.set()
        key_thread = self._key_thread
        self._key_thread = None
        if key_thread is not None:
            key_thread.join(timeout=5.0)

        pstop = self._presence_stop
        self._presence_stop = None
        if pstop is not None:
            pstop.set()
        pthread = self._presence_thread
        self._presence_thread = None
        if pthread is not None:
            pthread.join(timeout=5.0)
        if self._presence_lease:
            try:
                from security_gateway.vault.etcdstore import drop_presence

                drop_presence(self._presence_leases, self._presence_lease)
            except Exception:  # noqa: BLE001 - the lease expires on its own
                pass
            self._presence_lease = 0

        leader = self._leader
        self._leader = None
        if leader is not None:
            leader.stop()
            try:
                leader.release()
            except Exception:  # noqa: BLE001 - the lease expires on its own
                pass

        authority = self.authority
        if authority is None:
            return
        self.authority = None
        close = getattr(authority, "close", None)
        if callable(close):
            close()

    def present_generations(self) -> dict[str, int]:
        """The generation every live node currently claims."""
        if self.authority is None:
            return {}
        from security_gateway.vault.etcdstore import list_present

        store = self.authority.store
        try:
            return list_present(store.kv, store.ns)
        except Exception as exc:  # noqa: BLE001 - a barrier cannot break a rotation
            _log.debug("vault: could not list presence: %s", exc)
            return {}

    def await_adoption(
        self,
        target: int,
        *,
        timeout: float,
        ratio: float = 1.0 / 3.0,
        poll: float = 0.5,
    ):
        """Wait for the fleet's live nodes to adopt ``target``.

        Presence is per ``node_id``, so a host with several vault
        processes still contributes one vote.
        """
        from .barrier import await_adoption

        return await_adoption(
            self.present_generations,
            self._presence_node_id,
            target,
            timeout=timeout,
            ratio=ratio,
            poll=poll,
        )

    def _start_presence(self, node_id: str) -> None:
        """Publish this node's generation while it is open, when it can lease."""
        if not node_id or self.authority is None:
            return
        # Presence is keyed by node id, so exactly one process per host
        # may publish it: in a multi-process host that is the host leader.
        # Letting every process publish would mean the first process to
        # exit deletes the shared marker while its siblings are still
        # serving.
        if self._shared_key_meta and self._leader is None:
            return
        store = self.authority.store
        leases = getattr(store, "leases", None)
        if leases is None:
            return
        self._presence_node_id = node_id
        self._presence_leases = leases
        stop = threading.Event()
        self._presence_stop = stop
        thread = threading.Thread(
            target=self._presence_loop,
            args=(stop, store, leases, node_id),
            name="cred-router-vault-presence",
            daemon=True,
        )
        self._presence_thread = thread
        thread.start()

    def _presence_loop(self, stop, store, leases, node_id: str) -> None:
        from security_gateway.vault.etcdstore import (
            PRESENCE_TTL_SECONDS,
            put_presence,
            renew_presence,
        )

        last = -1
        while not stop.is_set():
            try:
                generation = self._local_dek_version()
                if self._presence_lease and generation == last:
                    renew_presence(leases, self._presence_lease)
                else:
                    self._presence_lease = put_presence(store.kv, leases, store.ns, node_id, generation)
                    last = generation
            except Exception as exc:  # noqa: BLE001 - presence is best effort
                # The lease may have expired between the renew and the
                # exception; forget it so the next pass publishes a new one.
                self._presence_lease = 0
                _log.debug("vault: could not publish presence: %s", exc)
            stop.wait(max(PRESENCE_TTL_SECONDS / 3.0, 1.0))

    def _local_dek_version(self) -> int:
        """The generation this node can open, read live."""
        cur = self.keys.cur()
        if cur is None:
            return 0
        pending = self.keys.pend()
        if pending is not None and int(pending.version) > int(cur.version):
            return int(pending.version)
        return int(cur.version)

    # -- internals ------------------------------------------------------

    def _encrypt_with(self, snap: KeySnapshot, plaintext: bytes) -> bytes:
        """Seal a value under a given key snapshot."""
        if snap is None:
            raise ClosedError("the store has no key", whole=True)
        return encrypt_credential(snap.mode, snap.dek_bytes(), plaintext)

    def _decrypt_for(self, version: int, blob: bytes) -> bytes:
        """Open a ciphertext with the key that holds the generation the record was written with."""
        snap = self.keys.by_version(version)
        if snap is not None:
            return self._decrypt_with(snap, version, blob)

        # The snapshot does not hold that generation. Another process may
        # have rotated the store since this one last looked.
        if self.authority is None or self._shared_key_meta:
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
                return decrypt_credential(candidate.mode, candidate.dek_bytes(), blob)
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

    def refresh_from_fleet(self) -> bool:
        """Adopt the fleet's current generation after another node rotated.

        Returns whether the local key moved.  A process that is merely
        behind can now rotate without waiting for the background wrap
        loop to hand it the newer key.
        """
        if self.authority is None or self._etcd_cfg is None:
            return False
        if self._self_identity is None or self._cluster_store is None:
            return False
        from .cluster import obtain_cluster_dek

        try:
            adopted = obtain_cluster_dek(
                self._etcd_cfg,
                self._cluster_store,
                self._self_identity,
                self._cluster_anchor,
            )
        except Exception as exc:  # noqa: BLE001 - the caller reports the stale key
            _log.warning("vault: could not ask the fleet for its current key: %s", exc)
            return False
        if adopted is None:
            return False
        cur = self.keys.cur()
        if cur is not None and int(adopted.version) <= int(cur.version):
            return False
        try:
            # A rotation can move the fleet more than one generation while
            # this process is catching up.  The newest key alone is not
            # enough then: records written under the generation in between
            # would be undecryptable.  Fetch that generation first; the
            # subsequent adopt keeps it as ``previous``.
            if cur is not None and int(adopted.version) > int(cur.version) + 1:
                from security_gateway.vault.clusterkey.handover import predecessor

                previous_dek, previous_version = predecessor(
                    self._cluster_store,
                    self._self_identity,
                    int(adopted.version),
                    self._etcd_cfg.fetch_timeout,
                )
                if int(previous_version) == int(adopted.version) - 1:
                    self.adopt_cluster_dek(previous_dek, previous_version)
                    self.reload_snapshot()
            self.adopt_cluster_dek(adopted.dek, adopted.version)
            self.reload_snapshot()
        except Exception as exc:  # noqa: BLE001 - the caller reports the stale key
            _log.warning("vault: could not adopt the fleet's key: %s", exc)
            return False
        return True

    def _plain_entry(self, row: RecordRow, sch: Schema) -> Entry:
        """Decode a stored row into an entry that carries only the fields the schema does not mark encrypted."""
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
                    raise StaleGenerationError(f'record "{row.id}" field "{f.name}": {exc}') from exc
                except UndecryptableError as exc:
                    raise UndecryptableError(f'record "{row.id}" field "{f.name}": {exc}') from exc
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
                raise SchemaMismatchError(f"the store's schema v{latest.version} is missing from its registry")
            if not is_additive(stored, declared):
                raise SchemaMismatchError(
                    f"schema v{stored.version} -> v{declared.version} changes an existing field; "
                    f"a schema change must be additive"
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
