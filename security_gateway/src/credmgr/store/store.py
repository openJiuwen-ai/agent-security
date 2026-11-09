"""The SQLite persistence layer of the credential manager.

The Go original is ``internal/credmgr/store/store.go`` plus
``internal/credmgr/store/credentials_schema.go``; the schema written here
is byte-for-byte the same, because one implementation has to read the
other's database files.

**The schema is bootstrapped, not migrated.** ``Open`` creates the tables
if they are missing, so a caller never runs a separate migration step.
The only schema change since the first release is two columns on
``key_metadata``, added by a guarded ``ALTER`` that runs only when the
column is absent.

**The database is reached through two pools, not one.** ``adminDB`` carries
the writes and the rotation transactions and is kept small, because SQLite
has exactly one writer; ``proxyDB`` carries the proxy's hot reads and is
kept wide, because those are the queries that must not queue behind
anything.  Both point at the same file, and WAL mode is what lets the
reader pool run while a write transaction is open.
"""

from __future__ import annotations

import queue
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator

from .credentials import CredentialMethods
from .credentials_sync import SourceCredentialMethods
from .errors import ClosedError, StoreError
from .key_metadata import KeyMetadataMethods
from .sync_state import SyncStateMethods

__all__ = [
    "DEFAULT_ADMIN_MAX_CONNS",
    "DEFAULT_PROXY_MAX_CONNS",
    "ConnectionPool",
    "OpenConfig",
    "PooledConnection",
    "Store",
    "bootstrap_schema",
    "transaction",
]

#: The admin pool's size. Two is enough for one writer plus a rotation
#: transaction, and small enough that the writers never crowd each other.
DEFAULT_ADMIN_MAX_CONNS = 2

#: The proxy pool's size. The proxy's read path is the hot path.
DEFAULT_PROXY_MAX_CONNS = 32

#: The DSN of the in-memory database. ``cache=shared`` is the load-bearing
#: part: without it every connection would open its own private database
#: and the pools would not see each other's rows.
MEMORY_DSN = "file::memory:?cache=shared"

#: How long a caller waits for a connection before giving up.  A bounded
#: wait turns a leaked lease into an error instead of a hang.
POOL_ACQUIRE_TIMEOUT = 30.0


@dataclass
class OpenConfig:
    """How to open a store."""

    path: str
    admin_max_conns: int = 0
    proxy_max_conns: int = 0


class PooledConnection:
    """A connection leased out of a :class:`ConnectionPool`.

    The lease keeps the pool honest: a connection is only ever in one
    place at a time, so two threads cannot interleave statements inside
    one transaction. Use it as a context manager and the connection goes
    back to the pool on the way out::
    """

    __slots__ = ("_conn", "_pool", "_released")

    def __init__(self, pool: "ConnectionPool", conn: sqlite3.Connection) -> None:
        self._pool = pool
        self._conn = conn
        self._released = False

    @property
    def connection(self) -> sqlite3.Connection:
        """The raw connection behind the lease."""
        return self._conn

    def release(self) -> None:
        """Return the connection to its pool."""
        if self._released:
            return
        self._released = True
        self._pool.release(self._conn)

    # ``close`` reads like "I am done with this connection"; on a lease
    # that means "give it back", not "destroy it".  The pool owns the
    # connection's lifetime.
    close = release

    def __enter__(self) -> sqlite3.Connection:
        return self._conn

    def __exit__(self, *exc_info: object) -> None:
        self.release()

    def __getattr__(self, name: str) -> object:
        return getattr(self._conn, name)

    def __del__(self) -> None:  # pragma: no cover - interpreter shutdown
        try:
            self.release()
        except Exception:  # noqa: BLE001 - interpreter shutdown
            return


class ConnectionPool:
    """A bounded set of connections to one database file.

    Idle connections wait in a queue, a new one is opened when the cap
    allows it, and a caller over the cap waits for one back.
    """

    def __init__(
        self,
        dsn: str,
        *,
        max_conns: int,
        uri: bool = False,
        wal: bool = True,
        foreign_keys: bool = False,
    ) -> None:
        self._dsn = dsn
        self._uri = uri
        self._max_conns = max(1, max_conns)
        self._wal = wal
        self._foreign_keys = foreign_keys
        self._idle: queue.Queue[sqlite3.Connection] = queue.Queue(maxsize=self._max_conns)
        self._all: list[sqlite3.Connection] = []
        self._lock = threading.Lock()
        self._created = 0
        self._closed = False

    @property
    def max_conns(self) -> int:
        """How many connections this pool may hold open at once."""
        return self._max_conns

    @property
    def open_connections(self) -> int:
        """How many connections are currently open."""
        with self._lock:
            return self._created

    def acquire(self) -> PooledConnection:
        """Lease a connection."""
        if self._closed:
            raise ClosedError("the connection pool is closed")
        try:
            conn = self._idle.get_nowait()
        except queue.Empty:
            conn = self._new_or_wait()
        return PooledConnection(self, conn)

    def _new_or_wait(self) -> sqlite3.Connection:
        with self._lock:
            if self._closed:
                raise ClosedError("the connection pool is closed")
            if self._created < self._max_conns:
                self._created += 1
                make = True
            else:
                make = False
        if make:
            try:
                return self._open()
            except BaseException:
                with self._lock:
                    self._created -= 1
                raise
        try:
            conn = self._idle.get(timeout=POOL_ACQUIRE_TIMEOUT)
        except queue.Empty as exc:
            raise StoreError(
                f"the connection pool is exhausted: no connection came back within {POOL_ACQUIRE_TIMEOUT} seconds"
            ) from exc
        if self._closed:
            self._idle.put(conn)
            raise ClosedError("the connection pool is closed")
        return conn

    def _open(self) -> sqlite3.Connection:
        conn = sqlite3.connect(
            self._dsn,
            timeout=5.0,
            check_same_thread=False,
            isolation_level=None,
            uri=self._uri,
        )
        try:
            self._apply_pragmas(conn)
        except BaseException:
            conn.close()
            raise
        with self._lock:
            self._all.append(conn)
        return conn

    def _apply_pragmas(self, conn: sqlite3.Connection) -> None:
        # busy_timeout is the driver's own waiting room for a locked
        # database; the Go DSN carries the same number.
        conn.execute("PRAGMA busy_timeout=5000")
        if self._wal:
            # WAL is what lets the proxy read pool work while an admin
            # write transaction is open.  An in-memory database has no
            # file to keep it in, and SQLite does not support WAL there.
            conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        if self._foreign_keys:
            conn.execute("PRAGMA foreign_keys=ON")

    def release(self, conn: sqlite3.Connection) -> None:
        """Take a connection back into the pool."""
        if self._closed:
            conn.close()
            return
        try:
            self._idle.put_nowait(conn)
        except queue.Full:  # pragma: no cover - cannot happen with the cap
            conn.close()

    def close(self) -> None:
        """Close every connection this pool opened."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            conns = list(self._all)
            self._all.clear()
        for conn in conns:
            try:
                conn.close()
            except sqlite3.Error:
                pass


@contextmanager
def transaction(conn: sqlite3.Connection) -> Iterator[sqlite3.Connection]:
    """Run a block inside one transaction."""
    conn.execute("BEGIN")
    try:
        yield conn
    except BaseException:
        try:
            conn.execute("ROLLBACK")
        except sqlite3.Error:
            pass
        raise
    conn.execute("COMMIT")


#: The credentials table.
CREDENTIALS_DDL = """
CREATE TABLE IF NOT EXISTS credentials (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT    NOT NULL,
    api_base        TEXT    NOT NULL,
    key_tag         TEXT    NOT NULL,
    proxy_key       TEXT    NOT NULL UNIQUE,
    api_key_cipher  BLOB    NOT NULL,
    auth_type       TEXT    NOT NULL,
    row_version     INTEGER NOT NULL DEFAULT 1,
    kek_version     INTEGER NOT NULL DEFAULT 1,
    dek_version     INTEGER NOT NULL DEFAULT 1,
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    UNIQUE (user_id, api_base, key_tag)
)"""

#: The lookup index for the ``(user_id, api_base, key_tag)`` identity.
CREDENTIALS_URT_INDEX_DDL = """
CREATE INDEX IF NOT EXISTS idx_credentials_urt
    ON credentials(user_id, api_base, key_tag)"""

#: The lookup index for the proxy key.
CREDENTIALS_PROXY_KEY_INDEX_DDL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_credentials_proxy_key
    ON credentials(proxy_key)"""

#: The single-row encryption metadata.
KEY_METADATA_DDL = """
CREATE TABLE IF NOT EXISTS key_metadata (
    id                    INTEGER PRIMARY KEY CHECK (id = 1),
    active_kek_version    INTEGER NOT NULL,
    pending_kek_version   INTEGER NOT NULL DEFAULT 0,
    active_dek_version    INTEGER NOT NULL,
    pending_dek_version   INTEGER NOT NULL DEFAULT 0,
    crypto_mode           TEXT    NOT NULL,
    active_config_shard   BLOB    NOT NULL,
    pending_config_shard  BLOB    NOT NULL DEFAULT x'',
    file_shard_version    INTEGER NOT NULL DEFAULT 1,
    file_shard_rotated_at INTEGER NOT NULL,
    last_rotate_at        INTEGER NOT NULL,
    wrapped_dek           BLOB    NOT NULL,
    pending_wrapped_dek   BLOB    NOT NULL,
    dek_rotated_at        INTEGER NOT NULL DEFAULT 0,
    updated_at            INTEGER NOT NULL,
    superseded_dek_version INTEGER NOT NULL DEFAULT 0,
    superseded_wrapped_dek  BLOB    NOT NULL DEFAULT x''
)"""

#: The restart position of the etcd watch loop. It is a singleton for the
#: same reason key_metadata is: there is exactly one etcd keyspace per
#: node, hence exactly one position.  0 means "never synced", which
#: forces a full listing rather than an incremental watch.
SYNC_STATE_DDL = """
CREATE TABLE IF NOT EXISTS sync_state (
    id                INTEGER PRIMARY KEY CHECK (id = 1),
    last_applied_rev  INTEGER NOT NULL DEFAULT 0,
    updated_at        INTEGER NOT NULL
)"""

#: Seeded rather than left absent so that the applied revision can treat
#: "no row" and "revision 0" as the same first-run state.
SYNC_STATE_SEED_DDL = "INSERT OR IGNORE INTO sync_state (id, last_applied_rev, updated_at) VALUES (1, 0, 0)"

#: The columns key_metadata gained after the table shape was first
#: shipped. The bootstrap's CREATE TABLE is IF NOT EXISTS, so the CREATE
#: is skipped whole for an already-provisioned directory and every later
#: query naming a new column fails with "no such column".  Each ALTER
#: therefore runs only when PRAGMA table_info reports the column absent.
KEY_METADATA_ADDITIONS: tuple[tuple[str, str], ...] = (
    ("superseded_dek_version", "ALTER TABLE key_metadata ADD COLUMN superseded_dek_version INTEGER NOT NULL DEFAULT 0"),
    ("superseded_wrapped_dek", "ALTER TABLE key_metadata ADD COLUMN superseded_wrapped_dek BLOB NOT NULL DEFAULT x''"),
)


def table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    """Return the column names of ``table``."""
    rows = conn.execute("SELECT name FROM pragma_table_info(?)", (table,)).fetchall()
    return {str(row[0]) for row in rows}


def bootstrap_schema(conn: sqlite3.Connection) -> None:
    """Create the credential_router schema if it does not already exist."""
    for stmt in (
        CREDENTIALS_DDL,
        CREDENTIALS_URT_INDEX_DDL,
        CREDENTIALS_PROXY_KEY_INDEX_DDL,
        KEY_METADATA_DDL,
        SYNC_STATE_DDL,
        SYNC_STATE_SEED_DDL,
    ):
        conn.execute(stmt)
    have = table_columns(conn, "key_metadata")
    for column, ddl in KEY_METADATA_ADDITIONS:
        if column in have:
            continue
        conn.execute(ddl)


class Store(
    CredentialMethods,
    KeyMetadataMethods,
    SourceCredentialMethods,
    SyncStateMethods,
):
    """The credential store: one SQLite file behind two pools.

    ``admin_db`` is the write path, ``proxy_db`` is the read path; both
    point at the same file, and the schema is bootstrapped when the
    store is opened. The table access lives in the mixins this class is
    built from — one per table.
    """

    def __init__(
        self,
        path: str,
        admin_max_conns: int = 0,
        proxy_max_conns: int = 0,
    ) -> None:
        self._path = path
        self._admin_max = admin_max_conns or DEFAULT_ADMIN_MAX_CONNS
        self._proxy_max = proxy_max_conns or DEFAULT_PROXY_MAX_CONNS
        if self._admin_max <= 0:
            self._admin_max = DEFAULT_ADMIN_MAX_CONNS
        if self._proxy_max <= 0:
            self._proxy_max = DEFAULT_PROXY_MAX_CONNS

        memory = path == ":memory:"
        uri = memory or path.startswith("file:")
        dsn = MEMORY_DSN if memory else path

        self._admin_pool = ConnectionPool(
            dsn,
            max_conns=self._admin_max,
            uri=uri,
            wal=not memory,
            foreign_keys=True,
        )
        self._proxy_pool = ConnectionPool(
            dsn,
            max_conns=self._proxy_max,
            uri=uri,
            wal=not memory,
        )
        self._closed = False
        try:
            lease = self._admin_pool.acquire()
            try:
                with lease as conn:
                    bootstrap_schema(conn)
            finally:
                lease.release()
        except BaseException:
            # A store that did not come up must not leave connections
            # behind: the caller has no handle to close them with.
            self._admin_pool.close()
            self._proxy_pool.close()
            raise

    # -- constructors ------------------------------------------------------

    @classmethod
    def open(cls, path: str) -> "Store":
        """Open a store with the default pool sizes."""
        return cls(path)

    @classmethod
    def open_with_config(cls, cfg: OpenConfig) -> "Store":
        """Open a store with an explicit configuration."""
        return cls(
            cfg.path,
            admin_max_conns=cfg.admin_max_conns,
            proxy_max_conns=cfg.proxy_max_conns,
        )

    @classmethod
    def open_for_testing(cls, path: str) -> "Store":
        """Open a store for a test."""
        return cls(path)

    # -- properties --------------------------------------------------------

    @property
    def path(self) -> str:
        """The path the store was opened with."""
        return self._path

    @property
    def admin_max_conns(self) -> int:
        """The admin pool's size."""
        return self._admin_max

    @property
    def proxy_max_conns(self) -> int:
        """The proxy pool's size."""
        return self._proxy_max

    @property
    def closed(self) -> bool:
        """Whether the store has been closed."""
        return self._closed

    # -- pools -------------------------------------------------------------

    def admin_db(self) -> PooledConnection:
        """Lease a connection from the write pool."""
        if self._closed:
            raise ClosedError("the store is closed")
        return self._admin_pool.acquire()

    def proxy_db(self) -> PooledConnection:
        """Lease a connection from the proxy read pool."""
        if self._closed:
            raise ClosedError("the store is closed")
        return self._proxy_pool.acquire()

    def admin_connection(self) -> PooledConnection:
        """Lease an admin connection as a context manager."""
        return self.admin_db()

    def proxy_connection(self) -> PooledConnection:
        """Lease a proxy connection as a context manager."""
        return self.proxy_db()

    @contextmanager
    def admin_transaction(self) -> Iterator[sqlite3.Connection]:
        """Run a block inside one admin transaction."""
        lease = self.admin_db()
        try:
            with lease as conn:
                with transaction(conn):
                    yield conn
        finally:
            lease.release()

    # -- lifecycle ---------------------------------------------------------

    def close(self) -> None:
        """Close both pools."""
        if self._closed:
            return
        self._closed = True
        first_error: BaseException | None = None
        for pool in (self._admin_pool, self._proxy_pool):
            try:
                pool.close()
            except BaseException as exc:  # pragma: no cover - defensive
                if first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Store(path={self._path!r}, admin={self._admin_max}, proxy={self._proxy_max})"


def _now() -> int:
    """The current unix time in seconds."""
    return int(time.time())
