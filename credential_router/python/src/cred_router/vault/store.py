"""The SQLite layer of the vault.

The vault owns four tables::

    vault_record        the records
    vault_schema        the schema registry: which schema each version is
    vault_key_metadata  the key material and the rotation state
    vault_sync_state    the mirror's bookkeeping

The key metadata lives in the same database as the records, so that the
thing that unlocks the records and the records themselves are backed up
and restored together.
"""

from __future__ import annotations

import os
import sqlite3
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Sequence, TypeVar

from .errors import ConflictError, VaultError
from .format import format_duration

#: The records table.
RECORD_DDL = """
CREATE TABLE IF NOT EXISTS vault_record (
    id             TEXT PRIMARY KEY,
    schema_version INTEGER NOT NULL,
    data           BLOB NOT NULL,
    dek_version    INTEGER NOT NULL,
    row_version    INTEGER NOT NULL DEFAULT 1,
    source_revision INTEGER NOT NULL DEFAULT 0,
    created_at     INTEGER NOT NULL,
    updated_at     INTEGER NOT NULL
)"""

#: The schema registry.
SCHEMA_DDL = """
CREATE TABLE IF NOT EXISTS vault_schema (
    version    INTEGER PRIMARY KEY,
    hash       BLOB NOT NULL,
    definition TEXT NOT NULL,
    created_at INTEGER NOT NULL
)"""

#: The key material and the rotation state.
KEY_META_DDL = """
CREATE TABLE IF NOT EXISTS vault_key_metadata (
    id                     INTEGER PRIMARY KEY CHECK (id = 1),
    active_dek_version     INTEGER NOT NULL,
    pending_dek_version    INTEGER NOT NULL DEFAULT 0,
    crypto_mode            TEXT    NOT NULL,
    active_config_shard    BLOB    NOT NULL,
    pending_config_shard   BLOB    NOT NULL DEFAULT x'',
    file_shard_version     INTEGER NOT NULL DEFAULT 1,
    file_shard_rotated_at  INTEGER NOT NULL DEFAULT 0,
    last_rotate_at         INTEGER NOT NULL DEFAULT 0,
    wrapped_dek            BLOB    NOT NULL,
    pending_wrapped_dek    BLOB    NOT NULL DEFAULT x'',
    superseded_dek_version INTEGER NOT NULL DEFAULT 0,
    superseded_wrapped_dek BLOB    NOT NULL DEFAULT x'',
    updated_at             INTEGER NOT NULL
)"""

#: The mirror's bookkeeping.
SYNC_STATE_DDL = """
CREATE TABLE IF NOT EXISTS vault_sync_state (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    last_applied_rev INTEGER NOT NULL DEFAULT 0,
    updated_at       INTEGER NOT NULL
)"""

T = TypeVar("T")

#: The singleton row id of ``vault_sync_state``.
MIRROR_SYNC_STATE_ID = 1

#: The permissions the database file is given.
DEFAULT_DB_FILE_PERM = 0o600

#: How many times a statement waits out a busy store before giving up.
#:
#: The database's own busy timeout does the waiting; this bounds how many
#: times it does it.
BUSY_WAIT_BUDGET_SECONDS = 30.0

#: How long a statement waits between attempts.
#:
#: It starts short and doubles, because the common case is a writer that is
#: about to finish.
BUSY_RETRY_DELAY_SECONDS = 0.01

#: The longest the busy backoff waits between attempts.
#:
#: The delay stops growing here and the wait continues at this length until
#: the budget runs out.
BUSY_RETRY_DELAY_MAX_SECONDS = 1.0


def is_busy(exc: sqlite3.OperationalError) -> bool:
    """Whether the error says another writer holds the lock."""
    text = str(exc).lower()
    return "database is locked" in text or "database table is locked" in text


def _sleep(seconds: float, stop: Callable[[], BaseException | None] | None) -> None:
    """Wait, unless the caller calls the wait off.

    ``stop`` stands in for a context: it returns the error to raise, or
    ``None`` to keep waiting.
    """
    if stop is None:
        time.sleep(seconds)
        return
    deadline = time.monotonic() + seconds
    while True:
        reason = stop()
        if reason is not None:
            raise reason
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        time.sleep(min(remaining, 0.05))


def run_with_busy_retry(
    fn: Callable[[], T],
    stop: Callable[[], BaseException | None] | None = None,
) -> T:
    """Run a statement, waiting out a busy store.

    ``stop`` calls the wait off: it returns the error to raise, or
    ``None`` to keep waiting.
    """
    started = time.monotonic()
    delay = BUSY_RETRY_DELAY_SECONDS
    while True:
        try:
            return fn()
        except sqlite3.OperationalError as exc:
            if not is_busy(exc):
                raise
            if (time.monotonic() - started) >= BUSY_WAIT_BUDGET_SECONDS:
                raise VaultError(
                    "vault: the store stayed busy for "
                    f"{format_duration(BUSY_WAIT_BUDGET_SECONDS)}: {exc}"
                ) from exc
            _sleep(delay, stop)
            delay = min(delay * 2, BUSY_RETRY_DELAY_MAX_SECONDS)


class Database:
    """The store's SQLite connection and its re-entrant lock.

    One connection is shared between threads, so the transaction
    boundaries are taken under this lock; it is re-entrant so that a
    helper may be called from inside a transaction.
    """

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        self._lock = threading.RLock()
        self._rolled_back = False

    @property
    def connection(self) -> sqlite3.Connection:
        """The raw connection, for the rare caller that needs it."""
        return self._conn

    def execute(self, sql: str, params: Sequence[object] = ()) -> sqlite3.Cursor:
        """Run one statement and return its cursor."""
        with self._lock:
            return self._conn.execute(sql, params)

    def query_all(self, sql: str, params: Sequence[object] = ()) -> list[tuple]:
        """Run one statement and fetch every row."""
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def query_one(self, sql: str, params: Sequence[object] = ()) -> tuple | None:
        """Run one statement and fetch the first row, or None."""
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def rollback(self) -> None:
        """Roll the open transaction back."""
        with self._lock:
            self._conn.execute("ROLLBACK")
            self._rolled_back = True

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """Run a block inside one transaction.

        ``immediate`` takes the write lock when the transaction starts
        rather than when it first writes; the write path needs that,
        because it reads the key metadata and writes the record under
        one lock.
        """
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
            self._rolled_back = False
            try:
                yield self._conn
            except BaseException:
                self._safe_rollback()
                raise
            else:
                if self._rolled_back:
                    return
                try:
                    self._conn.execute("COMMIT")
                except sqlite3.Error:
                    self._safe_rollback()
                    raise

    def _safe_rollback(self) -> None:
        """Roll the transaction back, whatever the database thinks."""
        with self._lock:
            try:
                self._conn.execute("ROLLBACK")
            except sqlite3.Error:
                pass
            self._rolled_back = True

    def close(self) -> None:
        """Close the connection."""
        with self._lock:
            self._conn.close()


def open_db(path: str) -> Database:
    """Open the store's SQLite database and apply the pragmas."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, DEFAULT_DB_FILE_PERM)
    os.close(fd)
    os.chmod(path, DEFAULT_DB_FILE_PERM)
    conn = sqlite3.connect(
        path, timeout=5.0, check_same_thread=False, isolation_level=None
    )
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return Database(conn)


def bootstrap_schema(db: Database) -> None:
    """Create the vault's tables."""
    for stmt in (RECORD_DDL, SCHEMA_DDL, KEY_META_DDL, SYNC_STATE_DDL):
        db.execute(stmt)
    db.execute(
        "INSERT OR IGNORE INTO vault_sync_state (id, last_applied_rev, updated_at) "
        "VALUES (?, 0, 0)",
        (MIRROR_SYNC_STATE_ID,),
    )
    ensure_mirror_columns(db)


def table_columns(db: Database, table: str) -> set[str]:
    """The column names of a table."""
    rows = db.query_all(f"PRAGMA table_info({table})")
    return {str(row[1]) for row in rows}


def ensure_mirror_columns(db: Database) -> None:
    """Add the mirror columns to a table created before they existed."""
    if "source_revision" not in table_columns(db, "vault_record"):
        db.execute(
            "ALTER TABLE vault_record ADD COLUMN "
            "source_revision INTEGER NOT NULL DEFAULT 0"
        )


@dataclass
class RecordRow:
    """A row of ``vault_record``."""

    id: str
    schema_version: int
    data: bytes
    dek_version: int
    row_version: int = 0
    source_revision: int = 0
    created_at: int = 0
    updated_at: int = 0


@dataclass
class SchemaEntry:
    """A row of ``vault_schema``."""

    version: int
    hash: bytes
    definition: str


_RECORD_COLUMNS = (
    "id, schema_version, data, dek_version, row_version, created_at, updated_at"
)


def _row_to_record(row: tuple) -> RecordRow:
    return RecordRow(
        id=row[0],
        schema_version=row[1],
        data=row[2],
        dek_version=row[3],
        row_version=row[4],
        created_at=row[5],
        updated_at=row[6],
    )


def get_record(db: Database, record_id: str) -> RecordRow | None:
    """Load one record by its id.

    It returns None when the id is unknown, so the caller distinguishes
    "absent" from "failed" without inspecting an error string.
    """
    row = db.query_one(
        f"SELECT {_RECORD_COLUMNS} FROM vault_record WHERE id = ?", (record_id,)
    )
    if row is None:
        return None
    return _row_to_record(row)


def put_record(db: Database, row: RecordRow) -> None:
    """Insert or replace a record.

    The write is last-write-wins: a record's identity is its id. The
    ``row_version`` is still maintained, because the key rotation uses
    it as an optimistic guard against a concurrent write.
    """
    now = int(time.time())
    if row.created_at == 0:
        row.created_at = now
    row.updated_at = now
    cur = db.execute(
        """
        INSERT INTO vault_record (id, schema_version, data, dek_version, row_version, created_at, updated_at)
        VALUES (?, ?, ?, ?, 1, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            schema_version = excluded.schema_version,
            data           = excluded.data,
            dek_version    = excluded.dek_version,
            row_version    = vault_record.row_version + 1,
            updated_at     = excluded.updated_at""",
        (
            row.id,
            row.schema_version,
            row.data,
            row.dek_version,
            row.created_at,
            row.updated_at,
        ),
    )
    if cur.rowcount == 0:
        raise ConflictError(f'writing record "{row.id}" affected no rows')


def delete_record(db: Database, record_id: str) -> bool:
    """Remove a record."""
    cur = db.execute("DELETE FROM vault_record WHERE id = ?", (record_id,))
    return cur.rowcount > 0


def list_records(db: Database, prefix: str) -> list[RecordRow]:
    """Load every record whose id begins with prefix."""
    query = f"SELECT {_RECORD_COLUMNS} FROM vault_record"
    args: list[object] = []
    if prefix:
        query += " WHERE id >= ?"
        args.append(prefix)
        upper, ok = prefix_upper_bound(prefix)
        if ok:
            query += " AND id < CAST(? AS TEXT)"
            args.append(upper)
    query += " ORDER BY id"
    return [_row_to_record(row) for row in db.query_all(query, args)]


def prefix_upper_bound(prefix: str | bytes) -> tuple[bytes, bool]:
    """The exclusive upper bound of the range that begins with prefix."""
    if isinstance(prefix, str):
        b = bytearray(prefix.encode("utf-8"))
    else:
        b = bytearray(prefix)
    for i in range(len(b) - 1, -1, -1):
        if b[i] < 0xFF:
            b[i] += 1
            return bytes(b[: i + 1]), True
    return b"", False


def count_records(db: Database) -> int:
    """The number of records in the store."""
    row = db.query_one("SELECT COUNT(*) FROM vault_record")
    return int(row[0]) if row is not None else 0


def select_stragglers(db: Database, target_dek: int, limit: int) -> list[RecordRow]:
    """Load up to ``limit`` records whose dek_version is below target_dek."""
    rows = db.query_all(
        f"SELECT {_RECORD_COLUMNS} FROM vault_record "
        "WHERE dek_version < ? ORDER BY id LIMIT ?",
        (target_dek, limit),
    )
    return [_row_to_record(row) for row in rows]


def count_stragglers(db: Database, target_dek: int) -> int:
    """The number of records whose dek_version is below target_dek."""
    row = db.query_one(
        "SELECT COUNT(*) FROM vault_record WHERE dek_version < ?", (target_dek,)
    )
    return int(row[0]) if row is not None else 0


def update_record_cipher(
    db: Database, record_id: str, row_version: int, data: bytes, dek_version: int
) -> bool:
    """Write a re-encrypted record."""
    cur = db.execute(
        """
        UPDATE vault_record
        SET data = ?, dek_version = ?, row_version = row_version + 1, updated_at = ?
        WHERE id = ? AND row_version = ?""",
        (data, dek_version, int(time.time()), record_id, row_version),
    )
    return cur.rowcount > 0


def read_schema_entries(db: Database) -> list[SchemaEntry]:
    """Load every schema version the store knows about."""
    rows = db.query_all(
        "SELECT version, hash, definition FROM vault_schema ORDER BY version"
    )
    return [
        SchemaEntry(version=int(r[0]), hash=r[1], definition=r[2]) for r in rows
    ]


def insert_schema_entry(db: Database, entry: SchemaEntry) -> None:
    """Record a schema version."""
    db.execute(
        """
        INSERT INTO vault_schema (version, hash, definition, created_at)
        VALUES (?, ?, ?, ?)""",
        (entry.version, entry.hash, entry.definition, int(time.time())),
    )


__all__ = [
    "BUSY_RETRY_DELAY_MAX_SECONDS",
    "BUSY_RETRY_DELAY_SECONDS",
    "BUSY_WAIT_BUDGET_SECONDS",
    "DEFAULT_DB_FILE_PERM",
    "KEY_META_DDL",
    "MIRROR_SYNC_STATE_ID",
    "RECORD_DDL",
    "SCHEMA_DDL",
    "SYNC_STATE_DDL",
    "Database",
    "RecordRow",
    "SchemaEntry",
    "bootstrap_schema",
    "count_records",
    "count_stragglers",
    "delete_record",
    "ensure_mirror_columns",
    "get_record",
    "insert_schema_entry",
    "is_busy",
    "list_records",
    "open_db",
    "prefix_upper_bound",
    "put_record",
    "read_schema_entries",
    "run_with_busy_retry",
    "select_stragglers",
    "table_columns",
    "update_record_cipher",
]
