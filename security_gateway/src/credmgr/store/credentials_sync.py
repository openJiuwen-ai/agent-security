"""Reconciling the local credentials with an external authority.

The Go original is ``internal/credmgr/store/credentials_sync.go``.

This is the multi-node half of the store: it reconciles rows that came
from an authority rather than from this process.  Every function needs
the caller's transaction — the purge sweep and the ``dek_version`` guard
have to run inside the same one.

The reconcile is a set replacement, and both halves matter.  A reconciler
that only upserts can never remove a credential deleted upstream, and an
upstream deletion that lingers locally is the one divergence that keeps
serving a revoked secret; a reconciler that only deletes would be equally
broken.  So every listed row is upserted and every local row the source
did not mention is deleted, in one transaction, so a crash half way
through leaves the table untouched and the next reconcile redoes it.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Sequence

from .errors import SourceIdentityConflictError, StoreError

__all__ = [
    "RECONCILE_BATCH_SIZE",
    "SourceCredential",
    "SourceCredentialMethods",
]

#: The rows per INSERT. The upsert binds eleven parameters per row and
#: older SQLite builds cap SQLITE_MAX_VARIABLE_NUMBER at 999, so fifty
#: rows (550 bindings) stays inside the limit on any build we might
#: run against. This is a hard constraint, not a style choice.
RECONCILE_BATCH_SIZE = 50

#: Everything before the row tuples.
_UPSERT_HEAD = """
INSERT INTO credentials
    (user_id, api_base, key_tag, proxy_key, api_key_cipher, auth_type,
     row_version, kek_version, dek_version, created_at, updated_at)
VALUES """

#: The conflict clause.
#:
#: ``api_key_cipher`` is copied verbatim: the bytes arrive already
#: encrypted under the cluster DEK, and re-encrypting here would need a
#: key this layer deliberately does not hold.
#:
#: The DO UPDATE guard is the DEK-rotation monotonicity rule. A cluster
#: rotation bumps ``dek_version`` in the authority while this node may
#: still be finishing its own re-encryption; applying an older
#: ``dek_version`` entry would roll the node back onto a ciphertext its
#: wrapped DEK can no longer unwrap. Anything not strictly newer is
#: left alone.
#:
#: ``row_version`` tracks the authority's revision rather than
#: incrementing locally: any local write that read an older revision
#: already fails its compare-and-swap once this lands.
_UPSERT_TAIL = """
ON CONFLICT(proxy_key) DO UPDATE SET
    user_id        = excluded.user_id,
    api_base       = excluded.api_base,
    key_tag        = excluded.key_tag,
    api_key_cipher = excluded.api_key_cipher,
    auth_type      = excluded.auth_type,
    row_version    = excluded.row_version,
    dek_version    = excluded.dek_version,
    updated_at     = excluded.updated_at
WHERE credentials.dek_version <= excluded.dek_version"""

#: The temporary table that records which proxy keys the source
#: mentioned. It keeps the purge one statement no matter how many keys
#: there are; the alternative, NOT IN (?, ?, ...), runs into SQLite's
#: variable limit at around a thousand credentials.
_SEEN_TABLE_DDL = "CREATE TEMP TABLE IF NOT EXISTS seen_source_key (proxy_key TEXT PRIMARY KEY)"


@dataclass
class SourceCredential:
    """One credential exactly as it exists in the authority.

    It exists so this package never imports the etcd client: the
    translation lives in the applier, and the store keeps no opinion
    about where its input came from.
    """

    proxy_key: str = ""
    user_id: str = ""
    api_base: str = ""
    key_tag: str = ""
    api_key_cipher: bytes = b""
    auth_type: str = ""
    dek_version: int = 0
    mod_revision: int = 0
    created_at: int = 0
    updated_at: int = 0

    #: The row counts as present in the source — so the reconcile purge
    #: spares it — while its content is withheld. The applier sets it
    #: when an entry is encrypted under a DEK version this node cannot
    #: yet decrypt: writing it would leave a local row the node cannot
    #: decrypt, but dropping it from the seen set would make the purge
    #: delete the still-valid older row.
    skip_update: bool = False


class SourceCredentialMethods:
    """The reconciliation half, mixed into :class:`~.store.Store`."""

    def reconcile_credentials_from_source(self, entries: Sequence[SourceCredential]) -> None:
        """Make the local credentials table an exact mirror of the source."""
        self._reconcile(entries, want_purged=False)

    def reconcile_credentials_from_source_with_purged(self, entries: Sequence[SourceCredential]) -> list[str]:
        """Reconcile, and report the proxy keys the purge removed."""
        return self._reconcile(entries, want_purged=True)

    def _reconcile(self, entries: Sequence[SourceCredential], *, want_purged: bool) -> list[str]:
        # Imported here because store.py composes this module's mixin
        # into Store: a module-level import would be circular.
        from .store import transaction

        purged: list[str] = []
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            conn.execute(_SEEN_TABLE_DDL)
            with transaction(conn):
                conn.execute("DELETE FROM seen_source_key")
                for start in range(0, len(entries), RECONCILE_BATCH_SIZE):
                    stop = start + RECONCILE_BATCH_SIZE
                    batch = entries[start:stop]
                    _upsert_credentials(conn, batch)
                    _record_seen_keys(conn, batch)
                if want_purged:
                    rows = conn.execute(
                        "DELETE FROM credentials "
                        "WHERE proxy_key NOT IN (SELECT proxy_key FROM seen_source_key) "
                        "RETURNING proxy_key"
                    ).fetchall()
                    purged = [str(row[0]) for row in rows]
                else:
                    conn.execute(
                        "DELETE FROM credentials WHERE proxy_key NOT IN (SELECT proxy_key FROM seen_source_key)"
                    )
        return purged

    def upsert_credential_from_source(self, entry: SourceCredential) -> None:
        """Apply a single source row under the same monotonicity guard.

        A withheld row is a no-op: the applier is expected to have
        skipped it, so no caller can write a row this node cannot
        decrypt.
        """
        if entry.skip_update:
            return
        # Imported here because store.py composes this module's mixin
        # into Store: a module-level import would be circular.
        from .store import transaction

        with self.admin_db() as conn:  # type: ignore[attr-defined]
            with transaction(conn):
                _upsert_credentials(conn, [entry])

    def delete_credential_by_proxy_key(self, proxy_key: str) -> None:
        """Remove a local row."""
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            conn.execute("DELETE FROM credentials WHERE proxy_key = ?", (proxy_key,))

    def list_proxy_keys(self) -> list[str]:
        """Return every proxy key held locally."""
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            rows = conn.execute("SELECT proxy_key FROM credentials").fetchall()
        return [str(row[0]) for row in rows]


def _upsert_credentials(conn: sqlite3.Connection, batch: Sequence[SourceCredential]) -> None:
    """Upsert one batch of source rows."""
    applicable = [e for e in batch if not e.skip_update]
    if not applicable:
        return
    placeholders = ",".join("(?,?,?,?,?,?,?,?,?,?,?)" for _ in applicable)
    args: list[object] = []
    for e in applicable:
        # kek_version is node-local bookkeeping, absent from the source:
        # a fresh row starts at 1, an existing row keeps whatever the
        # local rotation machinery has assigned.
        args.extend(
            [
                e.user_id,
                e.api_base,
                e.key_tag,
                e.proxy_key,
                e.api_key_cipher,
                e.auth_type,
                e.mod_revision,
                1,
                e.dek_version,
                e.created_at,
                e.updated_at,
            ]
        )
    sql = f"{_UPSERT_HEAD}{placeholders}{_UPSERT_TAIL}"
    try:
        conn.execute(sql, args)
    except sqlite3.IntegrityError as exc:
        if "UNIQUE constraint failed: credentials.user_id" in str(exc):
            raise SourceIdentityConflictError(
                f"two source rows share one (user_id, api_base, key_tag) identity: {exc}", cause=exc
            ) from exc
        raise StoreError(f"upsert the source credentials: {exc}", cause=exc) from exc
    except sqlite3.Error as exc:
        raise StoreError(f"upsert the source credentials: {exc}", cause=exc) from exc


def _record_seen_keys(conn: sqlite3.Connection, batch: Sequence[SourceCredential]) -> None:
    """Record every proxy key in the batch, withheld rows included."""
    if not batch:
        return
    placeholders = ",".join("(?)" for _ in batch)
    conn.execute(
        f"INSERT OR IGNORE INTO seen_source_key (proxy_key) VALUES {placeholders}",
        [e.proxy_key for e in batch],
    )
