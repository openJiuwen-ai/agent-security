"""The single-row encryption metadata and the DEK rotation state machine.

The Go original is ``internal/credmgr/store/key_metadata.go``.

The table holds exactly one row, and it is the store's answer to "which
key material is current".

**The pending versions are a two-phase rotation.** A rotation writes the
new key material as *pending* first and only then promotes it to
*active*, so a crash in between leaves the store with a pending key it
can still adopt instead of a half-rotated store it cannot open.

**Phase A re-encrypts in batches, under a compare-and-swap.** The batch
re-encrypts the rows whose ``dek_version`` is below the target, one
transaction per batch, and every row's update carries the ``row_version``
the batch read.  A row that moved on in the meantime is left alone.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Callable

from security_gateway.crypto import Mode, decrypt_credential, encrypt_credential, parse_mode

from .clock import now as _now
from .errors import (
    ConflictError,
    InvalidError,
    KeyMetadataEmptyError,
    NotFoundError,
    PhaseADecryptError,
    StoreError,
)

__all__ = [
    "KEY_METADATA_ID",
    "KeyMetadata",
    "KeyMetadataMethods",
    "set_reencrypt_phase_hook_for_testing",
]

#: The primary key of the one key_metadata row.
KEY_METADATA_ID = 1

#: The columns of the key_metadata row, in the order the scanner expects.
KEY_METADATA_COLUMNS = (
    "active_kek_version, pending_kek_version, active_dek_version, "
    "pending_dek_version, crypto_mode, active_config_shard, "
    "pending_config_shard, file_shard_version, file_shard_rotated_at, "
    "last_rotate_at, wrapped_dek, pending_wrapped_dek, dek_rotated_at, "
    "updated_at, superseded_dek_version, superseded_wrapped_dek"
)

#: The test-only hook fired between Phase A's SELECT and its per-row
#: UPDATE. It is called with the transaction's connection, so a test can
#: act inside the same transaction and prove that the compare-and-swap
#: refuses to overwrite newer data. Production never sets it.
_REENCRYPT_PHASE_HOOK: Callable[[sqlite3.Connection], None] | None = None


def set_reencrypt_phase_hook_for_testing(
    fn: Callable[[sqlite3.Connection], None] | None,
) -> Callable[[], None]:
    """Install the Phase A hook and return a function that restores it."""
    global _REENCRYPT_PHASE_HOOK
    previous = _REENCRYPT_PHASE_HOOK
    _REENCRYPT_PHASE_HOOK = fn

    def restore() -> None:
        """Restore."""
        global _REENCRYPT_PHASE_HOOK
        _REENCRYPT_PHASE_HOOK = previous

    return restore


def _blob(value: bytes | None) -> bytes:
    """Map a missing blob onto an empty one."""
    return b"" if value is None else bytes(value)


@dataclass
class KeyMetadata:
    """The store's single row of encryption metadata."""

    active_kek_version: int = 0
    pending_kek_version: int = 0
    active_dek_version: int = 0
    pending_dek_version: int = 0
    crypto_mode: Mode = Mode.AES
    active_config_shard: bytes = b""
    pending_config_shard: bytes = b""
    file_shard_version: int = 1
    file_shard_rotated_at: int = 0
    last_rotate_at: int = 0
    wrapped_dek: bytes = b""
    pending_wrapped_dek: bytes = b""
    superseded_dek_version: int = 0
    superseded_wrapped_dek: bytes = b""
    dek_rotated_at: int = 0
    updated_at: int = 0


def _scan_key_metadata(row: tuple) -> KeyMetadata:
    """Build a :class:`KeyMetadata` from a result row."""
    return KeyMetadata(
        active_kek_version=int(row[0]),
        pending_kek_version=int(row[1]),
        active_dek_version=int(row[2]),
        pending_dek_version=int(row[3]),
        crypto_mode=parse_mode(str(row[4])),
        active_config_shard=bytes(row[5]),
        pending_config_shard=bytes(row[6]),
        file_shard_version=int(row[7]),
        file_shard_rotated_at=int(row[8]),
        last_rotate_at=int(row[9]),
        wrapped_dek=bytes(row[10]),
        pending_wrapped_dek=bytes(row[11]),
        dek_rotated_at=int(row[12]),
        updated_at=int(row[13]),
        superseded_dek_version=int(row[14]),
        superseded_wrapped_dek=bytes(row[15]),
    )


class KeyMetadataMethods:
    """The key metadata state machine, mixed into :class:`~.store.Store`."""

    def get_key_metadata(self) -> KeyMetadata:
        """Return the single key_metadata row.

        Raises :class:`~.errors.KeyMetadataEmptyError` — a kind of
        not-found — when the store has never been initialised.
        """
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                f"SELECT {KEY_METADATA_COLUMNS} FROM key_metadata WHERE id = ?",
                (KEY_METADATA_ID,),
            ).fetchone()
        if row is None:
            raise KeyMetadataEmptyError("the key_metadata table is empty")
        try:
            return _scan_key_metadata(row)
        except Exception as exc:
            raise StoreError(f"parse the key_metadata row: {exc}", cause=exc) from exc

    def insert_key_metadata(self, km: KeyMetadata) -> KeyMetadata:
        """Insert the initial key_metadata row.

        Raises :class:`~.errors.ConflictError` when the row is already
        there: there is exactly one, and re-initialising would orphan
        it.
        """
        if km is None:
            raise InvalidError("no key metadata was given")
        now = _now()
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            try:
                conn.execute(
                    """
                    INSERT INTO key_metadata (
                        id, active_kek_version, pending_kek_version,
                        active_dek_version, pending_dek_version, crypto_mode,
                        active_config_shard, pending_config_shard,
                        file_shard_version, file_shard_rotated_at,
                        last_rotate_at, wrapped_dek, pending_wrapped_dek,
                        dek_rotated_at, updated_at, superseded_dek_version,
                        superseded_wrapped_dek
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        KEY_METADATA_ID,
                        km.active_kek_version,
                        km.pending_kek_version,
                        km.active_dek_version,
                        km.pending_dek_version,
                        str(km.crypto_mode),
                        _blob(km.active_config_shard),
                        _blob(km.pending_config_shard),
                        km.file_shard_version,
                        km.file_shard_rotated_at,
                        km.last_rotate_at,
                        _blob(km.wrapped_dek),
                        _blob(km.pending_wrapped_dek),
                        km.dek_rotated_at,
                        now,
                        km.superseded_dek_version,
                        _blob(km.superseded_wrapped_dek),
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ConflictError("the key_metadata row already exists", cause=exc) from exc
            except sqlite3.Error as exc:
                raise StoreError(f"insert key_metadata: {exc}", cause=exc) from exc
        km.updated_at = now
        return km

    def update_key_metadata(self, km: KeyMetadata) -> KeyMetadata:
        """Update the single key_metadata row.

        Raises :class:`~.errors.NotFoundError` when the row is missing —
        a store without key material cannot be updated into having some.
        """
        if km is None:
            raise InvalidError("no key metadata was given")
        now = _now()
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            cur = conn.execute(
                """
                UPDATE key_metadata SET
                    active_kek_version=?, pending_kek_version=?,
                    active_dek_version=?, pending_dek_version=?,
                    crypto_mode=?, active_config_shard=?, pending_config_shard=?,
                    file_shard_version=?, file_shard_rotated_at=?,
                    last_rotate_at=?, wrapped_dek=?, pending_wrapped_dek=?,
                    dek_rotated_at=?, updated_at=?, superseded_dek_version=?,
                    superseded_wrapped_dek=?
                WHERE id=?
                """,
                (
                    km.active_kek_version,
                    km.pending_kek_version,
                    km.active_dek_version,
                    km.pending_dek_version,
                    str(km.crypto_mode),
                    _blob(km.active_config_shard),
                    _blob(km.pending_config_shard),
                    km.file_shard_version,
                    km.file_shard_rotated_at,
                    km.last_rotate_at,
                    _blob(km.wrapped_dek),
                    _blob(km.pending_wrapped_dek),
                    km.dek_rotated_at,
                    now,
                    km.superseded_dek_version,
                    _blob(km.superseded_wrapped_dek),
                    KEY_METADATA_ID,
                ),
            )
            if cur.rowcount == 0:
                raise NotFoundError("the key_metadata row is missing")
        km.updated_at = now
        return km

    def bulk_update_kek_version(self, new_version: int) -> int:
        """Move every credential below ``new_version`` onto it."""
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            cur = conn.execute(
                "UPDATE credentials SET kek_version=?, row_version=row_version+1, updated_at=? WHERE kek_version < ?",
                (new_version, _now(), new_version),
            )
            return int(cur.rowcount)

    def reencrypt_dek_version_batch(
        self,
        old_dek: bytes,
        new_dek: bytes,
        mode: Mode,
        target_dek: int,
        limit: int,
    ) -> int:
        """Re-encrypt up to ``limit`` credentials onto ``new_dek``.

        A concurrent admin write may rewrite a row between this
        function's SELECT and its per-row UPDATE, so the UPDATE carries
        the ``row_version`` the batch read: a row that has moved on is
        silently skipped.
        """
        if limit <= 0:
            raise InvalidError(f"limit must be positive, got {limit}")
        if not old_dek or not new_dek:
            raise InvalidError("the old and the new DEK must both be present")

        # Imported here because store.py composes this module's mixin
        # into Store: a module-level import would be circular.
        from .store import transaction

        with self.admin_db() as conn:  # type: ignore[attr-defined]
            with transaction(conn):
                rows = conn.execute(
                    "SELECT id, row_version, api_key_cipher FROM credentials WHERE dek_version < ? ORDER BY id LIMIT ?",
                    (target_dek, limit),
                ).fetchall()
                batch: list[tuple[int, int, bytes]] = []
                for row in rows:
                    row_id = int(row[0])
                    row_version = int(row[1])
                    cipher = bytes(row[2])
                    try:
                        plaintext = decrypt_credential(mode, old_dek, cipher)
                    except Exception as exc:
                        raise PhaseADecryptError(
                            f"row {row_id}: the ciphertext could not be decrypted: {exc}", cause=exc
                        ) from exc
                    try:
                        new_cipher = encrypt_credential(mode, new_dek, plaintext)
                    except Exception as exc:
                        raise StoreError(
                            f"row {row_id}: the ciphertext could not be re-encrypted: {exc}", cause=exc
                        ) from exc
                    batch.append((row_id, row_version, new_cipher))

                # The deterministic barrier between the SELECT and the
                # UPDATEs: it lets a competing admin write win the race,
                # which is how the row_version guard is proved.
                if _REENCRYPT_PHASE_HOOK is not None:
                    _REENCRYPT_PHASE_HOOK(conn)

                now = _now()
                for row_id, row_version, new_cipher in batch:
                    try:
                        conn.execute(
                            "UPDATE credentials SET api_key_cipher=?, dek_version=?, "
                            "row_version=row_version+1, updated_at=? "
                            "WHERE id=? AND row_version=?",
                            (new_cipher, target_dek, now, row_id, row_version),
                        )
                    except sqlite3.Error as exc:
                        # A locked database is transient: another writer
                        # committed after this batch read its rows, so the
                        # snapshot this transaction holds is stale.  The
                        # batch rolls back and the caller retries.
                        raise StoreError(f"update row {row_id}: {exc}", cause=exc) from exc
                    # A row count of zero means a concurrent admin write
                    # advanced the row's version after the SELECT.  The
                    # row is already in the target state and must not be
                    # treated as a straggler, so it is skipped silently.
        return len(batch)
