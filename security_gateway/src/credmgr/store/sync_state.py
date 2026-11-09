"""Where the etcd watch got to.

The Go original is ``internal/credmgr/store/sync_state.go``.

The table is a singleton row: there is exactly one etcd keyspace per
node, hence exactly one watch position.  A revision of 0 means "never
synced", which is deliberately not an error — the caller must then do a
full listing rather than an incremental watch.
"""

from __future__ import annotations

import sqlite3

from .clock import now as _now
from .errors import InvalidError, StoreError, SyncStateEmptyError

__all__ = [
    "SYNC_STATE_ID",
    "SyncStateMethods",
]

#: The singleton key of the sync_state table.
SYNC_STATE_ID = 1


class SyncStateMethods:
    """The applied-revision bookkeeping, mixed into :class:`~.store.Store`."""

    def load_applied_rev(self) -> int:
        """Return the revision this node has already materialised.

        Raises :class:`~.errors.SyncStateEmptyError` — a kind of
        not-found — when the singleton row is absent.
        """
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                "SELECT last_applied_rev FROM sync_state WHERE id = ?",
                (SYNC_STATE_ID,),
            ).fetchone()
        if row is None:
            raise SyncStateEmptyError("the sync_state row is missing")
        return int(row[0])

    def save_applied_rev(self, rev: int) -> None:
        """Record how far the watch has been applied."""
        if rev < 0:
            raise InvalidError(f"the applied revision must be non-negative, got {rev}")
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            try:
                conn.execute(
                    "UPDATE sync_state SET last_applied_rev = ?, updated_at = ? WHERE id = ? AND last_applied_rev <= ?",
                    (rev, _now(), SYNC_STATE_ID, rev),
                )
            except sqlite3.Error as exc:  # pragma: no cover - defensive
                raise StoreError(f"save the applied revision: {exc}", cause=exc) from exc

    def applied_rev_at_least(self, rev: int) -> bool:
        """Report whether the stored revision has already reached ``rev``."""
        try:
            current = self.load_applied_rev()
        except SyncStateEmptyError:
            return False
        return current >= rev
