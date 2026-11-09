"""Materialise etcd credential state onto the local sqlite copy.

The Go original is ``internal/credmgr/etcdsync/sqliteapplier``.  It is
the seam between the ``etcdsync`` engine and the local sqlite store: the
engine knows about etcd, the store knows about rows, and neither knows
about the other.

Two behaviours are load-bearing.

**Entries sealed under a newer DEK are withheld, not dropped.**  A node
behind a rotation cannot open an entry sealed under the new generation:
writing it would leave a row the node knows it cannot decrypt, and
dropping it would let the reconcile purge delete the still valid older
row.  Either way turns "this node is late on the rotation" into an
outage.  So the entry is marked present-but-unchanged instead.

**Every applied mutation drops the cached plaintext.**  The proxy answers
from the cache, so a revoked credential would keep being served until the
TTL expires unless the cache is invalidated together with the row.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Sequence

from security_gateway.credmgr.etcdstore.entry import ZERO_TIMESTAMP, Entry, Timestamp
from security_gateway.credmgr.etcdsync import Listed
from security_gateway.credmgr.store import SourceCredential

_log = logging.getLogger(__name__)

__all__ = ["Applier", "from_entry"]


class Applier:
    """Apply etcd credential entries onto the local sqlite store.

    It satisfies the ``etcdsync.Applier`` protocol, and every method is
    idempotent: a resync and a watch replay re-deliver applied state.
    """

    def __init__(self, store: object, local_dek_version: Callable[[], int]) -> None:
        """Build an applier writing through ``store``.

        ``local_dek_version`` is required; passing ``None`` is a wiring
        bug rather than a documented "unlimited" mode: without it the
        applier cannot tell a decryptable entry from an undecryptable
        one.
        """
        if store is None:
            raise ValueError("sqliteapplier: nil store")
        if local_dek_version is None:
            raise ValueError("sqliteapplier: nil local DEK version reader")
        self._store = store
        self._local_dek_version = local_dek_version
        self._invalidate: Callable[[str], None] | None = None
        self._tombstone: Callable[[str], None] | None = None
        self._skipped = 0
        self._lock = threading.Lock()

    def with_cache_invalidation(
        self,
        invalidate: Callable[[str], None] | None,
        tombstone: Callable[[str], None] | None,
    ) -> "Applier":
        """Wire the cache hooks the constructor cannot require."""
        self._invalidate = invalidate
        self._tombstone = tombstone
        return self

    # -- the counters ------------------------------------------------------

    def skipped_newer_dek(self) -> int:
        """How many withhold decisions have been made.

        It counts decisions, not distinct credentials: every reconcile
        re-counts the entries still waiting for this node's DEK, so a
        growing counter after a rotation means this node never picked up
        its new DEK.
        """
        with self._lock:
            return int(self._skipped)

    def _count_skipped(self, count: int) -> None:
        if count <= 0:
            return
        with self._lock:
            self._skipped += int(count)

    # -- the cache hooks ---------------------------------------------------

    def _drop_cache(self, proxy_key: str) -> None:
        """Drop the cached plaintext for ``proxy_key``."""
        if self._invalidate is not None:
            self._invalidate(proxy_key)

    def _mark_deleted(self, proxy_key: str) -> None:
        """Mark ``proxy_key`` deleted in the cache."""
        if self._tombstone is not None:
            self._tombstone(proxy_key)
            return
        self._drop_cache(proxy_key)

    # -- the applier protocol ---------------------------------------------

    def reconcile(self, listed: Sequence[Listed[Entry]]) -> None:
        """Make the local table match ``listed`` exactly."""
        local = int(self._local_dek_version())
        entries: list[SourceCredential] = []
        withheld = 0
        for item in listed:
            record = from_entry(item.key, item.value, local)
            if record.skip_update:
                withheld += 1
            entries.append(record)
        if withheld > 0:
            self._count_skipped(withheld)
            _log.debug(
                "etcd sync: withholding credentials encrypted with a newer DEK",
                extra={"count": withheld, "local_dek_version": local},
            )
        purged = self._store.reconcile_credentials_from_source_with_purged(entries)
        # Every entry that was actually applied needs its cache dropped,
        # not only the purged ones: a row that was withheld has usually
        # been looked up since, and that lookup cached the miss — so
        # reconciling it in changes the store but not what the proxy
        # answers.  Withheld entries are skipped: they were not applied.
        for record in entries:
            if not record.skip_update:
                self._drop_cache(record.proxy_key)
        # Purged rows are gone from the authority, so anything the cache
        # still holds for them is stale plaintext.
        for key in purged or ():
            self._mark_deleted(key)

    def apply_upsert(self, proxy_key: str, entry: Entry) -> None:
        """Materialise one credential."""
        local = int(self._local_dek_version())
        record = from_entry(proxy_key, entry, local)
        if record.skip_update:
            _log.debug(
                "etcd sync: withholding credential encrypted with a newer DEK",
                extra={
                    "proxy_key": record.proxy_key,
                    "entry_dek_version": record.dek_version,
                    "local_dek_version": local,
                },
            )
            self._count_skipped(1)
            return
        self._store.upsert_credential_from_source(record)
        # Invalidate rather than tombstone: the credential still exists,
        # only its ciphertext moved.  A tombstone would 401 a live key.
        self._drop_cache(record.proxy_key)

    def apply_delete(self, proxy_key: str, mod_revision: int) -> None:
        """Remove the local materialisation of ``proxy_key``."""
        self._store.delete_credential_by_proxy_key(proxy_key)
        self._mark_deleted(proxy_key)


def from_entry(proxy_key: str, entry: Entry, local_dek: int) -> SourceCredential:
    """Convert one etcd entry into the row the local mirror stores."""
    if entry is None:
        raise ValueError("sqliteapplier: nil etcd entry")
    return SourceCredential(
        proxy_key=proxy_key,
        user_id=entry.user_id,
        api_base=entry.api_base,
        key_tag=entry.key_tag,
        api_key_cipher=entry.api_key_cipher,
        auth_type=entry.auth_type,
        dek_version=int(entry.dek_version),
        mod_revision=int(entry.mod_revision),
        created_at=_unix_seconds(entry.created_at),
        updated_at=_unix_seconds(entry.updated_at),
        skip_update=int(entry.dek_version) > int(local_dek),
    )


def _unix_seconds(value: Timestamp | None) -> int:
    """Convert an etcd timestamp to the unix-second form the local table uses."""
    if value is None:
        return 0
    if getattr(value, "text", "") == ZERO_TIMESTAMP.text:
        return 0
    return int(value.unix_seconds())
