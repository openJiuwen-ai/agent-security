"""An in-memory read cache for decrypted records.

The cache sits between the vault's read path and SQLite.  A hit skips the
row lookup and the field decryption; a miss falls through to the store and
installs the decoded record on the way back.

Only plaintext records are cached.  The cache is not a second source of
truth: ``put`` and ``delete`` evict the affected id, a mirror batch clears
the whole cache because it may have changed any row, and a local process
that commits through another connection is detected with SQLite's
``data_version`` counter.  There is no negative cache and no tombstone;
"absent" stays the store's answer.

TODO(cache): if read-side lock contention shows up, make the cached
entries immutable and publish them with a single reference swap so a
hit can skip the lock. The current lock-plus-copy design is for
correctness, not throughput.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Callable

from .record import Record, Value

__all__ = ["RecordCache"]


def _copy_record(record: Record) -> Record:
    """Return a record the caller may mutate without touching the cache."""
    return Record(
        id=record.id,
        fields={
            name: Value(type=value.type, data=bytes(value.data))
            for name, value in record.fields.items()
        },
    )


class RecordCache:
    """A bounded LRU of decrypted records, keyed by record id."""

    def __init__(
        self,
        max_entries: int,
        ttl: float = 0.0,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if max_entries <= 0:
            raise ValueError("vault cache: max_entries must be positive")
        if ttl < 0:
            raise ValueError("vault cache: ttl must not be negative")
        self._max_entries = int(max_entries)
        self._ttl = float(ttl)
        self._clock = clock
        self._lock = threading.Lock()
        self._entries: OrderedDict[str, tuple[float | None, Record]] = OrderedDict()
        self._hits = 0
        self._misses = 0

    def get(self, record_id: str) -> Record | None:
        """Return a copy of the cached record, or None on a miss."""
        with self._lock:
            item = self._entries.get(record_id)
            if item is None:
                self._misses += 1
                return None
            expires_at, record = item
            if expires_at is not None and self._clock() >= expires_at:
                self._entries.pop(record_id, None)
                self._misses += 1
                return None
            self._entries.move_to_end(record_id)
            self._hits += 1
            return _copy_record(record)

    def put(self, record_id: str, record: Record) -> None:
        """Install a record, replacing any older value for the id."""
        expires_at = None if self._ttl <= 0 else self._clock() + self._ttl
        with self._lock:
            self._entries[record_id] = (expires_at, _copy_record(record))
            self._entries.move_to_end(record_id)
            while len(self._entries) > self._max_entries:
                self._entries.popitem(last=False)

    def delete(self, record_id: str) -> None:
        """Evict one id."""
        with self._lock:
            self._entries.pop(record_id, None)

    def clear(self) -> None:
        """Evict every id."""
        with self._lock:
            self._entries.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)

    def stats(self) -> tuple[int, int]:
        """Return ``(hits, misses)``."""
        with self._lock:
            return self._hits, self._misses
