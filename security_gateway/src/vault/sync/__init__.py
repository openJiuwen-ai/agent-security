"""The two ends of the sync: what is being synchronised, and where it lands.

The Go original is ``internal/credmgr/etcdsync/etcdsync.go``.

The vocabulary the sync loop is written against — the source it reads,
the applier it writes through, the store it remembers its position in —
The sync logic itself lives in :mod:`security_gateway.vault.sync.loop`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import (
    Generic,
    Protocol,
    Sequence,
    TypeVar,
    runtime_checkable,
)

from security_gateway.vault.etcdstore.watch import Watcher

__all__ = [
    "DEFAULT_LIVENESS_INTERVAL",
    "DEFAULT_LIVENESS_TIMEOUT",
    "DEFAULT_RESYNC_BACKOFF_MAX",
    "DEFAULT_RESYNC_BACKOFF_MIN",
    "Applier",
    "Listing",
    "Listed",
    "Phase",
    "RevisionStore",
    "Source",
    "Stats",
    "SyncError",
]

#: How long the watch stream may go without a single response before it
#: is declared dead and a full resync is forced.
#:
#: The threshold tracks etcd's progress-notify interval, which the server
#: defaults to 10 minutes; 15 minutes tolerates two missed notifications,
#: and the 1-minute check interval keeps detection inside the window a
#: stale revoked credential would be serving.
DEFAULT_LIVENESS_TIMEOUT = 15 * 60.0

#: How often the liveness deadline is checked.
DEFAULT_LIVENESS_INTERVAL = 60.0

#: The shortest wait between two failed reconciliations.
DEFAULT_RESYNC_BACKOFF_MIN = 0.1

#: The longest wait between two failed reconciliations.
DEFAULT_RESYNC_BACKOFF_MAX = 30.0

#: The item a source carries.  It is generic because the sync logic is the
#: same whatever is being synchronised.
ItemT = TypeVar("ItemT")


class SyncError(RuntimeError):
    """A failure inside the sync loop.

    It carries the context the underlying error was wrapped with, so the
    reason a resync happened is still visible in the log.
    """


@dataclass(frozen=True)
class Listed(Generic[ItemT]):
    """One item in a namespace: the key it is stored under and its value.

    The key travels with the value because a consumer that writes each
    item back into a keyed store cannot do its job without it.
    """

    #: The item's key — the proxy key, for the credential subtree.
    key: str

    #: The decoded value.
    value: ItemT


@dataclass(frozen=True)
class Listing(Generic[ItemT]):
    """A full listing, and the snapshot revision it was taken at.

    The revision is the consistent point the listing was taken at: it is
    what the sync loop persists as its position and later resumes from.
    """

    #: Every item in the namespace.
    items: tuple[Listed[ItemT], ...] = ()

    #: The revision the listing was taken at.
    revision: int = 0


@runtime_checkable
class Source(Protocol[ItemT]):
    """The etcd side of the sync.

    It is generic over the shape of the item it carries, because the
    sync logic is the same whatever is being synchronised.
    """

    def namespace(self) -> str:
        """Identify the subtree this sync owns."""
        ...

    def list_entries(self, limit: int = 0) -> Listing[ItemT]:
        """Every item, plus the consistent snapshot revision."""
        ...

    def watch(self, rev: int) -> Watcher:
        """Stream changes after ``rev``."""
        ...

    def key_of(self, key: str) -> str:
        """Turn a watch event's key back into the item's key."""
        ...

    def decode(self, value: bytes, mod_revision: int) -> ItemT:
        """Parse a watch event's value."""
        ...


@runtime_checkable
class Applier(Protocol[ItemT]):
    """Materialises remote state into local state.

    Every method must be idempotent with respect to the key argument:
    resyncs and watch replays both re-deliver state already applied.
    """

    def reconcile(self, listed: Sequence[Listed[ItemT]]) -> None:
        """Make local state match ``listed`` exactly."""
        ...

    def apply_upsert(self, key: str, item: ItemT) -> None:
        """Materialise one item, replacing any existing row for its key."""
        ...

    def apply_delete(self, key: str, mod_revision: int) -> None:
        """Remove the local materialisation of a key.

        Deleting something already absent must succeed. The revision is
        the authority's: a late delete must not remove a row that was
        written again afterwards.
        """
        ...


@runtime_checkable
class RevisionStore(Protocol):
    """Persists how far the sync has got.

    It lets a restart resume from a known revision instead of re-listing
    the whole namespace.
    """

    def load_applied_rev(self) -> int:
        """The last revision fully applied, or 0 when nothing has been.

        A revision of 0 means "never synced", which is deliberately not
        an error: the caller must then do a full listing.
        """
        ...

    def save_applied_rev(self, rev: int) -> None:
        """Record ``rev`` as fully applied.

        It must not return until the value is durable: a revision lost
        on a crash would make the next start skip the events in between.
        """
        ...


class Phase(Enum):
    """How far along a sync is."""

    #: No full sync has completed yet: either the process just started,
    #: or etcd has been unreachable since.
    INITIALIZING = "initializing"

    #: A full sync completed and a watch is live.
    STEADY = "steady"

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class Stats:
    """A point-in-time snapshot of sync progress.

    It is what the admin health payload reports about the etcd keyspace.
    """

    #: How far along the sync is.
    phase: Phase = Phase.INITIALIZING

    #: The highest revision known to be fully applied.
    last_applied_rev: int = 0

    #: When a response last arrived on the watch stream. When it falls
    #: further behind than the liveness timeout while the phase is
    #: steady, the stream is treated as dead and a resync is forced.
    last_progress_at: datetime | None = None

    #: When the last full sync completed.
    synced_at: datetime | None = None

    #: How many full reconciliations have happened since the start.
    resync_count: int = 0

    #: Why the most recent watch stream ended. Empty before the first
    #: stream has run.
    last_stop_reason: str = ""

    #: The most recent error, cleared on the next success.
    last_error: str = ""
