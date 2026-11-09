"""The two ends of the sync: what is being synchronised, and where it lands.

The Go original is ``internal/credmgr/etcdsync/etcdsync.go``.

The vocabulary the sync loop is written against — the source it reads,
the applier it writes through, the store it remembers its position in —
together with the two adapters this project uses: the credential subtree
as a source, and the local SQLite mirror as an applier.  The sync logic
itself lives in :mod:`security_gateway.credmgr.etcdsync.syncer`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import (
    Any,
    Callable,
    Generic,
    Protocol,
    Sequence,
    TypeVar,
    runtime_checkable,
)

from security_gateway.credmgr.etcdstore.entry import ZERO_TIMESTAMP, Entry, Timestamp, unmarshal_entry
from security_gateway.credmgr.etcdstore.keys import proxy_key_from_cred_key
from security_gateway.credmgr.etcdstore.watch import (
    ErrNoWatch,
    Watcher,
    WatcherSource,
)
from security_gateway.credmgr.store import NotFoundError, SourceCredential, SyncStateEmptyError

__all__ = [
    "DEFAULT_LIVENESS_INTERVAL",
    "DEFAULT_LIVENESS_TIMEOUT",
    "DEFAULT_RESYNC_BACKOFF_MAX",
    "DEFAULT_RESYNC_BACKOFF_MIN",
    "Applier",
    "CredSource",
    "Listing",
    "Listed",
    "Phase",
    "RevisionStore",
    "Source",
    "Stats",
    "StoreApplier",
    "StoreRevisionStore",
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


def _unix_seconds(stamp: Timestamp) -> int:
    """The timestamp as unix seconds, with the zero time mapped to 0."""
    if stamp == ZERO_TIMESTAMP:
        return 0
    return stamp.unix_seconds()


class CredSource:
    """The credential subtree as a source.

    The watch capability is separate from the store: a store built
    without one can still list; asking it for a watch is a wiring bug.
    """

    def __init__(self, store: Any, watch_source: WatcherSource | None = None) -> None:
        self._store = store
        self._watch_source = watch_source

    def namespace(self) -> str:
        """The namespace this source reads."""
        return str(self._store.ns)

    def list_entries(self, limit: int = 0) -> Listing[Entry]:
        """Every credential entry, plus the snapshot revision."""
        listed, revision = self._store.list_entries(limit)
        return Listing(
            items=tuple(Listed(key=item.proxy_key, value=item.entry) for item in listed),
            revision=int(revision),
        )

    def watch(self, rev: int) -> Watcher:
        """Stream changes under the namespace's credential subtree.

        Raises :class:`~security_gateway.credmgr.etcdstore.watch.ErrNoWatch`
        when the source was built without a watch capability.
        """
        if self._watch_source is None:
            raise ErrNoWatch()
        return self._watch_source.watch_creds(self.namespace(), rev)

    def key_of(self, key: str) -> str:
        """The proxy key a full credential key carries."""
        return proxy_key_from_cred_key(self.namespace(), key)

    def decode(self, value: bytes, mod_revision: int) -> Entry:
        """Parse a watch event's value into an entry."""
        entry = unmarshal_entry(value)
        entry.mod_revision = int(mod_revision)
        return entry


class StoreApplier:
    """The local SQLite mirror of the credential subtree.

    It turns the entries the source reports into the local store's own
    shape and hands them to the store's reconciliation primitives.
    """

    def __init__(
        self,
        store: Any,
        decryptable: Callable[[int], bool] | None = None,
    ) -> None:
        self._store = store
        self._decryptable = decryptable

    def reconcile(self, listed: Sequence[Listed[Entry]]) -> None:
        """Make the local credentials table an exact mirror of the source."""
        self._store.reconcile_credentials_from_source([self._source_credential(item) for item in listed])

    def apply_upsert(self, key: str, item: Entry) -> None:
        """Write one entry into the local table."""
        self._store.upsert_credential_from_source(self._source_credential(Listed(key=key, value=item)))

    def apply_delete(self, key: str, mod_revision: int) -> None:
        """Remove one entry from the local table.

        A late delete must not remove a row written again afterwards, so
        the local row's revision is compared against the delete's.
        Removing an absent row is success.
        """
        try:
            row = self._store.get_credential_by_proxy_key(key)
        except NotFoundError:
            return
        if row.row_version > int(mod_revision):
            return
        self._store.delete_credential_by_proxy_key(key)

    def _source_credential(self, item: Listed[Entry]) -> SourceCredential:
        """The local store's shape of one entry."""
        entry = item.value
        return SourceCredential(
            proxy_key=item.key,
            user_id=entry.user_id,
            api_base=entry.api_base,
            key_tag=entry.key_tag,
            api_key_cipher=entry.api_key_cipher,
            auth_type=entry.auth_type,
            dek_version=entry.dek_version,
            mod_revision=entry.mod_revision,
            created_at=_unix_seconds(entry.created_at),
            updated_at=_unix_seconds(entry.updated_at),
            skip_update=not self._can_decrypt(entry.dek_version),
        )

    def _can_decrypt(self, dek_version: int) -> bool:
        """Whether this node can open an entry written under that key."""
        if self._decryptable is None:
            return True
        return bool(self._decryptable(int(dek_version)))


class StoreRevisionStore:
    """The local store's sync state as the sync loop's revision store.

    A revision of 0 means "never synced", which forces a full listing: a
    watch from revision 0 would replay all history. The store's own
    bookkeeping only moves the marker forward, so a save that arrives
    out of order is ignored rather than treated as an error.
    """

    def __init__(self, store: Any) -> None:
        self._store = store

    def load_applied_rev(self) -> int:
        """The last revision fully applied, or 0 when nothing has been."""
        try:
            return int(self._store.load_applied_rev())
        except SyncStateEmptyError:
            return 0

    def save_applied_rev(self, rev: int) -> None:
        """Record ``rev`` as fully applied."""
        self._store.save_applied_rev(int(rev))
