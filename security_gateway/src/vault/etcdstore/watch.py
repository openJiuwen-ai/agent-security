"""The watch over the credential subtree.

The Python client has no response type: its ``watch_prefix`` hands out an
iterator of events, one per change, with no batch and no header. So the
shapes the sync loop consumes are defined here — a response that carries
its events, its header revision and, when something went wrong, the
error — and the real watcher pumps the client's iterator into them.

The seam is deliberately narrow: a fake only has to push responses into a
queue it owns, which is what makes the sync loop's gap, compaction and
reconnect logic testable without an etcd server.

Two properties of the watch are load-bearing:

* The revision a watch starts at is **inclusive**. Passing the last
  applied revision would re-deliver events that are already in local
  state, so the caller passes ``last applied + 1``.
* The stream carries progress notifications. They are the only signal
  that distinguishes a quiet cluster from a silently dead stream — a
  half-open socket or a wedged proxy leaves the server delivering into a
  void while the reader sits waiting. The sync loop's liveness guard
  exists because of them.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Iterator, Protocol, runtime_checkable

from .errors import CompactedError, EtcdStoreError, remap_compacted
from .keys import creds_prefix, handover_request_prefix, records_prefix

__all__ = [
    "ClusterWatcherSource",
    "ErrNoWatch",
    "RealWatcher",
    "RealWatcherSource",
    "WatchEvent",
    "WatchEventType",
    "WatchResponse",
    "Watcher",
    "WatcherSource",
    "is_compacted",
]


class ErrNoWatch(EtcdStoreError):
    """Raised when a watch is asked for on a store built without one."""

    def __init__(
        self,
        message: str = "etcdstore: watch not available on this Store",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class WatchEventType(Enum):
    """What happened to a key: ``PUT`` for a write, ``DELETE`` for a removal."""

    PUT = "put"
    DELETE = "delete"


@dataclass(frozen=True)
class WatchEvent:
    """One change under the watched prefix.

    The key is bytes because that is what the etcd client delivers; the
    sync loop turns it into a string only where the keyspace layout
    demands one.
    """

    #: The key that changed.
    key: bytes = b""

    #: The value the key now holds. Empty for a delete.
    value: bytes = b""

    #: The revision the change was made at.
    mod_revision: int = 0

    #: Whether the key was written or removed.
    type: WatchEventType = WatchEventType.PUT

    #: The key's creation version, as etcd reports it.
    version: int = 0

    #: The value the key held before the change, when the client was
    #: asked for it.
    prev_value: bytes | None = None


@dataclass(frozen=True)
class WatchResponse:
    """One answer from the watch stream.

    The events it carries, the revision the stream had reached when it
    was produced, and the error that ended it, if any.
    """

    #: The revision the stream had reached.
    header_revision: int = 0

    #: The changes this response carries.
    events: tuple[WatchEvent, ...] = ()

    #: The failure that ended the stream, when one did.
    error: BaseException | None = None

    #: Whether this response is a progress notification: the server
    #: telling the reader that it is alive and that everything up to
    #: ``header_revision`` has been delivered.
    progress_notify: bool = False

    #: Whether this response only acknowledges that the watch was
    #: established. It carries no events, and crediting its header would
    #: claim progress past changes that are still in flight.
    created: bool = False


@runtime_checkable
class Watcher(Protocol):
    """A live watch stream over a credential prefix.

    It is the minimal shape ``etcdsync`` consumes: a way to take the
    next response, a way to ask whether the stream has ended, and a way
    to shut the stream down.
    """

    def recv(self, timeout: float | None = None) -> WatchResponse | None:
        """The next response, or ``None`` when none arrived in time.

        A ``None`` answer means either the timeout expired or the stream
        has ended; :attr:`ended` says which.
        """
        ...

    @property
    def ended(self) -> bool:
        """Whether the stream has ended."""
        ...

    def close(self) -> None:
        """Shut the stream down."""
        ...


@runtime_checkable
class WatcherSource(Protocol):
    """Opens watcher streams over a namespace's credential subtree."""

    def watch_creds(self, ns: str, rev: int = 0) -> Watcher:
        """Stream changes under the namespace's credential subtree."""
        ...


@runtime_checkable
class ClusterWatcherSource(Protocol):
    """Opens the two streams a cluster wrapping loop reacts to.

    The authority's DEK generation key, and the prefix every pending
    handover request lives under. A loop that watches both learns about
    a rotation or a peer request without waiting for its timer.
    """

    def watch_generation(self, ns: str) -> Watcher:
        """Stream changes to the namespace's DEK generation key."""
        ...

    def watch_handover_requests(self, ns: str) -> Watcher:
        """Stream changes under the namespace's handover request prefix."""
        ...


def is_compacted(exc: BaseException | None) -> bool:
    """Report whether an error is etcd's "revision has been compacted".

    The etcd client is an optional extra and cannot be imported here, so
    the check is by the package's own sentinel and by the message.
    """
    if exc is None:
        return False
    if isinstance(exc, CompactedError):
        return True
    return "compacted" in str(exc).lower()


def _event_type(raw: Any, value: bytes | None = None) -> WatchEventType:
    """The kind of change an etcd client event describes.

    The clients disagree on how they say it: one hands over an enum with
    a ``name``, another hands over the string, and the one this package
    speaks to says nothing at all and reports a delete by leaving the
    value empty. A delete that is read as a put leaves a revoked
    credential in the mirror, so the empty value counts as a delete.
    """
    if isinstance(raw, int) and not isinstance(raw, bool):
        # The protobuf EventType: 0 is a put, 1 is a delete.
        return WatchEventType.DELETE if raw == 1 else WatchEventType.PUT
    name = getattr(raw, "name", None)
    if isinstance(name, str):
        text = name
    elif isinstance(raw, str):
        text = raw
    else:
        text = ""
    if text.strip().upper().startswith("DELETE"):
        return WatchEventType.DELETE
    # An empty value is how the client reports a delete, and this package
    # never stores an empty value, so the two cannot be confused.
    if not value:
        return WatchEventType.DELETE
    return WatchEventType.PUT


def response_from_event(event: Any) -> WatchResponse:
    """Turn one client event into a watch response."""
    key = getattr(event, "key", b"") or b""
    raw_value = getattr(event, "value", None)
    if isinstance(raw_value, (bytes, bytearray)):
        value = bytes(raw_value)
    else:
        value = b""
    mod_revision = int(getattr(event, "mod_revision", 0) or 0)
    version = int(getattr(event, "version", 0) or 0)
    prev_value = getattr(event, "prev_value", None)
    if isinstance(prev_value, (bytes, bytearray)):
        prev_value = bytes(prev_value)
    else:
        prev_value = None
    # Clients spell the two control answers differently, and some of them
    # deliver a progress notification as a bare event with no key at all.
    progress = bool(
        getattr(event, "progress_notify", False)
        or getattr(event, "is_progress_notify", False)
    )
    created = bool(
        getattr(event, "created", False) or getattr(event, "is_create", False)
    )
    if not key and not value:
        # Nothing happened: the server is either confirming the watch or
        # saying it is still there. Emitting an empty change would make
        # the mirror treat a heartbeat as a write.
        return WatchResponse(
            header_revision=mod_revision, progress_notify=progress, created=created
        )
    return WatchResponse(
        header_revision=mod_revision,
        events=(
            WatchEvent(
                key=bytes(key),
                value=value,
                mod_revision=mod_revision,
                type=_event_type(getattr(event, "type", None), raw_value),
                version=version,
                prev_value=prev_value,
            ),
        ),
        progress_notify=progress,
        created=created,
    )


def responses_from_item(item: Any) -> tuple[WatchResponse, ...]:
    """Turn one item from the client's watch iterator into responses.

    The client yields ``WatchResponse`` messages whose ``events`` are the
    changes, and a message with no events is a progress notification:
    the server saying it is still there. Other clients hand out the bare
    events instead, so both shapes are accepted.
    """
    changes = getattr(item, "events", None)
    if changes is None:
        return (response_from_event(item),)
    header = getattr(item, "header", None)
    revision = int(getattr(header, "revision", 0) or 0)
    created = bool(getattr(item, "created", False))
    if getattr(item, "canceled", False):
        # The server ended the stream. A compaction says the revision we
        # follow is gone (the caller must re-LIST); any other cancel is a
        # dead stream, not a heartbeat.
        compacted = int(getattr(item, "compact_revision", 0) or 0)
        message = f"etcdstore: watch canceled (compact revision {compacted})"
        return (WatchResponse(header_revision=revision, error=CompactedError(message)),)
    if not changes:
        # No events: either the watch was just established or the server
        # is proving it is still alive. Either way nothing changed, and
        # reporting an empty change would look like a write.
        # ``created`` says the stream was established; ``progress_notify``
        # says an established stream proved it is alive. The two are
        # different signals and must not be conflated.
        return (
            WatchResponse(
                header_revision=revision,
                progress_notify=not created,
                created=created,
            ),
        )
    responses = []
    for event in changes:
        response = response_from_event(event)
        if revision:
            response = WatchResponse(
                header_revision=revision,
                events=response.events,
                error=response.error,
                progress_notify=response.progress_notify,
                created=created or response.created,
            )
        responses.append(response)
    return tuple(responses)


class RealWatcher:
    """A watch stream over the etcd client's event iterator.

    The client also hands out a callable that cancels the watch. It is
    kept because it is the only thing that tears the watch down on the
    server: the iterator ending is the server's decision, and a reader
    that stops reading has to say so.
    """

    def __init__(
        self, events: Iterator[Any], cancel: Callable[[], None] | None = None
    ) -> None:
        self._queue: queue.Queue[WatchResponse | None] = queue.Queue()
        self._ended = threading.Event()
        self._closed = threading.Event()
        self._cancel = cancel
        self._thread = threading.Thread(
            target=self._pump, args=(events,), name="etcd-watch", daemon=True
        )
        self._thread.start()

    def _pump(self, events: Iterator[Any]) -> None:
        try:
            for item in events:
                if self._closed.is_set():
                    break
                for response in responses_from_item(item):
                    self._queue.put(response)
        except BaseException as exc:  # noqa: BLE001 - the failure is data
            # The stream's failure is delivered as a response, not raised
            # at the reader: the reader has to be able to tell a
            # compaction apart from any other failure, and it can only do
            # that if it sees the error as one.
            self._queue.put(WatchResponse(error=remap_compacted(exc)))
        finally:
            self._ended.set()
            self._queue.put(None)

    def recv(self, timeout: float | None = None) -> WatchResponse | None:
        """The next response, or ``None`` when none arrived in time."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def ended(self) -> bool:
        """Whether the stream has ended."""
        return self._ended.is_set()

    def close(self) -> None:
        """Shut the stream down."""
        self._closed.set()
        self._ended.set()
        self._queue.put(None)
        cancel = self._cancel
        if cancel is not None:
            try:
                cancel()
            except Exception:  # noqa: BLE001 - the watch is closing anyway
                pass


class RealWatcherSource:
    """Opens watch streams over the etcd client.

    The client is not imported here: the ``etcd`` extra is optional and
    this package must import cleanly without it. Whatever object is
    handed in only has to offer ``watch_prefix`` and ``watch``.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def watch_creds(self, ns: str, rev: int = 0) -> Watcher:
        """Stream changes under the namespace's credential subtree."""
        return self.watch_prefix(creds_prefix(ns), rev)

    def watch_records(self, ns: str, rev: int = 0) -> Watcher:
        """Stream changes under the namespace's record subtree."""
        return self.watch_prefix(records_prefix(ns), rev)

    def watch_generation(self, ns: str) -> Watcher:
        """Stream changes to the namespace's DEK generation key."""
        from .cluster import generation_key

        return self.watch_key(generation_key(ns))

    def watch_handover_requests(self, ns: str) -> Watcher:
        """Stream changes under the namespace's handover request prefix."""
        return self.watch_prefix(handover_request_prefix(ns))

    def watch_key(self, key: str, rev: int = 0) -> Watcher:
        """Stream changes to a single key, starting at revision ``rev``."""
        return self._open(self._client.watch, key, **self._options(rev))

    def watch_prefix(self, prefix: str, rev: int = 0) -> Watcher:
        """Stream changes under a prefix, starting at revision ``rev``."""
        return self._open(self._client.watch_prefix, prefix, **self._options(rev))

    @staticmethod
    def _options(rev: int) -> dict[str, Any]:
        """The keyword arguments every watch is opened with.

        Progress notifications are requested because they are the only
        proof a stream is still alive: without them a watch that the
        server silently stopped feeding looks exactly like an idle
        namespace, and the reconcile loop never notices the difference.
        """
        options: dict[str, Any] = {"progress_notify": True}
        if rev > 0:
            options["start_revision"] = rev
        return options

    @staticmethod
    def _open(opener: Any, *args: Any, **kwargs: Any) -> RealWatcher:
        """Open a watch through the client and wrap what it hands back."""
        result = opener(*args, **kwargs)
        if isinstance(result, tuple) and len(result) == 2:
            events, cancel = result
        else:
            events, cancel = result, None
        return RealWatcher(events, cancel)
