"""The loop that mirrors the watch into local state.

The Go original is ``internal/credmgr/etcdsync/syncer.go``.

The shape is deliberately flat: watch until something ends the stream,
then reconcile in full, then watch again.  Every abnormal stream exit
takes the same path, which makes the "reconnect without re-listing"
defect impossible to reproduce here.

A resumed node does not re-list: etcd replays everything written since
the stored revision through the watch, so the events missed while the
node was down still arrive.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Generic

from security_gateway.credmgr.etcdstore.watch import (
    Watcher,
    WatchEventType,
    WatchResponse,
    is_compacted,
)

from .etcdsync import (
    DEFAULT_LIVENESS_INTERVAL,
    DEFAULT_LIVENESS_TIMEOUT,
    DEFAULT_RESYNC_BACKOFF_MAX,
    DEFAULT_RESYNC_BACKOFF_MIN,
    Applier,
    ItemT,
    Phase,
    RevisionStore,
    Source,
    Stats,
    SyncError,
)

__all__ = ["Config", "Syncer", "response_revision"]

#: How often the watch loop looks at the stop flag and the resync
#: request while it waits for the next response.
#:
#: Python has no ``select`` over three channels at once, so the loop wakes
#: up this often to check the two things it cannot block on. The value is
#: small enough to be invisible and large enough not to spin.
_POLL_INTERVAL = 0.05


def response_revision(resp: WatchResponse) -> int:
    """The revision a single response may be credited with."""
    if resp.events:
        return resp.events[-1].mod_revision
    if resp.progress_notify and not resp.created:
        return resp.header_revision
    return 0


@dataclass
class Config:
    """Tunes a sync loop.

    Every unset duration and counter falls back to the ``DEFAULT_*``
    constants, so the zero value is usable.
    """

    #: How long the watch stream may go without a single response
    #: before it is declared dead and a full resync is forced.
    liveness_timeout: float = 0.0

    #: How often that deadline is checked.
    liveness_interval: float = 0.0

    #: The retry delay while etcd is unreachable, and its ceiling.
    #:
    #: The sync loop keeps retrying for as long as it is allowed to run;
    #: it never degrades into serving from a half-known state silently,
    #: because the local store keeps serving throughout.
    resync_backoff_min: float = 0.0
    resync_backoff_max: float = 0.0

    #: Bounds one reconciliation listing. 0 means unbounded.
    #:
    #: A non-zero value is treated as a safety assertion, not a tuning
    #: knob: a listing that comes back full is refused rather than
    #: reconciled partially, since a partial view would delete every
    #: credential beyond the cut-off.
    list_limit: int = 0

    #: Overrides the clock; tests use it to drive the liveness deadline
    #: without sleeping.
    now: Callable[[], datetime] | None = None

    #: How often the watch loop checks the stop flag and the resync
    #: request. See :data:`_POLL_INTERVAL`.
    poll_interval: float = _POLL_INTERVAL

    def with_defaults(self) -> "Config":
        """The configuration with every unset value filled in."""
        if self.liveness_timeout <= 0:
            self.liveness_timeout = DEFAULT_LIVENESS_TIMEOUT
        if self.liveness_interval <= 0:
            self.liveness_interval = DEFAULT_LIVENESS_INTERVAL
        if self.resync_backoff_min <= 0:
            self.resync_backoff_min = DEFAULT_RESYNC_BACKOFF_MIN
        if self.resync_backoff_max < self.resync_backoff_min:
            self.resync_backoff_max = DEFAULT_RESYNC_BACKOFF_MAX
        if self.poll_interval <= 0:
            self.poll_interval = _POLL_INTERVAL
        return self


class Syncer(Generic[ItemT]):
    """Mirrors one namespace's items from etcd into local state.

    :meth:`run` blocks until the stop event is set; the caller owns that
    event.
    """

    def __init__(
        self,
        src: Source[ItemT],
        apply: Applier[ItemT],
        revs: RevisionStore,
        cfg: Config | None = None,
    ) -> None:
        self._src = src
        self._apply = apply
        self._revs = revs
        self._cfg = (cfg or Config()).with_defaults()

        self._lock = threading.Lock()
        self._phase = Phase.INITIALIZING

        #: Whether this run continued from a persisted revision, which
        #: decides when the phase may advance: a first sync waits for
        #: the reconciling pass, a resumed one has already reconciled
        #: and only needs its stream back up.
        self._resumed = False
        self._applied_rev = 0
        self._progress_at: datetime | None = None
        self._synced_at: datetime | None = None
        self._resyncs = 0
        self._stop_reason = ""
        self._last_error = ""

        self._liveness_tripped = threading.Event()
        self._resync_requested = threading.Event()

    # -- the loop ---------------------------------------------------------

    def run(self, stop: threading.Event) -> None:
        """Drive the sync until ``stop`` is set.

        It returns ``None``; a failure to read the stored revision at
        all is a start-up failure the caller cannot retry into.
        """
        rev = int(self._revs.load_applied_rev())
        self._set_applied_rev(rev)

        # rev == 0 means this node has never completed a sync, so there
        # is no revision to resume from; starting a watch from 1 would
        # replay the namespace's entire history.
        resumed = rev != 0
        if rev == 0:
            if not self._sync_until_ok(stop):
                return

        with self._lock:
            self._resumed = resumed

        while not stop.is_set():
            self._liveness_tripped.clear()
            self._pump(stop)
            if stop.is_set():
                break
            if not self._sync_until_ok(stop):
                break

    def request_resync(self) -> None:
        """Ask for a rebuild from a fresh listing."""
        self._resync_requested.set()

    def stats(self) -> Stats:
        """A snapshot of the sync's progress, for the health endpoint."""
        with self._lock:
            return Stats(
                phase=self._phase,
                last_applied_rev=self._applied_rev,
                last_progress_at=self._progress_at,
                synced_at=self._synced_at,
                resync_count=self._resyncs,
                last_stop_reason=self._stop_reason,
                last_error=self._last_error,
            )

    # -- one watch stream ------------------------------------------------

    def _pump(self, stop: threading.Event) -> None:
        """Consume one watch stream, returning when it ends."""
        if stop.is_set():
            self._set_stop_reason("context cancelled")
            return
        from_rev = self._current_rev() + 1

        try:
            watcher = self._src.watch(from_rev)
        except BaseException as exc:  # noqa: BLE001 - reported, not raised
            self._set_stop_reason(f"open watch at revision {from_rev}: {exc}")
            return

        try:
            # A resumed node is consuming from a store it had already
            # reconciled, so opening the watch is what completing the
            # sync looks like for it.  Without this it reported
            # "initializing" for its whole life: a resumed node does not
            # resync until its watch breaks, so a healthy restarted node
            # looked permanently un-converged to the health endpoint.
            if self._was_resumed():
                self._mark_steady()

            # The moment the stream opens counts as the first progress.
            # The guard is for a stream that has gone quiet *after* it
            # was established; marking progress at open time keeps an
            # idle cluster from tripping it.
            self._mark_progress()
            self._guard_liveness(watcher, stop)

            while True:
                if stop.is_set():
                    self._set_stop_reason("context cancelled")
                    return
                if self._resync_requested.is_set():
                    # Ending the stream here sends the outer loop into
                    # its normal resync-then-rewatch path.  No stop
                    # reason: every reason that field carries describes
                    # something having gone wrong, and nothing did.
                    self._resync_requested.clear()
                    return

                resp = watcher.recv(timeout=self._cfg.poll_interval)
                if resp is None:
                    if watcher.ended:
                        self._set_stop_reason(self._termination_reason())
                        return
                    continue

                self._mark_progress()
                if resp.error is not None:
                    if is_compacted(resp.error):
                        self._set_stop_reason("compacted: revision no longer retained, resyncing")
                    else:
                        self._set_stop_reason(f"watch error: {resp.error}")
                    return
                try:
                    self._apply_batch(resp)
                except BaseException as exc:  # noqa: BLE001 - reported
                    self._set_error(exc)
                    self._set_stop_reason(f"apply failed, resyncing: {exc}")
                    return
                self._advance(response_revision(resp))
        finally:
            watcher.close()

    def _termination_reason(self) -> str:
        """Why the stream ended."""
        if self._liveness_tripped.is_set():
            return "liveness timeout: no watch response within the deadline, resyncing"
        return "watch channel closed, resyncing"

    def _guard_liveness(self, watcher: Watcher, stop: threading.Event) -> None:
        """Close the watch when no response arrives within the deadline."""

        def loop() -> None:
            """Loop."""
            while not stop.is_set():
                if stop.wait(self._cfg.liveness_interval):
                    return
                if watcher.ended:
                    return
                last = self._progress_at
                if last is None:
                    continue
                if (self._now() - last).total_seconds() > self._cfg.liveness_timeout:
                    self._liveness_tripped.set()
                    watcher.close()
                    return

        threading.Thread(target=loop, name="etcd-sync-liveness", daemon=True).start()

    def _apply_batch(self, resp: WatchResponse) -> None:
        """Apply one response's events."""
        for event in resp.events:
            key = self._src.key_of(event.key.decode("utf-8"))
            if event.type is WatchEventType.PUT:
                try:
                    item = self._src.decode(event.value, event.mod_revision)
                except BaseException as exc:  # noqa: BLE001 - reported
                    raise SyncError(f"decode {key}: {exc}") from exc
                try:
                    self._apply.apply_upsert(key, item)
                except BaseException as exc:  # noqa: BLE001 - reported
                    raise SyncError(f"apply upsert {key}: {exc}") from exc
            elif event.type is WatchEventType.DELETE:
                try:
                    self._apply.apply_delete(key, event.mod_revision)
                except BaseException as exc:  # noqa: BLE001 - reported
                    raise SyncError(f"apply delete {key}: {exc}") from exc

    # -- one reconciliation -----------------------------------------------

    def _resync(self) -> None:
        """Reconcile local state with the whole namespace."""
        try:
            listing = self._src.list_entries(self._cfg.list_limit)
        except BaseException as exc:  # noqa: BLE001 - reported
            raise SyncError(f"etcdsync: list: {exc}") from exc

        # A listing that came back exactly at the limit may be truncated,
        # and reconciling a truncated view would delete every credential
        # past the cut-off.  Refusing is the only safe response.
        if self._cfg.list_limit > 0 and len(listing.items) >= self._cfg.list_limit:
            raise SyncError(
                f"etcdsync: listing returned {len(listing.items)} entries at the "
                f"limit of {self._cfg.list_limit}, refusing to reconcile a "
                "partial view"
            )

        try:
            self._apply.reconcile(listing.items)
        except BaseException as exc:  # noqa: BLE001 - reported
            raise SyncError(f"etcdsync: reconcile: {exc}") from exc

        with self._lock:
            self._resyncs += 1
            self._synced_at = self._now()
            self._phase = Phase.STEADY
            self._last_error = ""
        self._advance(listing.revision)

    def _sync_until_ok(self, stop: threading.Event) -> bool:
        """Retry the reconciliation until it succeeds or the stop is set."""
        delay = self._cfg.resync_backoff_min
        while True:
            try:
                self._resync()
                return True
            except BaseException as exc:  # noqa: BLE001 - reported
                self._set_error(exc)
                if stop.is_set():
                    return False
                if stop.wait(delay):
                    return False
                delay = min(delay * 2, self._cfg.resync_backoff_max)

    # -- bookkeeping -------------------------------------------------------

    def _advance(self, rev: int) -> None:
        """Record that everything up to ``rev`` has been applied."""
        with self._lock:
            if rev <= self._applied_rev:
                return
            self._applied_rev = rev
            self._last_error = ""

        # A failure to persist is not fatal: replaying events after a
        # crash is harmless because every applier method is idempotent.
        try:
            self._revs.save_applied_rev(rev)
        except BaseException as exc:  # noqa: BLE001 - reported
            self._set_error(SyncError(f"etcdsync: persist revision {rev}: {exc}"))

    def _set_applied_rev(self, rev: int) -> None:
        with self._lock:
            self._applied_rev = rev

    def _current_rev(self) -> int:
        with self._lock:
            return self._applied_rev

    def _was_resumed(self) -> bool:
        with self._lock:
            return self._resumed

    def _mark_steady(self) -> None:
        """Advance the phase for a node whose stream is up."""
        with self._lock:
            self._phase = Phase.STEADY
            self._last_error = ""

    def _mark_progress(self) -> None:
        """Note that a response arrived on the stream."""
        with self._lock:
            self._progress_at = self._now()

    def _set_stop_reason(self, reason: str) -> None:
        with self._lock:
            self._stop_reason = reason

    def _set_error(self, exc: BaseException) -> None:
        with self._lock:
            self._last_error = str(exc)

    def _now(self) -> datetime:
        if self._cfg.now is not None:
            return self._cfg.now()
        return datetime.now(timezone.utc)
