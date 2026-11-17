"""Waking a wrapping loop before its timer does.

A watch removes the wait for the tick without removing the tick.  The
loop watches two things — the authority's DEK generation key and the
prefix every pending handover request lives under — and starts a round
the moment either moves.  The timer stays as the backstop for the cases
a watch cannot cover: a store built without watch support, a stream
that ends, a compaction.

The shape of the two channels
----------------------------

Python has no channels, so this package uses a :class:`queue.Queue`
with room for exactly one item.  One item is the whole point: a loop
that is already awake needs one reason to run again, not a queue of
reasons.  A second wake-up that arrives while the first is still
pending is dropped, and the loop runs once for both.

The same queue is what the timer and the wake are merged into, so a
caller waits on one queue instead of selecting over two.

What is *not* here
------------------

There is no context.  The Python etcd client is synchronous and has no
context to thread, and a cancellation is expressed by closing the
client.  The watch threads here are daemons: they end when the store's
stream ends, and they never keep the interpreter alive.
"""

from __future__ import annotations

import logging
import queue
import threading
from typing import Any, Protocol, runtime_checkable

from security_gateway.vault.etcdstore.watch import ErrNoWatch, Watcher

__all__ = [
    "ClusterWatchStore",
    "drain_watch",
    "start_rounds",
    "start_ticks",
    "wake",
]

_log = logging.getLogger(__name__)

#: How long a drain waits for the next response before looking again.
#:
#: The wait is what lets the drain notice that its stream ended rather
#: than blocking on a stream that will never deliver again. It is short
#: enough to be invisible next to a tick and long enough not to spin.
_WATCH_POLL_INTERVAL = 0.1


@runtime_checkable
class ClusterWatchStore(Protocol):
    """What :func:`wake` needs of the authority's store.

    The protocol is separate from the store's own type so that a fake in
    a test can stand in for the store without dragging the whole etcd
    seam along, and so that a store built without watch support is a
    missing method rather than a wrong type.
    """

    def watch_generation(self) -> Watcher:
        """Stream changes to the authority's DEK generation key."""
        ...

    def watch_handover_requests(self) -> Watcher:
        """Stream changes under the pending-request prefix."""
        ...


def wake(store: Any | None) -> queue.Queue[None] | None:
    """Return a queue that receives when something the loop acts on changes."""
    if store is None:
        return None
    out: queue.Queue[None] = queue.Queue(maxsize=1)
    streams = 0
    for name, opener in (
        ("generation", getattr(store, "watch_generation", None)),
        ("handover requests", getattr(store, "watch_handover_requests", None)),
    ):
        if opener is None:
            # A store that cannot watch at all: the timer is the only
            # mechanism, which is the Go's behaviour for such a store.
            continue
        try:
            watcher = opener()
        except ErrNoWatch:
            continue
        except Exception as exc:  # noqa: BLE001 - a broken watch is not fatal
            # A watch that cannot be opened is no worse than one that
            # was never there: the timer still backs the loop up. It is
            # worth saying so, because a watch that silently stops
            # working is how a rotation ends up waiting a tick.
            _log.warning(
                "cannot watch for cluster changes; the timer is the only mechanism",
                extra={"watch": name, "error": exc},
            )
            continue
        streams += 1
        threading.Thread(
            target=drain_watch,
            args=(watcher, out),
            name=f"clusterkey-wake-{name}",
            daemon=True,
        ).start()
    if streams == 0:
        return None
    return out


def drain_watch(watcher: Watcher, out: queue.Queue[None]) -> None:
    """Turn a watch stream into wake-ups, one pending wake-up at a time."""
    try:
        while True:
            response = watcher.recv(timeout=_WATCH_POLL_INTERVAL)
            if response is None:
                if watcher.ended:
                    return
                continue
            if response.error is not None or not response.events:
                continue
            _offer(out)
    finally:
        watcher.close()


def start_ticks(interval: float, stop: threading.Event) -> queue.Queue[Any]:
    """Return a queue that receives a tick every ``interval`` seconds."""
    ticks: queue.Queue[Any] = queue.Queue(maxsize=1)

    def pump() -> None:
        """Pump."""
        while not stop.wait(interval):
            _offer(ticks)

    threading.Thread(
        target=pump,
        name="clusterkey-ticks",
        daemon=True,
    ).start()
    return ticks


def start_rounds(
    timer: queue.Queue[Any] | None,
    wake_queue: queue.Queue[None] | None,
) -> queue.Queue[None]:
    """Return a queue that fires on every timer tick and on every wake."""
    rounds: queue.Queue[None] = queue.Queue(maxsize=1)
    if timer is not None:
        threading.Thread(
            target=_pump_timer,
            args=(timer, rounds),
            name="clusterkey-rounds-timer",
            daemon=True,
        ).start()
    if wake_queue is not None:
        threading.Thread(
            target=_pump_wake,
            args=(wake_queue, rounds),
            name="clusterkey-rounds-wake",
            daemon=True,
        ).start()
    return rounds


def _pump_timer(timer: queue.Queue[Any], rounds: queue.Queue[None]) -> None:
    """Forward every timer tick to the rounds queue."""
    while True:
        try:
            timer.get()
        except Exception:  # noqa: BLE001 - a closed timer ends the pump
            return
        _offer(rounds)


def _pump_wake(wake_queue: queue.Queue[None], rounds: queue.Queue[None]) -> None:
    """Forward every wake-up to the rounds queue."""
    while True:
        try:
            wake_queue.get()
        except Exception:  # noqa: BLE001 - a closed wake ends the pump
            return
        _offer(rounds)


def _offer(rounds: queue.Queue[Any]) -> None:
    """Mark a round as due, dropping it when one is already due."""
    try:
        rounds.put_nowait(None)
    except queue.Full:
        return
