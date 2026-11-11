"""The watch that lets a wrapping loop react before its timer does.

The Go original is ``internal/credmgr/clusterkey/wake_test.go``.
"""

from __future__ import annotations

import queue
import threading
import time

import pytest
from security_gateway.vault.clusterkey.wake import drain_watch, start_rounds, wake
from security_gateway.vault.etcdstore.store import Store
from security_gateway.vault.etcdstore.watch import ErrNoWatch

from ..etcdstore.cluster_fakes import FakeKV
from .conftest import FakeWatchStore


def _wait_for(predicate, timeout: float = 2.0) -> bool:
    """Wait until ``predicate`` holds, or the timeout runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.005)
    return predicate()


def test_a_round_starts_on_a_wake_before_the_timer() -> None:
    """Test a round starts on a wake before the timer."""
    timer: queue.Queue[object] = queue.Queue()
    wakeups: queue.Queue[None] = queue.Queue(maxsize=1)

    rounds = start_rounds(timer, wakeups)
    wakeups.put_nowait(None)

    assert rounds.get(timeout=2.0) is None


def test_a_round_starts_on_the_timer_without_a_wake() -> None:
    """Test a round starts on the timer without a wake."""
    timer: queue.Queue[object] = queue.Queue()

    rounds = start_rounds(timer, None)
    timer.put_nowait(object())

    assert rounds.get(timeout=2.0) is None


def test_a_wake_is_absent_without_a_watch() -> None:
    """A store with no watch capability must leave the timer as the only
    mechanism rather than hand back a queue that never fires and silently
    disables it.
    """
    store = Store(kv=FakeKV(), ns="test")

    assert wake(store) is None


def test_a_wake_is_absent_for_a_store_that_cannot_watch_at_all() -> None:
    """A store that never had watch support is the same case."""
    from security_gateway.vault.clusterkey.authority import KVClusterStore

    store = KVClusterStore(FakeKV(), "test")

    assert wake(store) is None


def test_a_store_without_a_watch_says_so() -> None:
    """The store reports the missing watch rather than handing back a stream
    that never fires.

    A stream that never fires looks like a quiet cluster, and a quiet
    cluster is exactly what the timer is there to cover.
    """
    store = Store(kv=FakeKV(), ns="test")

    with pytest.raises(ErrNoWatch):
        store.watch_generation()
    with pytest.raises(ErrNoWatch):
        store.watch_handover_requests()


def test_a_wake_fires_when_the_generation_moves() -> None:
    """Test a wake fires when the generation moves."""
    source = FakeWatchStore()

    wakeups = wake(source)
    assert wakeups is not None

    source.generation.push_event(key=b"/security_gateway/test/generation")

    assert wakeups.get(timeout=2.0) is None


def test_a_wake_fires_when_a_peer_publishes_a_request() -> None:
    """Test a wake fires when a peer publishes a request."""
    source = FakeWatchStore()

    wakeups = wake(source)
    assert wakeups is not None

    source.handover.push_event(key=b"/security_gateway/test/handover/req/b")

    assert wakeups.get(timeout=2.0) is None


def test_a_wake_holds_one_reason_at_a_time() -> None:
    """A loop that is already awake needs one reason to run again, not a queue
    of them.
    """
    source = FakeWatchStore()
    wakeups = wake(source)
    assert wakeups is not None

    source.generation.push_event()
    source.generation.push_event()

    assert _wait_for(lambda: source.generation.received >= 2)
    assert wakeups.qsize() == 1


def test_a_drain_closes_the_stream_it_reads() -> None:
    """A stream that is abandoned does not stay open behind the loop that
    stopped reading it.
    """
    source = FakeWatchStore()
    out: queue.Queue[None] = queue.Queue(maxsize=1)

    thread = threading.Thread(
        target=drain_watch, args=(source.generation, out), daemon=True
    )
    thread.start()
    source.generation.end()
    thread.join(timeout=2.0)

    assert not thread.is_alive()
    assert source.generation.closed


def test_a_response_without_an_event_is_not_a_change() -> None:
    """A progress notification says the stream is alive, not that anything
    moved.
    """
    from security_gateway.vault.etcdstore.watch import WatchResponse

    source = FakeWatchStore()
    out: queue.Queue[None] = queue.Queue(maxsize=1)

    thread = threading.Thread(
        target=drain_watch, args=(source.generation, out), daemon=True
    )
    thread.start()
    source.generation.push(WatchResponse(progress_notify=True))
    assert _wait_for(lambda: source.generation.received >= 1)
    time.sleep(0.05)

    assert out.qsize() == 0
    source.generation.end()


def test_a_round_starts_on_either_source() -> None:
    """The point of merging them: a caller waits on one queue and keeps the
    timer as its backstop.
    """
    timer: queue.Queue[object] = queue.Queue()
    wakeups: queue.Queue[None] = queue.Queue(maxsize=1)

    rounds = start_rounds(timer, wakeups)

    wakeups.put_nowait(None)
    assert rounds.get(timeout=2.0) is None

    timer.put_nowait(object())
    assert rounds.get(timeout=2.0) is None
