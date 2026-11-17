# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Tests for the sandbox daemon accept loop's shutdown wakeup.

The daemon used to block in ``accept()`` with a 1 s socket timeout, so a
shutdown request - handled on a worker thread - could only be noticed once the
current ``accept()`` timed out. That fixed ~1 s was the dominant cost of
deleting a sandbox.

These tests exercise the replacement: the loop waits on the listener plus a
wakeup socketpair (via ``selectors``, so no ``FD_SETSIZE`` ceiling), and
``request_shutdown`` writes one byte to wake it. Everything here uses real
sockets and real threads rather than mocks,
because the behaviour under test is exactly the interleaving between a worker
thread setting the flag and the loop blocking.

Timings asserted are deliberately loose (well below the old 1 s, well above the
observed 0.2-0.5 ms) so the suite stays stable on a loaded CI machine while
still failing loudly if the polling behaviour comes back.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Iterator

import pytest

from jiuwenbox.supervisor import daemon_ipc
from jiuwenbox.supervisor import sandbox_daemon as daemon

# AF_UNIX / select on socket pairs: the daemon itself only runs on Linux, so
# these tests do too. Socket-level tests elsewhere in this suite follow the
# same convention.
pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="sandbox_daemon runs only on Linux; AF_UNIX is used throughout",
)

# The old implementation could only notice shutdown after this long.
OLD_POLL_LATENCY_SECONDS = 1.0
# Generous upper bound for "woken by an event rather than by the poll".
WAKEUP_BUDGET_SECONDS = 0.30
# Upper bound for "the loop thread finished" in teardown/assertions. Only an
# upper bound: a healthy loop returns in well under a millisecond.
LOOP_JOIN_TIMEOUT_SECONDS = 3.0
# Timeout for a client talking to the daemon over its control socket.
CLIENT_TIMEOUT_SECONDS = 2.0
# Short drain budget used to prove "not yet drained" without slowing the suite.
SHORT_DRAIN_SECONDS = 0.05
# Generous drain budget for "it did drain". Only an upper bound.
DRAIN_TIMEOUT_SECONDS = 1.0
# Window used to sample idle CPU, and the ceiling the loop may burn in it.
# A 1 Hz poll costs microseconds here, so this only catches a spinning loop.
IDLE_SAMPLE_SECONDS = 0.5
IDLE_CPU_CEILING_SECONDS = 0.05
# ``select.select`` refuses descriptors at or above this value. The listener fd
# is inherited from box-server, so it is not guaranteed to stay below it.
_FD_SETSIZE = 1024


def _bind_listener(tmp_path) -> socket.socket:
    """Return a listening AF_UNIX socket on a path short enough to bind.

    ``tmp_path`` is *not* used as the socket directory: pytest derives it from
    the test id and the CI workdir, which on a shared runner easily exceeds the
    kernel's 108-byte ``sun_path`` limit and makes ``bind()`` fail with
    ``OSError: AF_UNIX path too long``. The parameter stays in the signature so
    call sites are uniform and can still use it for other files.

    A fresh short directory under the system temp root is used instead; pairing
    the socket with :func:`_close_listener` removes it.
    """
    _ = tmp_path  # kept for signature uniformity; see the note above
    sock_dir = tempfile.mkdtemp(prefix="jbd-")
    path = os.path.join(sock_dir, "c.sock")
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(path)
        listener.listen(16)
    except OSError:
        listener.close()
        shutil.rmtree(sock_dir, ignore_errors=True)
        raise
    return listener


def _close_listener(listener: socket.socket) -> None:
    """Close a listener created by :func:`_bind_listener` and drop its dir."""
    try:
        path = listener.getsockname()
    except OSError:
        path = None
    try:
        listener.close()
    except OSError:
        pass
    if path:
        shutil.rmtree(os.path.dirname(path), ignore_errors=True)


def _start_loop(listener: socket.socket, state: daemon.DaemonState) -> threading.Thread:
    thread = threading.Thread(
        target=daemon.accept_loop,
        args=(listener, state),
        name="test-accept-loop",
        daemon=True,
    )
    thread.start()
    return thread


def _wait_for_wakeup_attached(
    state: daemon.DaemonState,
    timeout: float = CLIENT_TIMEOUT_SECONDS,
) -> None:
    """Block until the loop published its wakeup socket."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if state.wakeup is not None:
            return
        time.sleep(0.002)
    raise AssertionError("accept loop never attached a wakeup socket")


def test_shutdown_wakes_loop_without_waiting_for_poll(tmp_path) -> None:
    """A shutdown request must stop the loop in well under the old 1 s poll."""
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        started = time.monotonic()
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        elapsed = time.monotonic() - started

        assert not loop.is_alive(), "accept loop did not exit after shutdown"
        assert elapsed < WAKEUP_BUDGET_SECONDS, (
            f"shutdown took {elapsed * 1000:.1f} ms; the old poll cost "
            f"~{OLD_POLL_LATENCY_SECONDS * 1000:.0f} ms, so this looks like "
            "polling is still in use"
        )
    finally:
        _close_listener(listener)


def test_shutdown_before_loop_starts_still_exits(tmp_path) -> None:
    """A shutdown that races loop startup must not strand the loop.

    ``request_shutdown`` is called with no wakeup socket registered; the event
    is set, and the loop's first iteration must observe it instead of blocking
    forever in ``select``.
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    state.request_shutdown()

    loop = _start_loop(listener, state)
    try:
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        assert not loop.is_alive(), "loop blocked despite a pre-set shutdown flag"
    finally:
        _close_listener(listener)


def test_repeated_shutdown_is_idempotent(tmp_path) -> None:
    """Extra wakeups must not raise or wedge the loop."""
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        for _ in range(5):
            state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        assert not loop.is_alive()

        # Calling it again after the loop tore down the wakeup must be safe.
        state.request_shutdown()
    finally:
        _close_listener(listener)


def test_idle_loop_does_not_spin(tmp_path) -> None:
    """An idle loop must block, not poll.

    The old implementation woke 1x/second per sandbox. With hundreds of
    sandboxes that is pure overhead, so assert the loop consumes essentially
    no CPU while waiting.
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        before = time.process_time()
        time.sleep(IDLE_SAMPLE_SECONDS)
        consumed = time.process_time() - before

        assert consumed < IDLE_CPU_CEILING_SECONDS, (
            f"idle loop burned {consumed * 1000:.1f} ms of CPU in "
            f"{IDLE_SAMPLE_SECONDS} s; a spinning loop is the likely cause"
        )
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_connection_is_served_before_shutdown(tmp_path) -> None:
    """The loop must still accept and serve connections after the rewrite.

    A real ``list_dir`` request is used rather than monkeypatching
    ``_handle_connection``: the point is that the loop dispatches to a worker
    that answers on the wire, and a real round-trip proves that end to end
    without touching a private symbol.
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.settimeout(CLIENT_TIMEOUT_SECONDS)
        client.connect(listener.getsockname())
        try:
            daemon_ipc.send_frame(
                client,
                daemon_ipc.encode_request(
                    request_type=daemon_ipc.REQUEST_TYPE_LIST_DIR,
                    payload={"path": str(tmp_path)},
                ),
            )
            response = json.loads(
                daemon_ipc.recv_frame(client, daemon.MAX_HEADER_BYTES),
            )
            # The daemon answered, so the loop accepted and dispatched it.
            assert "ok" in response, response
        finally:
            client.close()
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_listener_timeout_is_cleared(tmp_path) -> None:
    """The listener must be blocking; a leftover timeout would add a stall."""
    listener = _bind_listener(tmp_path)
    listener.settimeout(1.0)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)
        assert listener.gettimeout() is None
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_high_numbered_listener_fd_does_not_crash_the_loop(tmp_path) -> None:
    """A listener fd >= FD_SETSIZE must still work.

    The listener descriptor is inherited from box-server via ``pass_fds``, so it
    keeps the parent's fd number. On a loaded server that number can exceed
    ``FD_SETSIZE`` (1024), and ``select.select`` rejects such fds with
    ``ValueError`` - not an ``OSError`` - which would kill the daemon on entry.
    The loop uses ``selectors`` (epoll/poll) precisely to avoid that ceiling.

    A real high-numbered *listening* socket is built by filling the fd table
    first, so the listener is created with a high descriptor from the start.
    """
    # Take ownership of descriptors until the next allocation is >= FD_SETSIZE.
    filler: list[int] = []
    try:
        while True:
            fd = os.open(os.devnull, os.O_RDONLY)
            filler.append(fd)
            if fd + 1 >= _FD_SETSIZE:
                break
    except OSError:  # pragma: no cover - environment cannot open that many
        for fd in filler:
            os.close(fd)
        pytest.skip("cannot allocate a file descriptor above FD_SETSIZE")

    try:
        listener = _bind_listener(tmp_path)
        try:
            assert listener.fileno() >= _FD_SETSIZE, (
                f"listener fd {listener.fileno()} is below FD_SETSIZE; the "
                "test could not reproduce the condition"
            )

            state = daemon.DaemonState()
            loop = _start_loop(listener, state)
            try:
                _wait_for_wakeup_attached(state)
                started = time.monotonic()
                state.request_shutdown()
                loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)

                assert not loop.is_alive(), (
                    "loop did not exit with a high-numbered listener fd; "
                    "select.select would raise ValueError here"
                )
                assert time.monotonic() - started < WAKEUP_BUDGET_SECONDS
            finally:
                state.request_shutdown()
                loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        finally:
            _close_listener(listener)
    finally:
        for fd in filler:
            try:
                os.close(fd)
            except OSError:
                pass


def test_wakeup_sockets_are_not_inheritable(tmp_path) -> None:
    """Exec children must not inherit the wakeup fds."""
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)
        assert state.wakeup is not None
        assert not state.wakeup.get_inheritable()
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_drain_still_covers_the_shutdown_request() -> None:
    """``wait_drain`` must wait for the handler that is acknowledging shutdown.

    The daemon relies on the shutdown request itself being counted in
    ``in_flight`` so the ack is flushed before the process exits. If
    ``begin_request`` stopped covering it, the ack could be lost.
    """
    state = daemon.DaemonState()
    state.begin_request()

    started = time.monotonic()
    # A short drain timeout returns False while the request is outstanding.
    assert state.wait_drain(SHORT_DRAIN_SECONDS) is False
    assert time.monotonic() - started >= SHORT_DRAIN_SECONDS

    state.end_request()
    assert state.wait_drain(DRAIN_TIMEOUT_SECONDS) is True


@pytest.mark.parametrize("timeout", [0.0, -1.0])
def test_drain_returns_false_on_exhausted_budget(timeout: float) -> None:
    """Degenerate timeouts must not block."""
    state = daemon.DaemonState()
    state.begin_request()

    started = time.monotonic()
    assert state.wait_drain(timeout) is False
    assert time.monotonic() - started < IDLE_SAMPLE_SECONDS


@contextlib.contextmanager
def _connect(path) -> Iterator[socket.socket]:
    """Yield a connected control client, closing it on exit.

    A context manager keeps acquisition and release in the same scope, which
    is what the resource-pairing check (G.PRM.03) requires; returning a bare
    socket from a helper leaves the close to the caller and trips it.
    """
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(CLIENT_TIMEOUT_SECONDS)
    try:
        client.connect(str(path))
        yield client
    finally:
        client.close()


def test_shutdown_request_over_ipc_is_acknowledged_before_exit(tmp_path) -> None:
    """The real shutdown path must ack the client and then stop the loop.

    This exercises the whole handshake the runtime relies on during delete:
    ``ProcessRuntime.stop`` sends a ``shutdown`` frame and reads the
    ``shutdown_ack`` response before the daemon exits. The ack must arrive
    while the loop is still alive; if ``request_shutdown`` ran before the
    response was flushed, the client would see a reset instead.
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        with _connect(listener.getsockname()) as client:
            daemon_ipc.send_frame(
                client,
                daemon_ipc.encode_request(
                    request_type=daemon_ipc.REQUEST_TYPE_SHUTDOWN,
                ),
            )
            response = json.loads(
                daemon_ipc.recv_frame(client, daemon.MAX_HEADER_BYTES),
            )
            assert response["ok"] is True
            assert response["type"] == "shutdown_ack"

            loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
            assert not loop.is_alive(), "loop did not exit after shutdown"
            assert state.wait_drain(DRAIN_TIMEOUT_SECONDS), (
                "shutdown handler was still in flight when the loop exited; "
                "the ack could have been cut off"
            )
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_shutdown_does_not_wait_for_in_flight_requests(tmp_path) -> None:
    """The loop must exit promptly while a request is still being served.

    ``stop()`` calls ``wait_drain`` after the loop returns, so the loop itself
    must not wait for in-flight handlers. Simulate a long-running exec by
    leaving one request counted in ``in_flight`` and assert the loop still
    exits inside the wakeup budget while the drain correctly reports "not
    done yet".
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    state.begin_request()  # stand-in for a long-running exec handler
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)

        started = time.monotonic()
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        assert not loop.is_alive(), "loop waited for the in-flight request"
        assert time.monotonic() - started < WAKEUP_BUDGET_SECONDS

        # The loop is gone but the handler is not; main's drain must still see
        # it and wait, otherwise the response could be truncated.
        assert state.wait_drain(SHORT_DRAIN_SECONDS) is False
        state.end_request()
        assert state.wait_drain(DRAIN_TIMEOUT_SECONDS) is True
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)


def test_wakeup_fds_are_not_inherited_across_exec(tmp_path) -> None:
    """A forked+exec'd user command must not inherit the wakeup fds.

    ``set_inheritable(False)`` is what keeps the wakeup socketpair out of
    user commands. Checking the flag (as the earlier test does) is only an
    indirect proof; this test execs a fresh interpreter with
    ``close_fds=False`` - which passes every *inheritable* fd - and inspects
    ``/proc/self/fd`` in the child.
    """
    listener = _bind_listener(tmp_path)
    state = daemon.DaemonState()
    loop = _start_loop(listener, state)
    try:
        _wait_for_wakeup_attached(state)
        wake_fd = state.wakeup.fileno()

        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                (
                    "import os; "
                    "print(' '.join(sorted(os.listdir('/proc/self/fd'))))"
                ),
            ],
            stdout=subprocess.PIPE,
            close_fds=False,
            text=True,
        )
        output, _ = child.communicate(timeout=5)
        assert child.returncode == 0, output

        fds = {int(entry) for entry in output.split()}
        assert {0, 1} <= fds, f"child fd listing looked wrong: {output!r}"
        assert wake_fd not in fds, (
            f"wakeup fd {wake_fd} leaked into the exec child (fds: {sorted(fds)})"
        )
    finally:
        state.request_shutdown()
        loop.join(timeout=LOOP_JOIN_TIMEOUT_SECONDS)
        _close_listener(listener)
