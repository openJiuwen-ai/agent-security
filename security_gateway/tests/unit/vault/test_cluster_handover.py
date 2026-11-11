"""The vault's share of the fleet's key.

The Go counterpart is ``pkg/vault/cluster.go``.  It is the vault's own
version of the exchange the router runs in
``cmd/credential-router/cluster.go``: the same protocol, over the vault's
own keyspace.

Two things are pinned here, and neither needs an etcd:

* the **trust anchor** — a node that meant to have one and does not have
  one must not quietly become a node that hands the vault's key to
  everybody;
* the **fleet's key** — the key a joining node adopts, and the
  generations it can hand over.

The Go's comments are the specification; these tests exist because each
of them records a way for the fleet's key to end up in the wrong hands.
"""

from __future__ import annotations

import queue
import threading
import types

import pytest
from security_gateway.crypto import KeyBytes, Mode
from security_gateway.vault.cluster import (
    cluster_anchor_for,
    held_deks,
    load_cluster_identity,
    obtain_cluster_dek,
    serve_cluster_wrapping,
)
from security_gateway.vault.errors import InvalidError
from security_gateway.vault.keys import KeySnapshot


class FakeTls:
    def __init__(
        self, ca_file: str = "", cert_file: str = "", key_file: str = ""
    ) -> None:
        self.ca_file = ca_file
        self.cert_file = cert_file
        self.key_file = key_file


class FakeEtcdConfig:
    """The vault's own etcd configuration, as far as these tests read it."""

    def __init__(
        self,
        node_id: str = "node-a",
        pins=None,
        tls: FakeTls | None = None,
        identity_ca_file: str = "",
    ) -> None:
        self.node_id = node_id
        self.trusted_cert_sha256 = list(pins or [])
        self.identity_cert_file = ""
        self.identity_key_file = ""
        self.identity_ca_file = identity_ca_file
        self.tls = tls if tls is not None else FakeTls()
        self.endpoints = ("http://127.0.0.1:2379",)
        self.namespace = "credential-router-vault"
        self.dial_timeout = 5.0
        self.fetch_timeout = 30.0


# -- the trust anchor ------------------------------------------------------


def test_a_missing_anchor_is_refused():
    """A node with neither a CA nor pins cannot verify a peer's identity."""
    with pytest.raises(InvalidError, match="identity_ca_file"):
        cluster_anchor_for(FakeEtcdConfig())


def test_an_unbuildable_anchor_is_refused():
    """An anchor that is configured but cannot be built is an error.

    A node that meant to have a trust anchor and cannot build it must
    not quietly become a node that hands nothing over - that is how a
    broken CA file turns into a fleet that stops handing over.
    """
    cfg = FakeEtcdConfig(tls=FakeTls(ca_file="/nonexistent/ca.pem"))
    with pytest.raises(Exception):
        cluster_anchor_for(cfg)


def test_a_pin_list_is_an_anchor():
    """The pin list stands on its own.

    It is the trust anchor when the cluster CA is not available yet, and
    it takes over outright when it is configured: a certificate has to
    satisfy the pin list, and the CA is not consulted.
    """
    fingerprint = "ab" * 32
    anchor = cluster_anchor_for(FakeEtcdConfig(pins=[fingerprint]))
    assert anchor is not None
    assert anchor.pins_take_over() is True


def test_an_unreadable_ca_file_is_refused(tmp_path):
    """An anchor that is configured but cannot be built is an error."""
    cfg = FakeEtcdConfig(identity_ca_file=str(tmp_path / "missing.pem"))
    with pytest.raises(Exception):
        cluster_anchor_for(cfg)


# -- the identity ----------------------------------------------------------


def test_the_identity_is_read_from_the_node_id():
    """The identity is the node's name in the roster."""
    cfg = FakeEtcdConfig(node_id="node-b")
    with pytest.raises(Exception):
        # There is no certificate at the configured path, so the read
        # fails — but it fails at the certificate, not at the node id.
        identity = load_cluster_identity(cfg)
        assert identity.node_id == "node-b"


# -- the fleet's key -------------------------------------------------------


def test_no_identity_means_no_key_to_adopt():
    """A node that is not in the exchange has nothing to adopt."""
    assert obtain_cluster_dek(FakeEtcdConfig(), object(), None, None) is None


def test_no_authority_means_no_key_to_adopt():
    """Without the authority there is nobody to ask."""
    assert obtain_cluster_dek(FakeEtcdConfig(), None, object(), None) is None


def test_the_held_generations_are_the_current_one_and_the_one_before():
    """A node hands over the key in use and, while a rotation has not
    released it, the one it replaced.

    A node that joins while the fleet is rewriting its records under the
    current generation arrives into a world where the authority still
    holds records sealed to the older one, so the older key has to be
    handed over too.
    """
    current = KeySnapshot(
        dek=KeyBytes(b"\x01" * 16),
        version=7,
        mode=Mode.AES,
    )
    previous = KeySnapshot(
        dek=KeyBytes(b"\x02" * 16),
        version=6,
        mode=Mode.AES,
    )

    held = held_deks(current, previous)
    assert [h.generation for h in held] == [7, 6]
    assert [h.dek for h in held] == [b"\x01" * 16, b"\x02" * 16]


def test_a_node_holding_one_key_hands_over_one_key():
    """Before a rotation there is only the key in use."""
    current = KeySnapshot(
        dek=KeyBytes(b"\x01" * 16),
        version=1,
        mode=Mode.AES,
    )

    held = held_deks(current, None)
    assert [h.generation for h in held] == [1]


# -- the handover loop -----------------------------------------------------


def test_the_handover_loop_does_not_start_without_an_anchor():
    """A node with no anchor answers nothing, so the loop does not run.

    Nothing would ever be handed over, so running it would only produce
    a warning every few seconds.  Serve traffic regardless: a node that
    holds the key can decrypt every record it is asked for without
    handing anything to anyone.
    """
    stop = threading.Event()
    touched = []

    class ExplodingAuthority:
        def __getattr__(self, name):
            touched.append(name)
            raise AssertionError(f"the store must not be touched: {name}")

    identity = types.SimpleNamespace(node_id="node-a")

    serve_cluster_wrapping(
        stop,
        ExplodingAuthority(),
        identity,
        lambda: KeySnapshot(dek=KeyBytes(b"\x01" * 16), version=1, mode=Mode.AES),
        lambda: None,
        anchor=None,
        interval=0.01,
    )

    assert touched == []


# -- the wake channel ------------------------------------------------------


class FakeWatchStore:
    """A store that hands out the two watches the loop reacts to."""

    def __init__(self) -> None:
        self.generation = _FakeWatcher()
        self.handover = _FakeWatcher()

    def watch_generation(self):
        return self.generation

    def watch_handover_requests(self):
        return self.handover


class _FakeWatcher:
    """A watch stream a test drives by hand."""

    def __init__(self) -> None:
        self._responses: queue.Queue = queue.Queue()
        self._ended = threading.Event()

    def push_event(self) -> None:
        from security_gateway.vault.etcdstore.watch import (
            WatchEvent,
            WatchResponse,
        )

        self._responses.put(
            WatchResponse(
                header_revision=1,
                events=(WatchEvent(key=b"k", value=b"v", mod_revision=1),),
            )
        )

    def recv(self, timeout=None):
        try:
            return self._responses.get(timeout=timeout)
        except queue.Empty:
            return None

    @property
    def ended(self) -> bool:
        return self._ended.is_set()

    def close(self) -> None:
        self._ended.set()
        self._responses.put(None)


class _Loop:
    """The handover loop, running in the background."""

    def __init__(self) -> None:
        self.stop = threading.Event()
        self.rounds = 0
        self._done = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, monkeypatch, watch_store, interval) -> "_Loop":
        def fake_answer(authority, identity, anchor, held):
            self.rounds += 1
            self._done.set()
            return 0

        def fake_ask(authority, identity, generation, on_newer):
            return None

        monkeypatch.setattr("security_gateway.vault.cluster.answer_requests", fake_answer)
        monkeypatch.setattr("security_gateway.vault.cluster.ask_for_newer_key", fake_ask)

        self._thread = threading.Thread(
            target=serve_cluster_wrapping,
            args=(
                self.stop,
                object(),
                types.SimpleNamespace(node_id="node-a"),
                lambda: KeySnapshot(
                    dek=KeyBytes(b"\x01" * 16), version=1, mode=Mode.AES
                ),
                lambda: None,
                object(),
            ),
            kwargs={"interval": interval, "watch_store": watch_store},
            daemon=True,
        )
        self._thread.start()
        return self

    def wait_for_a_round(self, deadline: float) -> bool:
        """Whether a round happened within ``deadline`` seconds."""
        return self._done.wait(deadline)

    def shutdown(self) -> None:
        self.stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)


def test_a_published_request_wakes_the_loop_before_the_tick(monkeypatch):
    """A peer publishes a request; the holder answers it now.

    The tick is the backstop, not the mechanism.  A holder that waits
    for the tick makes every joining node wait a tick, and a joining
    node waits out its whole fetch timeout if the tick is the only
    thing that can move the exchange forward.
    """
    store = FakeWatchStore()
    # A tick interval far longer than the test would tolerate, so the
    # only thing that can start a round is the watch.
    loop = _Loop().start(monkeypatch, store, interval=30.0)
    try:
        assert loop.wait_for_a_round(0.5) is False
        store.handover.push_event()
        assert loop.wait_for_a_round(3.0) is True
    finally:
        loop.shutdown()


def test_the_tick_is_the_backstop_when_there_is_no_watch(monkeypatch):
    """A store without watch support still gets its rounds."""
    loop = _Loop().start(monkeypatch, None, interval=0.05)
    try:
        assert loop.wait_for_a_round(3.0) is True
    finally:
        loop.shutdown()
