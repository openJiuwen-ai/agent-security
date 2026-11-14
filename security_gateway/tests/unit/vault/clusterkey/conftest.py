"""The fake authority the cluster key's unit tests run against.

The Go original is ``internal/credmgr/clusterkey/handover_test.go``'s
helpers, which lean on the ``etcdstore``'s in-memory fake.

A real etcd is reachable — ``docs/ETCD_CLIENT_CONTRACT.md`` says how —
but these tests run against the same in-memory fake the ``etcdstore``'s
own tests use, imported rather than copied: a
second copy of a fake that evaluates compare-and-swap would be a
second thing to keep honest about the semantics that matter here.

What the fake has to get right is the verdict of a transaction. A
rejected comparison is not an error — the transaction reports
``succeeded=False`` and changes nothing — and the handover depends on
that: a fake that answers "the comparison holds" for every comparison
turns every optimistic lock off.
"""

from __future__ import annotations

import base64
import contextlib
import datetime
import queue
import threading
from dataclasses import dataclass

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from security_gateway.crypto import DEK_SIZE
from security_gateway.vault.clusterdek import Anchor, Fingerprint, new_anchor
from security_gateway.vault.clusterkey.authority import KVClusterStore, NodeEntry
from security_gateway.vault.clusterkey.clusterkey import HeldDEK, Identity
from security_gateway.vault.clusterkey.handover import answer_requests
from security_gateway.vault.etcdstore.watch import WatchEvent, WatchResponse

from ..etcdstore.cluster_fakes import FakeKV

__all__ = [
    "FakeWatcher",
    "FakeWatchStore",
    "Member",
    "handover_test_dek",
    "make_test_node",
    "make_test_roster",
    "serve",
]


@dataclass(frozen=True)
class Member:
    """One roster member's wrapping keypair.

    The certificate is what the roster stores and what the anchor
    verifies; the private key is what signs this node's requests and
    opens its own answers. Both are needed here because the property
    under test is per-node.
    """

    #: The name this node answers requests under.
    id: str = ""

    #: The certificate the roster vouches for.
    cert: x509.Certificate | None = None

    #: The private half, which never leaves the process.
    priv: ec.EllipticCurvePrivateKey | None = None

    def identity(self) -> Identity:
        """The identity this node answers requests under."""
        return Identity(
            node_id=self.id,
            private=self.priv,
            public=self.priv.public_key() if self.priv else None,
            cert=self.cert,
        )


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def make_test_node(node_id: str) -> Member:
    """Make a node with its own self-signed client certificate.

    The certificate is self-signed because the trust anchor the tests
    build is a pin list: what the anchor checks is that the
    certificate's fingerprint is one the roster vouches for, not that
    some CA signed it.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node_id)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(hours=24))
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return Member(id=node_id, cert=cert, priv=key)


def make_test_roster(
    store: KVClusterStore, members: tuple[Member, ...] | list[Member]
) -> Anchor:
    """Register every member and return the anchor that pins them.

    The answer the handover gives is the one it would give in a fleet
    where every node's certificate is trusted.
    """
    pins: list[str] = []
    for member in members:
        pins.append(Fingerprint(member.cert))
        store.register_node(
            NodeEntry(
                node_id=member.id,
                cert_der=base64.b64encode(
                    member.cert.public_bytes(Encoding.DER)
                ).decode("ascii"),
                dek_version=1,
            )
        )
    return new_anchor("", pins)


def handover_test_dek(seed: int) -> bytes:
    """A key of the fleet's shape, derived from a seed.

    The bytes do not have to be random: what matters is that the test
    can tell one generation's key from another's.
    """
    return bytes((seed + index) % 256 for index in range(DEK_SIZE))


@contextlib.contextmanager
def serve(
    store: KVClusterStore,
    identity: Identity,
    anchor,
    held: list[HeldDEK],
    interval: float = 0.01,
):
    """Answer handover requests in the background, the way a running node does.

    It is what lets a requester that blocks on an answer be tested
    directly.
    """
    stop = threading.Event()

    def _loop() -> None:
        while not stop.is_set():
            answer_requests(store, identity, anchor, held)
            stop.wait(interval)

    thread = threading.Thread(target=_loop, name="handover-serve", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2.0)


class FakeWatcher:
    """A watch stream a test drives by hand.

    It satisfies the ``Watcher`` seam: a test pushes responses into it
    and the drain under test reads them.
    """

    def __init__(self) -> None:
        self._responses: queue.Queue[WatchResponse | None] = queue.Queue()
        self._ended = threading.Event()
        #: Whether the stream was closed by the reader.
        self.closed = False
        #: How many responses the reader has taken, for assertions.
        self.received = 0

    def push(self, response: WatchResponse) -> None:
        """Deliver one response."""
        self._responses.put(response)

    def push_event(self, key: bytes = b"k", value: bytes = b"v") -> None:
        """Deliver a response carrying one change."""
        self.push(
            WatchResponse(
                header_revision=1,
                events=(WatchEvent(key=key, value=value, mod_revision=1),),
            )
        )

    def end(self) -> None:
        """End the stream, the way a server restart would."""
        self._ended.set()
        self._responses.put(None)

    def recv(self, timeout: float | None = None) -> WatchResponse | None:
        """The next response, or ``None`` when none arrived in time."""
        try:
            response = self._responses.get(timeout=timeout)
        except queue.Empty:
            return None
        self.received += 1
        return response

    @property
    def ended(self) -> bool:
        """Whether the stream has ended."""
        return self._ended.is_set()

    def close(self) -> None:
        """Shut the stream down."""
        self.closed = True
        self._ended.set()
        self._responses.put(None)


class FakeWatchStore:
    """An authority that hands out watches a test controls.

    It is what a store with watch support looks like from the outside,
    which is all :func:`~security_gateway.vault.clusterkey.wake.wake` asks
    of one.
    """

    def __init__(self) -> None:
        self.generation = FakeWatcher()
        self.handover = FakeWatcher()

    def watch_generation(self) -> FakeWatcher:
        """Stream changes to the authority's DEK generation key."""
        return self.generation

    def watch_handover_requests(self) -> FakeWatcher:
        """Stream changes under the prefix every pending request lives under."""
        return self.handover


@pytest.fixture
def fake_kv() -> FakeKV:
    """An empty etcd."""
    return FakeKV()


@pytest.fixture
def store(fake_kv: FakeKV) -> KVClusterStore:
    """The cluster's half of the authority, over the fake."""
    return KVClusterStore(fake_kv, "handover")
