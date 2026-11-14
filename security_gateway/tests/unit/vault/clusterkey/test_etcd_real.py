"""The cluster key's handover, against a **real** etcd.

The Go counterpart is ``tests/integration/vault_cluster_test.go``, which runs
the same exchange against an embedded etcd that demands a client
certificate.

The handover's unit tests run against the ``FakeKV`` the ``etcdstore``'s own
tests use.  The fake is faithful about the compare-and-swap, and the
handover depends on that being so — but a fake implements the seam itself,
so it never goes through the translation layer onto the real client, and it
never has to answer a real server's questions about compare-and-swap, range
reads and deletes.

What this file checks is therefore the part only a live etcd can settle:

  - the handover's own writes reach the server, and a *second* connection
    finds them: a request that only the publisher can see is a request that
    never reached the authority;
  - the exchange is really cleared from etcd once it is over, so the
    write-ahead log keeps an inert ciphertext rather than an openable one;
  - the mint election has exactly one winner under a real
    ``create_revision == 0`` comparison;
  - the generation fence refuses to move backwards.

The trust anchor here is a **pin list**, not a CA: the certificate is the
node's identity, and what the anchor checks is that its fingerprint is one
the roster vouches for.  So this file needs no PKI and no TLS — on this
side of the port the identity is deliberately not the transport credential.

The tests are skipped unless ``CRED_ROUTER_ETCD_ENDPOINT`` names an etcd,
in the ``host:port`` form the client takes.
"""

from __future__ import annotations

import os
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from security_gateway.vault.clusterdek import (
    HandoverRequest,
    marshal_public_key,
    marshal_request,
    unwrap,
)
from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.clusterkey.clusterkey import HeldDEK
from security_gateway.vault.clusterkey.handover import (
    answer_requests,
    await_answer,
    publish_request,
)
from security_gateway.vault.etcdstore.store import Etcd3KV

from .conftest import handover_test_dek, make_test_node, make_test_roster

#: The endpoint a real etcd is at, in the ``host:port`` form the client
#: takes.  The tests that need a real server are skipped when it is not set.
ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"

pytestmark = pytest.mark.skipif(
    not os.environ.get(ETCD_ENDPOINT_ENV),
    reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
)


def _endpoint() -> tuple[str, int]:
    """The endpoint, split into the host and the port the client takes."""
    value = os.environ[ETCD_ENDPOINT_ENV].strip()
    for prefix in ("http://", "https://"):
        if value.startswith(prefix):
            prefix_length = len(prefix)
            value = value[prefix_length:]
    host, _, port = value.rstrip("/").partition(":")
    return host, int(port or 2379)


def _client():
    """A connection to the live etcd."""
    import etcd3

    host, port = _endpoint()
    return etcd3.Etcd3Client(host=host, port=port)


@pytest.fixture
def namespace() -> str:
    """A namespace of this test's own."""
    return "clusterkeytest-" + uuid.uuid4().hex[:12]


@pytest.fixture
def client():
    """A connection to the live etcd."""
    handle = _client()
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture
def store(client, namespace) -> KVClusterStore:
    """The cluster's half of the authority, over the live etcd."""
    return KVClusterStore(Etcd3KV(client), namespace)


def test_the_handover_delivers_the_key_to_the_requester(store):
    """The exchange works end to end over a live etcd.

    The requester publishes, the holder finds the request with a range
    read, the holder seals the fleet's key to the requester's one-shot key,
    and the requester opens the answer and clears the exchange.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x11)

    nonce, one_shot = publish_request(store, requester.identity(), 0)

    answered = answer_requests(
        store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]
    )
    assert answered == 1, "the holder did not find the request in the authority"

    version, got = await_answer(
        store, requester.identity(), nonce, one_shot, timeout=10
    )
    assert version == 1
    assert got == dek

    # The exchange is over: the request is gone, so the holder stops
    # answering it, and the answer is gone with it.
    assert store.list_handover_requests() == []
    with pytest.raises(Exception):
        store.get_handover_sealed(requester.identity().node_id, nonce)


def test_a_second_connection_finds_the_request(store, namespace):
    """The request is in the server, not in the publisher's own view.

    A second connection is the honest test of that: a store that could see
    its own write without a round trip would pass the exchange test above
    even if nothing had been written at all.
    """
    requester = make_test_node("router-b")

    nonce, _one_shot = publish_request(store, requester.identity(), 0)

    other = _client()
    try:
        elsewhere = KVClusterStore(Etcd3KV(other), namespace)
        entries = elsewhere.list_handover_requests()
    finally:
        other.close()

    assert [entry.node_id for entry in entries] == ["router-b"], (
        f"the request never reached the authority: {entries}"
    )
    assert entries[0].nonce == nonce
    assert entries[0].payload, "the request reached the authority with no payload"


def test_the_answer_left_in_the_authority_opens_for_nobody_else(store):
    """The copy of the answer in etcd is inert.

    It opens for the requester and for nobody else — not even for the
    holder that wrote it, and not for the authority that keeps it.  That is
    the whole point of the one-shot key: the write-ahead log keeps a
    ciphertext nobody holds the key to.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x22)

    nonce, _one_shot = publish_request(store, requester.identity(), 0)
    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)])

    _version, sealed = store.get_handover_sealed(requester.identity().node_id, nonce)

    # The holder does not hold the one-shot key, so the answer is sealed
    # against the holder as well.
    with pytest.raises(Exception):
        unwrap(holder.identity().private, sealed)

    # And a key that is not the requester's does not open it either.
    stranger = make_test_node("router-c")
    with pytest.raises(Exception):
        unwrap(stranger.identity().private, sealed)


def test_a_request_signed_by_another_key_is_refused(store):
    """Anyone who can write to the authority cannot hand themselves the key.

    The signature is what stops that, and it is the whole reason the request
    is signed.  The rogue here publishes under the requester's name with a
    key of its own.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    rogue = make_test_node("router-rogue")
    anchor = make_test_roster(store, (holder, requester, rogue))
    dek = handover_test_dek(0x33)

    one_shot = ec.generate_private_key(ec.SECP256R1())
    request = HandoverRequest(
        node_id=requester.identity().node_id,
        generation=0,
        nonce="rogue-nonce",
        public_key=marshal_public_key(one_shot.public_key()),
    )
    request.sign(rogue.identity().private)
    store.put_handover_request(
        requester.identity().node_id, request.nonce, marshal_request(request)
    )

    answered = answer_requests(
        store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]
    )
    assert answered == 0, (
        "a request signed by a key the roster does not vouch for must not be answered"
    )
    with pytest.raises(Exception):
        store.get_handover_sealed(requester.identity().node_id, request.nonce)


def test_the_mint_election_has_exactly_one_winner(store):
    """Two nodes starting at once do not both mint the fleet's first key.

    The guard is a create-if-absent comparison: it holds only for a key that
    has never existed, so exactly one caller can ever win it.
    """
    assert store.claim_mint("node-a") is True, "the first node did not win the election"
    assert store.claim_mint("node-b") is False, (
        "two nodes both won the mint election; the fleet would have split"
    )
    assert store.mint_owner() == "node-a"


def test_the_roster_round_trips(store):
    """A node publishes its certificate, and the roster reads it back.

    The certificate is the node's identity: the holder verifies a request's
    signature with the key in it, so a roster entry that came back empty or
    mangled would silently stop every handover.
    """
    member = make_test_node("router-a")
    make_test_roster(store, (member,))

    entry = store.get_node("router-a")
    assert entry.node_id == "router-a"
    assert entry.cert_der, "the roster entry carries no certificate"
    assert entry.dek_version == 1


def test_the_generation_fence_refuses_to_move_backwards(store):
    """The fence only moves forward.

    Moving it back would let a writer that was fenced out back in, and
    would strand the entries written under the generation the authority has
    already left behind.
    """
    moved, generation = store.advance_generation(3)
    assert moved is True
    assert generation == 3

    with pytest.raises(ValueError):
        store.advance_generation(2)

    assert store.generation() == 3, "the refused move changed the fence anyway"

    # Moving it to where it already is is not a failure: it is what a
    # takeover whose holder had already moved the fence lands on.
    moved, generation = store.advance_generation(3)
    assert moved is False
    assert generation == 3
