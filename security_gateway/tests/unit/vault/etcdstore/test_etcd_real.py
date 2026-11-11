"""The cluster control plane, against a **real** etcd.

The Go counterpart is ``tests/integration/harness_etcd_test.go`` and the
cluster's own integration tests, which run against an embedded etcd.

The control plane's unit tests run against the fake, and the fake is
faithful about the compare-and-swap — but a fake implements the seam
itself, so it never goes through the translation layer onto the real
client, and it never has to answer a real server's questions about
compare-and-swap and leases.

The rules this file checks are the ones that only a real etcd can settle:

  - the mint election has exactly one winner, and the winner is decided by
    a ``create_revision == 0`` comparison — true only for a key that has
    never existed;
  - a rejected comparison leaves the stored value **untouched** and
    reports ``succeeded=False``, which is a conflict and not an error;
  - the takeover claim is exclusive and is a *leased* key, so a holder
    that disappears frees it without anybody having to notice.

The tests are skipped unless ``CRED_ROUTER_ETCD_ENDPOINT`` names an etcd,
in the ``host:port`` form the client takes.
"""

from __future__ import annotations

import base64
import os
import uuid
from datetime import datetime, timezone

import pytest
from security_gateway.vault.etcdstore.cluster import Cluster, NodeEntry, generation_key
from security_gateway.vault.etcdstore.store import Store

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


@pytest.fixture
def namespace() -> str:
    """A namespace of this test's own."""
    return "clustertest-" + uuid.uuid4().hex[:12]


@pytest.fixture
def store(namespace):
    """A store over a live etcd."""
    import etcd3

    host, port = _endpoint()
    client = etcd3.Etcd3Client(host=host, port=port)
    handle = Store.from_client(client, namespace, generation_key=generation_key(namespace))
    try:
        yield handle
    finally:
        client.close()


@pytest.fixture
def cluster(store, namespace):
    """The control plane over that store."""
    return Cluster(store.kv, namespace, store.leases)


def _node_entry(node_id: str) -> NodeEntry:
    """A roster entry.

    The certificate only has to be base64: the roster is a public key and
    the control plane does not parse it.
    """
    return NodeEntry(
        node_id=node_id,
        cert_der=base64.b64encode(f"cert-for-{node_id}".encode()).decode(),
        dek_version=1,
    )


def test_the_mint_election_has_exactly_one_winner(cluster):
    """Two nodes starting at once do not both mint the fleet's first key.

    The guard is a create-if-absent comparison: it holds only for a key
    that has never existed, so exactly one caller can ever win it.
    """
    assert cluster.claim_mint("node-a") is True, "the first node did not win the election"
    assert cluster.claim_mint("node-b") is False, "two nodes both won the mint election; the fleet would have split"
    assert cluster.mint_owner() == "node-a"

    # And the loser's attempt left the winner's claim untouched.
    assert cluster.claim_mint("node-c") is False
    assert cluster.mint_owner() == "node-a"


def test_the_roster_round_trips(cluster):
    """A node publishes itself, and the roster reads it back."""
    cluster.register_node(_node_entry("node-a"))
    cluster.register_node(_node_entry("node-b"))

    entry = cluster.get_node("node-a")
    assert entry.node_id == "node-a"
    assert entry.dek_version == 1

    roster = cluster.list_nodes()
    assert [item.node_id for item in roster] == ["node-a", "node-b"]

    # A node that republishes replaces its own entry rather than adding a
    # second one.
    cluster.register_node(_node_entry("node-a"))
    assert [item.node_id for item in cluster.list_nodes()] == ["node-a", "node-b"]


def test_the_takeover_claim_is_exclusive_and_leased(cluster):
    """Only one node resolves a stalled rotation, and its claim is leased.

    The claim is a create-if-absent transaction against a leased key: one
    holder at a time, and a holder that stops renewing stops counting
    within its TTL.
    """
    claimed_a, lease_a = cluster.claim_takeover("node-a", 30)
    assert claimed_a is True
    assert lease_a is not None
    claimed_b, lease_b = cluster.claim_takeover("node-b", 30)
    assert claimed_b is False, "two nodes both claimed the takeover"
    assert lease_b is None

    cluster.release_takeover(lease_a)
    claimed_b, lease_b = cluster.claim_takeover("node-b", 30)
    assert claimed_b is True, "the claim did not free itself when its holder released it"
    assert lease_b is not None


def test_a_rotation_marker_round_trips(cluster):
    """A rotation marker is written, read back and cleared.

    It is read two ways on purpose.  The stalled view proves the control
    plane can *find* the marker — which is what a takeover depends on, and
    which a fake would have made look right.  The target generation proves
    the value survived the write, because a takeover that cannot read the
    target has to mint a fresh generation instead of continuing the one
    the dead node was rotating toward.
    """
    cluster.put_rotation_marker("node-a", 2)

    markers = cluster.stalled_markers()
    assert [marker.node_id for marker in markers] == ["node-a"], f"the rotation marker is not there: {markers}"
    assert markers[0].value == "2", f"the marker lost its target generation: {markers}"
    assert cluster.stalled_rotations() == ["node-a"]
    assert cluster.stalled_rotation_targets() == {"node-a": 2}

    cluster.delete_rotation_marker("node-a")
    assert cluster.stalled_markers() == []
    assert cluster.stalled_rotations() == []


def test_the_last_rotation_record_round_trips(cluster):
    """The shared rotation marker survives a write and a read.

    It is the one answer to "when did the cluster last rotate", and it has
    to be the *same* answer for every node — which is why it lives in etcd
    rather than in each node's own bookkeeping.
    """
    when = datetime(2026, 11, 2, 12, 0, 0, tzinfo=timezone.utc)
    cluster.set_last_rotation_at(when)

    found = cluster.last_rotation_at()
    assert found.replace(microsecond=0) == when.replace(microsecond=0)
