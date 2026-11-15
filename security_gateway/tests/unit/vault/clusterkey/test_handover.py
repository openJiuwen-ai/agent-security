"""The handover: publishing a request, answering one, opening an answer.

The Go original is ``internal/credmgr/clusterkey/handover_test.go``.
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec
import pytest

from security_gateway.vault.clusterdek import (
    HandoverRequest,
    marshal_public_key,
    marshal_request,
    unwrap,
)
from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.clusterkey.clusterkey import ErrNoPredecessor, HeldDEK
from security_gateway.vault.clusterkey.handover import (
    answer_requests,
    await_answer,
    predecessor,
    publish_request,
)

from .conftest import handover_test_dek, make_test_node, make_test_roster, serve


def test_the_handover_delivers_the_key_to_the_requester(
    store: KVClusterStore,
) -> None:
    """Test the handover delivers the key to the requester."""
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x11)

    # The requester holds no key, so it names generation 0. A holder answers
    # only when it holds something strictly newer, and every holder does.
    nonce, one_shot, _lease = publish_request(store, requester.identity(), 0)

    answered = answer_requests(
        store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]
    )
    assert answered == 1

    version, got = await_answer(store, requester.identity(), nonce, one_shot)
    assert version == 1
    assert got == dek

    # The exchange is over: the request is gone, so the holder stops answering
    # it, and the answer is gone with it.
    assert store.list_handover_requests() == []
    with pytest.raises(Exception):
        store.get_handover_sealed(requester.identity().node_id, nonce)


def test_only_the_requester_can_open_the_handover_answer(
    store: KVClusterStore,
) -> None:
    """The answer opens for the requester and for nobody else.

    The holder has the ciphertext in its own hands and still cannot read it.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    dek = handover_test_dek(0x22)

    nonce, one_shot, _lease = publish_request(store, requester.identity(), 0)
    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)])
    _, sealed = store.get_handover_sealed(requester.identity().node_id, nonce)

    # The holder holds the ciphertext and cannot open it: the key that opens
    # it was the requester's one-shot key.
    with pytest.raises(Exception):
        unwrap(holder.identity().private, sealed)
    assert unwrap(one_shot, sealed) == dek


def test_a_handover_request_signed_by_another_key_is_refused(
    store: KVClusterStore,
) -> None:
    """Anyone who can write to the authority could publish a request carrying
    a key of their own and be handed the fleet's key.

    The signature is what stops that, and it is the whole reason the request
    is signed.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    rogue = make_test_node("router-rogue")
    anchor = make_test_roster(store, (holder, requester, rogue))
    dek = handover_test_dek(0x33)

    # The rogue publishes a request under the requester's name, signed with
    # its own key.
    one_shot = ec.generate_private_key(ec.SECP256R1())
    request = HandoverRequest(
        node_id=requester.identity().node_id,
        generation=0,
        nonce="rogue-nonce",
        public_key=marshal_public_key(one_shot.public_key()),
    )
    request.sign(rogue.identity().private)
    payload = marshal_request(request)
    store.put_handover_request(requester.identity().node_id, request.nonce, payload)

    answered = answer_requests(
        store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=1)]
    )
    assert answered == 0, (
        "a request signed by a key the roster does not vouch for must not be answered"
    )
    with pytest.raises(Exception):
        store.get_handover_sealed(requester.identity().node_id, request.nonce)


def test_a_holder_of_the_same_generation_does_not_answer(
    store: KVClusterStore,
) -> None:
    """A holder of the same generation has nothing the requester wants.

    The request stands: it names the generation the requester holds, and a
    holder answers only when it holds something strictly newer. A holder at
    the same generation stays quiet, which is what lets a request wait for a
    rotation to actually move the fleet on.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))

    # The requester holds generation 1 and the holder holds generation 1.
    publish_request(store, requester.identity(), 1)
    answered = answer_requests(
        store,
        holder.identity(),
        anchor,
        [HeldDEK(dek=handover_test_dek(0x44), generation=1)],
    )
    assert answered == 0, "the request names generation 1 and the holder has 1"

    # A holder that has moved on answers it.
    answered = answer_requests(
        store,
        holder.identity(),
        anchor,
        [HeldDEK(dek=handover_test_dek(0x44), generation=2)],
    )
    assert answered == 1, "the request names generation 1 and the holder has 2"


def test_a_holder_does_not_answer_its_own_request(
    store: KVClusterStore,
) -> None:
    """A holder does not answer its own request.

    The requester opens the answer and deletes the exchange with it, so a
    node that answered its own standing request would consume it: the
    request would be gone from the authority while the node still believed
    it was asking, and nothing would publish another one. The node would
    then never hear about the next rotation.
    """
    holder = make_test_node("router-a")
    anchor = make_test_roster(store, (holder,))

    # The node publishes its own standing request: it holds generation 1 and
    # asks for something newer.
    publish_request(store, holder.identity(), 1)

    # It has moved on to generation 2, so it holds something strictly newer
    # than the request names — and it must still not answer itself.
    answered = answer_requests(
        store,
        holder.identity(),
        anchor,
        [HeldDEK(dek=handover_test_dek(0x55), generation=2)],
    )
    assert answered == 0, "a node has nothing newer to hand itself"

    # And the request is still there, which is the point: it is what asks the
    # fleet for the next generation.
    assert len(store.list_handover_requests()) == 1


def test_awaiting_an_answer_that_never_comes_gives_up(
    store: KVClusterStore,
) -> None:
    """The requester gives up when nobody answers, rather than waiting
    forever.
    """
    requester = make_test_node("router-b").identity()

    nonce, one_shot, _lease = publish_request(store, requester, 1)
    with pytest.raises(TimeoutError):
        await_answer(store, requester, nonce, one_shot, timeout=0.3)


def test_a_node_joining_mid_rotation_is_handed_both_generations(
    store: KVClusterStore,
) -> None:
    """A node that joins while the fleet is rewriting its records is handed
    both generations.

    Holding only the newer one would leave it unable to read every record
    the rewrite has not reached yet, and nothing about the node would look
    wrong.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))

    new_dek = handover_test_dek(0x31)
    old_dek = handover_test_dek(0x21)
    held = [HeldDEK(dek=new_dek, generation=3), HeldDEK(dek=old_dek, generation=2)]

    # The newcomer holds nothing, so it asks for the newest generation.
    nonce, one_shot, _lease = publish_request(store, requester.identity(), 0)
    answer_requests(store, holder.identity(), anchor, held)
    generation, got = await_answer(store, requester.identity(), nonce, one_shot)
    assert generation == 3
    assert got == new_dek

    # Then the one below it, which is what the records still under it need.
    with serve(store, holder.identity(), anchor, held):
        older, older_version = predecessor(store, requester.identity(), generation)
    assert older_version == 2
    assert older == old_dek


def test_latest_asks_for_the_newest_generation_above_a_held_one(
    store: KVClusterStore,
) -> None:
    """A joining node that already holds one generation asks for the newest.

    The predecessor lookup wants the exact next generation; a node catching
    up wants the newest.  The request hint separates the two.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))
    held = [
        HeldDEK(dek=handover_test_dek(0x31), generation=3),
        HeldDEK(dek=handover_test_dek(0x21), generation=2),
    ]

    nonce, one_shot, _lease = publish_request(
        store, requester.identity(), 1, latest=True
    )
    answer_requests(store, holder.identity(), anchor, held)
    generation, _ = await_answer(store, requester.identity(), nonce, one_shot)
    assert generation == 3


def test_a_predecessor_is_not_invented_out_of_the_current_generation(
    store: KVClusterStore,
) -> None:
    """A holder that has no older generation must not pass the current one off
    as the older one.

    The newcomer would install the same key twice and still be unable to
    read the records under the generation it asked for.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    anchor = make_test_roster(store, (holder, requester))

    current = handover_test_dek(0x31)
    held = [HeldDEK(dek=current, generation=3)]
    with serve(store, holder.identity(), anchor, held), pytest.raises(ErrNoPredecessor):
        predecessor(store, requester.identity(), 3, timeout=2.0)


def test_the_first_rotation_has_no_predecessor_to_hand_out(
    store: KVClusterStore,
) -> None:
    """The generation below the first one cannot be asked for by name.

    A request names the generation below the one wanted, and below the
    first is the value that means "I hold nothing". The first rotation
    therefore has no predecessor to hand out, and this pins that it says
    so instead of asking for the wrong generation.
    """
    holder = make_test_node("router-a")
    requester = make_test_node("router-b")
    make_test_roster(store, (holder, requester))

    with pytest.raises(ErrNoPredecessor):
        predecessor(store, requester.identity(), 2)
    assert store.list_handover_requests() == [], (
        "no request may be published for a generation that cannot be asked for"
    )


# -- the exchange's lifetime ----------------------------------------------


def test_a_request_is_leased_so_a_dead_requester_takes_it_with_it(fake_kv) -> None:
    """The request carries a heartbeat; without one it expires."""
    store = KVClusterStore(fake_kv, "handover", fake_kv)
    node = make_test_node("router-a")

    nonce, _one_shot, lease = publish_request(store, node.identity(), 0)

    assert lease is not None
    assert [entry.nonce for entry in store.list_handover_requests()] == [nonce]
    fake_kv.expire_lease(lease.id)
    assert store.list_handover_requests() == []


def test_an_answer_is_leased_so_an_unopened_one_expires(fake_kv) -> None:
    """An answer nobody opens is garbage, and it expires on its own."""
    store = KVClusterStore(fake_kv, "handover", fake_kv)

    lease = store.put_handover_sealed("router-a", "n1", 1, b"sealed", ttl_seconds=300)

    assert lease is not None
    fake_kv.expire_lease(lease.id)
    assert store.list_handover_requests() == []
    with pytest.raises(Exception, match="no handover answer"):
        store.get_handover_sealed("router-a", "n1")


def test_giving_up_clears_the_request_and_its_lease(fake_kv) -> None:
    """A timeout is a clean exit: nothing is left for a holder to answer."""
    store = KVClusterStore(fake_kv, "handover", fake_kv)
    node = make_test_node("router-a")
    nonce, one_shot, lease = publish_request(store, node.identity(), 0)

    with pytest.raises(TimeoutError):
        await_answer(
            store,
            node.identity(),
            nonce,
            one_shot,
            timeout=0.05,
            poll_interval=0.01,
            lease=lease,
        )

    assert store.list_handover_requests() == []
