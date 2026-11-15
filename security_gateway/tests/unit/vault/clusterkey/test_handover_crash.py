"""The answering loop dying between requests.

The Go original is ``internal/credmgr/clusterkey/handover_crash_test.go``.
"""

from __future__ import annotations

import pytest

from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.clusterkey.clusterkey import HeldDEK
from security_gateway.vault.clusterkey.fault import (
    HANDOVER_ANSWERED_STAGE,
    set_handover_fault_hook_for_testing,
)
from security_gateway.vault.clusterkey.handover import (
    answer_requests,
    await_answer,
    publish_request,
)

from .conftest import Member, handover_test_dek, make_test_node, make_test_roster


def test_the_handover_interrupted_mid_roster_is_completed_on_the_next_pass(
    store: KVClusterStore,
) -> None:
    """The answering loop dying between requests is the one crash that leaves
    a state the recovery path has to repair.

    A request that was answered and a request that was not. Nothing is
    corrupt, but the next pass has to finish the job, and the only way to
    know it does is to interrupt the loop exactly there.
    """
    holder = make_test_node("router-a")
    askers = [
        make_test_node("router-b"),
        make_test_node("router-c"),
        make_test_node("router-d"),
    ]
    members = [holder, *askers]
    anchor = make_test_roster(store, members)

    dek = handover_test_dek(0x01)

    # Every requester holds generation 1 and asks for something newer; the
    # holder has generation 2.
    nonces: list[str] = []
    one_shots = []
    for asker in askers:
        nonce, one_shot, _lease = publish_request(store, asker.identity(), 1)
        nonces.append(nonce)
        one_shots.append(one_shot)

    # Die after the second answer.
    answered = 0

    def _hook(stage: str) -> None:
        nonlocal answered
        if stage != HANDOVER_ANSWERED_STAGE:
            return
        answered += 1
        if answered == 2:
            raise RuntimeError("crash mid-roster")

    restore = set_handover_fault_hook_for_testing(_hook)
    try:
        with pytest.raises(RuntimeError):
            answer_requests(
                store,
                holder.identity(),
                anchor,
                [HeldDEK(dek=dek, generation=2)],
            )
    finally:
        restore()

    # The state under test: some answered, one not.
    assert answered_count(store, askers) == 2, (
        "a partial answer is the state under test"
    )

    # The recovery run is an ordinary call with no fault injected.
    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)])
    assert answered_count(store, askers) == len(askers)

    # And every requester can open what it was answered.
    for index, asker in enumerate(askers):
        _, dek_got = await_answer(
            store, asker.identity(), nonces[index], one_shots[index]
        )
        assert dek_got == dek, f"{asker.id} opened its answer to a different key"


def answered_count(store: KVClusterStore, askers: list[Member]) -> int:
    """Report how many of the requesters have an answer waiting."""
    count = 0
    requests = store.list_handover_requests()
    for asker in askers:
        for request in requests:
            if request.node_id != asker.id:
                continue
            try:
                store.get_handover_sealed(asker.id, request.nonce)
            except Exception:  # noqa: BLE001 - only "no answer" is benign
                continue
            count += 1
    return count


def test_an_answer_published_before_a_crash_is_not_sealed_again(
    store: KVClusterStore,
) -> None:
    """A holder that died after publishing an answer leaves it in place.

    The next answering pass must reuse that answer, not publish a second
    ciphertext for the same request; the requester then opens the original
    one and clears the exchange.
    """
    holder = make_test_node("router-a")
    asker = make_test_node("router-b")
    anchor = make_test_roster(store, [holder, asker])
    nonce, one_shot, _lease = publish_request(store, asker.identity(), 0)
    dek = handover_test_dek(0x02)

    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)])
    first = store.get_handover_sealed(asker.id, nonce)

    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)])
    second = store.get_handover_sealed(asker.id, nonce)

    assert second == first, "the second pass re-sealed an answer that already existed"
    version, got = await_answer(store, asker.identity(), nonce, one_shot)
    assert (version, got) == (2, dek)
    with pytest.raises(Exception):  # noqa: B017 - only "cleared" is benign
        store.get_handover_sealed(asker.id, nonce)


def test_a_requester_that_died_before_cleanup_can_open_the_answer_again(
    store: KVClusterStore,
) -> None:
    """Reading the answer and dying before deleting it must be harmless.

    The answer is a ciphertext under the requester's one-shot key; opening
    it twice produces the same key.  The second read is also what clears the
    exchange if the first process died between the read and the delete.
    """
    holder = make_test_node("router-a")
    asker = make_test_node("router-b")
    anchor = make_test_roster(store, [holder, asker])
    nonce, one_shot, _lease = publish_request(store, asker.identity(), 0)
    dek = handover_test_dek(0x03)

    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)])
    # The first process read the answer but never got to delete it.
    store.get_handover_sealed(asker.id, nonce)

    version, got = await_answer(store, asker.identity(), nonce, one_shot)
    assert (version, got) == (2, dek)
    with pytest.raises(Exception):  # noqa: B017 - only "cleared" is benign
        store.get_handover_sealed(asker.id, nonce)


def test_a_failed_sealed_write_is_retried_on_the_next_pass(
    store: KVClusterStore, monkeypatch
) -> None:
    """A network error while publishing an answer must not consume the request.

    The request is still there and no answer exists, so the next pass can
    publish it.  A failed write must not leave the exchange half-created.
    """
    holder = make_test_node("router-a")
    asker = make_test_node("router-b")
    anchor = make_test_roster(store, [holder, asker])
    nonce, one_shot, _lease = publish_request(store, asker.identity(), 0)
    dek = handover_test_dek(0x04)

    def boom(*args, **kwargs):
        raise OSError("the authority is unreachable")

    with monkeypatch.context() as patch:
        patch.setattr(store, "put_handover_sealed", boom)
        assert (
            answer_requests(
                store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)]
            )
            == 0
        )
        with pytest.raises(Exception):  # noqa: B017 - the answer was not written
            store.get_handover_sealed(asker.id, nonce)

    assert (
        answer_requests(
            store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)]
        )
        == 1
    )
    assert await_answer(store, asker.identity(), nonce, one_shot) == (2, dek)


def test_a_failed_cleanup_is_retried_by_the_next_reader(
    store: KVClusterStore, monkeypatch
) -> None:
    """Deleting the exchange is best effort; the answer must survive it.

    A requester that opened the key but could not delete the exchange has
    still received the key, and the next read has to return the same key and
    finish the cleanup.
    """
    holder = make_test_node("router-a")
    asker = make_test_node("router-b")
    anchor = make_test_roster(store, [holder, asker])
    nonce, one_shot, _lease = publish_request(store, asker.identity(), 0)
    dek = handover_test_dek(0x05)

    answer_requests(store, holder.identity(), anchor, [HeldDEK(dek=dek, generation=2)])

    def boom(*args, **kwargs):
        raise OSError("the authority is unreachable")

    with monkeypatch.context() as patch:
        patch.setattr(store, "delete_handover", boom)
        assert await_answer(store, asker.identity(), nonce, one_shot) == (2, dek)
        assert store.get_handover_sealed(asker.id, nonce)

    assert await_answer(store, asker.identity(), nonce, one_shot) == (2, dek)
    with pytest.raises(Exception):  # noqa: B017 - only "cleared" is benign
        store.get_handover_sealed(asker.id, nonce)
