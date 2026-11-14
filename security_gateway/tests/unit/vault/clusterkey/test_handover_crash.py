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
        nonce, one_shot = publish_request(store, asker.identity(), 1)
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
