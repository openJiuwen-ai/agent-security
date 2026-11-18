"""The first-DEK mint is a permanent compare-create.

A node writes its key locally first, then asks the authority to accept the
mint.  A crash before the acceptance leaves only a key nobody uses; a
crash after it leaves a key the node already has.
"""

from __future__ import annotations

from .cluster_fakes import FakeKV, make_cluster


def test_the_first_mint_wins_once() -> None:
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.claim_mint("node-b") is False
    assert cluster.mint_owner() == "node-a"
    assert cluster.generation() == 1


def test_a_new_node_cannot_claim_a_committed_mint() -> None:
    """A committed mint belongs to the existing fleet, not a newcomer."""
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.claim_mint("node-b") is False
    assert cluster.mint_owner() == "node-a"


def test_a_dead_minter_can_be_replaced_without_a_live_key_holder() -> None:
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.recover_mint("node-b", "node-a", 2) is True
    assert cluster.mint_owner() == "node-b"
    assert cluster.generation() == 2


def test_a_recovery_race_has_one_winner() -> None:
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.recover_mint("node-b", "node-a", 2) is True
    assert cluster.recover_mint("node-c", "node-a", 2) is False
    assert cluster.mint_owner() == "node-b"


def test_a_recovery_that_loses_the_generation_fence_does_nothing() -> None:
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.recover_mint("node-b", "node-a", 2) is True
    assert cluster.recover_mint("node-c", "node-b", 2) is False
    assert cluster.mint_owner() == "node-b"
    assert cluster.generation() == 2


def test_recovery_refuses_to_move_to_the_current_generation() -> None:
    cluster = make_cluster(FakeKV())
    cluster.ensure_generation()

    assert cluster.claim_mint("node-a") is True
    assert cluster.recover_mint("node-b", "node-a", 1) is False
    assert cluster.generation() == 1
    assert cluster.mint_owner() == "node-a"
