"""The rotation barrier: how many peers must see the new generation."""

from __future__ import annotations

from security_gateway.vault.barrier import adoption_quorum, await_adoption


def test_a_lone_peer_must_always_confirm():
    assert adoption_quorum(1.0 / 3.0, 0) == 0
    assert adoption_quorum(1.0 / 3.0, 1) == 1


def test_the_quorum_is_a_third_of_the_other_nodes():
    assert adoption_quorum(1.0 / 3.0, 2) == 1
    assert adoption_quorum(1.0 / 3.0, 3) == 1
    assert adoption_quorum(1.0 / 3.0, 4) == 2
    assert adoption_quorum(1.0 / 3.0, 9) == 3


def test_a_full_quorum_needs_every_peer():
    assert adoption_quorum(1.0, 3) == 3


def test_an_out_of_range_ratio_falls_back_to_a_third():
    assert adoption_quorum(0.0, 3) == 1
    assert adoption_quorum(2.0, 3) == 1


def test_the_barrier_passes_when_enough_peers_adopt():
    reads = [
        {"self": 1, "b": 1, "c": 1},
        {"self": 2, "b": 2, "c": 1},
        {"self": 2, "b": 2, "c": 2},
    ]
    calls = 0

    def present():
        nonlocal calls
        value = reads[min(calls, len(reads) - 1)]
        calls += 1
        return value

    result = await_adoption(present, "self", 2, timeout=1.0, poll=0.01)
    assert result.ok
    assert result.confirmed == 1
    assert result.required == 1


def test_the_barrier_times_out_without_a_quorum():
    result = await_adoption(
        lambda: {"self": 2, "b": 1},
        "self",
        2,
        timeout=0.05,
        poll=0.01,
    )
    assert result.timed_out
    assert result.confirmed == 0
    assert result.required == 1


def test_an_empty_fleet_passes_immediately():
    result = await_adoption(lambda: {}, "self", 2, timeout=0)
    assert result.ok
    assert result.required == 0
