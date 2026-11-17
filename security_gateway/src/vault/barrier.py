"""The fleet-adoption barrier for a rotation.

A rotation is committed on the authority before every node has the new
generation.  Records are encrypted under the new key from that moment,
so a node that is still on the old generation cannot read them.  The
barrier is the wait that turns "the rotation succeeded" into "enough of
the fleet can read what the rotation wrote".

The quorum is deliberately not a majority of processes: presence is
published once per ``node_id``, so a host running three vault processes
is still one vote.  etcd keeps the same rule for its own quorum.

The wait is bounded.  A node that never adopts must not hold a rotation
open forever; the caller gets a result that says the barrier timed out
and can decide whether that is fatal for its deployment.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Callable, Mapping

__all__ = [
    "AdoptionResult",
    "adoption_quorum",
    "await_adoption",
]


@dataclass(frozen=True)
class AdoptionResult:
    """What the barrier saw when it stopped waiting."""

    confirmed: int
    required: int
    timed_out: bool

    @property
    def ok(self) -> bool:
        """Whether enough peers had adopted when the wait ended."""
        return self.confirmed >= self.required


def adoption_quorum(ratio: float, others: int) -> int:
    """How many *other* nodes must adopt for the barrier to pass.

    ``others`` excludes this node: it has already adopted, because it
    performed the rotation.  A single peer must always confirm, and the
    quorum never exceeds the number of peers that exist.
    """
    if others <= 1:
        return max(others, 0)
    if not 0.0 < ratio <= 1.0:
        ratio = 1.0 / 3.0
    return min(max(int(math.ceil(ratio * others)), 1), others)


def await_adoption(
    list_present: Callable[[], Mapping[str, int]],
    node_id: str,
    target: int,
    *,
    timeout: float,
    ratio: float = 1.0 / 3.0,
    poll: float = 0.5,
    cancel: Callable[[], bool] | None = None,
) -> AdoptionResult:
    """Wait until the fleet's live nodes have adopted ``target``.

    ``list_present`` returns the generation each live node currently
    claims, keyed by node id.  This node is excluded from both the
    denominator and the confirmed count.  A zero or negative timeout
    performs one read and returns immediately.
    """
    deadline = time.monotonic() + max(float(timeout), 0.0)
    interval = max(float(poll), 0.01)
    while True:
        present = dict(list_present() or {})
        others = {key: int(value) for key, value in present.items() if key != node_id}
        required = adoption_quorum(ratio, len(others))
        confirmed = sum(1 for version in others.values() if version >= target)
        timed_out = time.monotonic() >= deadline
        if confirmed >= required or timed_out:
            return AdoptionResult(
                confirmed=confirmed, required=required, timed_out=timed_out
            )
        if cancel is not None and cancel():
            return AdoptionResult(
                confirmed=confirmed, required=required, timed_out=True
            )
        time.sleep(interval)
