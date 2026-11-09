"""The crash-injection hook the handover's answering loop fires.

The hook exists for one state: the answering loop dying *between*
requests.  That is the only crash that leaves the authority holding a
part-answered roster — some requests answered, some not.  Nothing is
corrupt, but the next pass has to finish the job, and the only way to
know that it does is to interrupt the loop at exactly that point.

The hook lives here as a module-level variable that is ``None`` in any
normal run, so the seam is reachable from a test without a special
build.

The stage is named for the point in the operation it interrupts rather
than for the function it lives in, so a test can say what state it wants
to be in when it dies.
"""

from __future__ import annotations

from collections.abc import Callable

__all__ = [
    "HANDOVER_ANSWERED_STAGE",
    "set_handover_fault_hook_for_testing",
]

#: The stage fired after a request's answer was published.
HANDOVER_ANSWERED_STAGE = "cluster_handover_answered"

#: The installed hook. It is ``None`` outside a test, which is what makes
#: the fault-injection seam inert in a production run.
_handover_fault_hook: Callable[[str], None] | None = None


def invoke_handover_fault(stage: str) -> None:
    """Call the crash-injection hook if one is installed.

    A hook that raises ends the operation the way a crashed process
    would: the exception propagates out of the answering loop, leaving
    the authority in whatever state it had reached.
    """
    hook = _handover_fault_hook
    if hook is not None:
        hook(stage)


def set_handover_fault_hook_for_testing(
    fn: Callable[[str], None] | None,
) -> Callable[[], None]:
    """Install the crash-injection hook and return a way to remove it."""
    global _handover_fault_hook
    previous = _handover_fault_hook
    _handover_fault_hook = fn
    return _restore_handover_fault_hook(previous)


def _restore_handover_fault_hook(previous: Callable[[str], None] | None):
    """Build the callable that puts ``previous`` back."""

    def _restore() -> None:
        global _handover_fault_hook
        _handover_fault_hook = previous

    return _restore
