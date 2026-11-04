"""The machinery a rotation is made of.

A rotation is a protocol rather than a sequence of statements: claim
the generation, mint the key, swap it before the ciphertext moves,
re-encrypt the records that are still under the old key, commit.

This module holds the pieces that protocol is built from — the tuning
constants, the protocol the rotation expects of the store it rotates,
the claim, the commit, the lease, and the helpers the re-encryption
pass shares with the rest of the rotation.

A rotation that dies partway leaves the pending marker set on purpose.
The next open promotes the pending key, keeps the old one as the
previous key, and finishes the re-encryption before any caller sees
the store.

It is split out of :mod:`cred_router.vault.rotate` because the
rotation's order of operations and the statements each step is made of
are two different kinds of code: one is read top to bottom to see what
the rotation does, the other is read to see how a step is carried out.
The public API stays in :mod:`cred_router.vault.rotate`, which is what
the rest of the package imports.
"""

from __future__ import annotations

import random
import threading
import time
from typing import Any, Callable, Protocol

from .errors import KeyMismatchError, VaultError
from .keys import KeyManager, read_key_meta
from .schema import Schema
from .store import Database
from .store import count_stragglers as _count_store_stragglers
from .store import run_with_busy_retry


#: How many records one pass of the re-encryption loop takes at a time.
#:
#: The batch is bounded so the database's write lock is not held for the
#: whole store: a rotation of a large vault would otherwise stall every
#: writer for the length of the re-encryption.
ROTATION_BATCH_SIZE = 100

#: How many times the rotation re-runs its re-encryption pass before
#: giving up.
#:
#: The bound exists so a workload that writes continuously cannot keep the
#: rotation in the loop forever.
MAX_ROTATION_ATTEMPTS = 10

#: How long a node may hold the authority's rotation lock.
#:
#: It has to outlast a rotation of a large store and be short enough that a
#: node that dies mid-rotation does not block the fleet indefinitely.
ROTATION_LOCK_TTL_SECONDS = 90

#: How many times a rotation starts over because the generation moved
#: underneath it.
#:
#: It takes two rotations in the same instant to bring it about.
MAX_CLAIM_ATTEMPTS = 3

#: How long a rotation's lease stays valid.
#:
#: The lease is the store's own updated_at timestamp, refreshed by the
#: rotation while it works. A rotation that dies stops refreshing it, and a
#: takeover may happen once the lease has been stale for this long.
#:
#: It is short on purpose: a lease that looks stale although the rotation
#: is alive costs a duplicated re-encryption pass — waste, not damage. The
#: other direction costs a rotation that stays stuck.
PENDING_LEASE_SECONDS = 15

#: The longest a process waits before it looks at a stale lease again.
#:
#: Several processes can notice the same stale lease at the same moment.
#: Without the wait they would all start re-encrypting the same records;
#: with it, one of them gets there first, refreshes the lease, and the
#: others see the fresh lease and give up.
#:
#: It is a wait on the way to a takeover, not a timeout instead of one.
PENDING_LEASE_JITTER_SECONDS = 4


class RotationTarget(Protocol):
    """What a rotation needs from the store it rotates.

    It is a protocol rather than the store's class so that the rotation
    does not have to import the store.
    """

    #: The store's database.
    db: Database

    #: The store's key material.
    keys: KeyManager

    #: Where the store's S1 shard files live.
    secrets_dir: str

    #: The write barrier. Ordinary writers take it for the length of their
    #: write; a rotation takes it for the final straggler check.
    wmu: Any

    #: Serialises rotations inside this process.
    rotate_mu: Any

    def schema_for_version(self, version: int) -> Schema | None:
        """The schema a record with that version was written with."""
        ...

    def reload_snapshot(self) -> None:
        """Replace the key snapshot with one read from the store."""
        ...


def _not_started() -> None:
    """The stop callable of a rotator that was never started."""


def _stop_check(
    lost_lock: Callable[[], Exception | None] | None,
    cancel: Callable[[], BaseException | None] | None,
) -> Callable[[], BaseException | None]:
    """One check for both reasons a rotation stops.

    The fleet's rotation lock can be lost — its lease went — and the
    caller can call the rotation off. Both mean the same thing to the
    rotation: it is no longer the one rotating, so it stops.
    """

    def check() -> BaseException | None:
        if lost_lock is not None:
            failure = lost_lock()
            if failure is not None:
                return VaultError(
                    f"vault: etcd: the rotation lock's lease was lost: {failure}"
                )
        if cancel is not None:
            return cancel()
        return None

    return check


def _stop_from_event(stopped: threading.Event) -> Callable[[], BaseException | None]:
    """A stop that reports the schedule's stop as the reason to give up.

    Stopping the schedule cancels the tick that is running: the rotation
    does not wait out a store that may never be free.
    """

    def check() -> BaseException | None:
        if stopped.is_set():
            return VaultError("vault: the rotation was cancelled")
        return None

    return check


def _sleep_jitter(seconds: float) -> None:
    """Wait a random moment, at most ``seconds``.

    The wait staggers the processes that noticed the same stale lease.
    It is not a timeout: it happens on the way to a takeover, not
    instead of one.
    """
    if seconds <= 0:
        return
    time.sleep(random.uniform(0.0, seconds))


def _claim_rotation(
    vault: RotationTarget,
    target: int,
    wrapped: bytes,
    active: int,
    stop: Callable[[], BaseException | None] | None = None,
) -> bool:
    """Claim the rotation, waiting out a writer that holds the database's write lock."""

    def claim() -> bool:
        cur = vault.db.execute(
            """
        UPDATE vault_key_metadata
        SET pending_dek_version = ?, pending_wrapped_dek = ?, updated_at = ?
        WHERE id = 1 AND pending_dek_version = 0 AND active_dek_version = ?""",
            (target, wrapped, int(time.time()), active),
        )
        return cur.rowcount == 1

    return run_with_busy_retry(claim, stop)


def _commit_rotation(
    vault: RotationTarget,
    target: int,
    wrapped: bytes,
    old_wrapped: bytes,
    old_version: int,
    stop: Callable[[], BaseException | None] | None = None,
) -> bool:
    """Advance the local store's generation.

    It counts the stragglers and updates the key metadata in one write
    transaction, so a write that lands between the count and the update
    cannot slip past the count.
    """

    def commit() -> bool:
        with vault.db.transaction(immediate=True):
            stragglers = _count_store_stragglers(vault.db, target)
            if stragglers > 0:
                vault.db.rollback()
                return False

            now = int(time.time())
            cur = vault.db.execute(
                """
        UPDATE vault_key_metadata
        SET active_dek_version = ?, superseded_dek_version = ?,
            wrapped_dek = ?, superseded_wrapped_dek = ?,
            pending_dek_version = 0, pending_wrapped_dek = x'',
            last_rotate_at = ?, updated_at = ?
        WHERE id = 1 AND pending_dek_version = ?""",
                (target, old_version, wrapped, old_wrapped, now, now, target),
            )
            if cur.rowcount != 1:
                # The pending generation is no longer pending: somebody else
                # took the rotation over.
                vault.db.rollback()
                return False
            return True

    return run_with_busy_retry(commit, stop)


def rotation_finished_elsewhere(vault: RotationTarget, target: int) -> bool:
    """Whether the store has already moved past the generation a rotation was aiming at.

    The second is not a failure: two processes that noticed the same
    stale lease both adopt the pending generation and race to commit it,
    and the loser of that race must report success.
    """
    km = read_key_meta(vault.db)
    if km is None:
        raise KeyMismatchError("the store has no key metadata")
    return km.active_dek_version >= target


def _refresh_lease(
    vault: RotationTarget,
    generation: int,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """Renew the lease of the generation a rotation is rolling out.

    The lease is the store's own updated_at timestamp. The renewal is
    conditional on the generation still being pending, so a lease that
    outlived its rotation cannot be renewed.
    """

    def refresh() -> None:
        vault.db.execute(
            """
        UPDATE vault_key_metadata SET updated_at = ?
        WHERE id = 1 AND pending_dek_version = ?""",
            (int(time.time()), generation),
        )

    run_with_busy_retry(refresh, stop)


def converge_stragglers(vault: RotationTarget) -> None:
    """Re-encrypt every record that is still under an older key generation."""
    vault.converge_stragglers()
