"""The cross-node rotation lock.

The lock is the cross-node mutex for the DEK rotation described in design
§2.12 step 1. Exactly one node in a cluster may hold it.

The lock *is* the existence of ``/security_gateway/<ns>/rotation``, kept alive by
an etcd lease: if the holder dies or its lease expires, etcd removes the key
and the next candidate can take it. There is no separate lock record to
reconcile.  A plain key would need somebody to delete it after a crash, and
the somebody is usually not there; a lease expires on its own, so the lock
fails over without an operator, a janitor, or a timeout sweep.

The rotation state is written into the same key, under the same lease, so
that the state and the lock cannot disagree: a node reading the state sees
the holder's identity and the phase, and a node that has lost the lease
cannot overwrite the state of the node that replaced it — the write is
conditional on the key still being at the revision this lock last wrote.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone

from .cluster import LeaseFactory, LeasePutOp
from .errors import ConflictError, InvalidValueError, NotFoundError, RotationHeldError
from .keys import rotation_key
from .rotation import (
    ROTATION_STATE_ABORTED,
    ROTATION_STATE_ACQUIRING,
    ROTATION_STATE_COMPLETED,
    ROTATION_STATE_IN_PROGRESS,
    RotationState,
    marshal_rotation,
    unmarshal_rotation,
)
from .store import (
    KV,
    Compare,
    KVValue,
    Operation,
    TxnResult,
    compare_create,
    compare_mod,
)

__all__ = [
    "ROTATION_STATE_ABORTED",
    "ROTATION_STATE_ACQUIRING",
    "ROTATION_STATE_COMPLETED",
    "ROTATION_STATE_IN_PROGRESS",
    "RotationLock",
    "acquire_rotation_lock",
    "get_rotation_state",
    "rotation_lock_held",
]


def acquire_rotation_lock(
    kv: KV,
    leases: LeaseFactory,
    ns: str,
    holder: str,
    ttl_seconds: int,
) -> RotationLock:
    """Attempt to become the node performing the cluster-wide DEK rotation.

    The returned lock must be renewed at least once per ``ttl_seconds``
    for the duration of the rotation, or etcd will expire it and another
    node will take over mid-rotation.
    """
    if not holder:
        raise InvalidValueError("etcdstore: rotation lock holder must be non-empty")
    if ttl_seconds <= 0:
        raise InvalidValueError(
            f"etcdstore: rotation lock ttl must be positive, got {ttl_seconds}"
        )

    lease = leases.lease(ttl_seconds)
    lease_id = lease.grant()

    key = rotation_key(ns)
    value = marshal_rotation(
        RotationState(
            state=ROTATION_STATE_ACQUIRING,
            holder=holder,
            target_dek_version=0,
            started_at=datetime.now(timezone.utc),
        )
    )

    result = _txn(kv, [compare_create(key)], [LeasePutOp(key, value, lease_id)])
    # A failed comparison here means the lock is taken — the common case
    # under contention, not a transport problem. A failed *transaction* is
    # the verdict, not an exception.
    if not result.succeeded:
        _discard(lease)
        raise RotationHeldError("etcdstore: rotation lock is held by another holder")

    return RotationLock(
        kv=kv,
        leases=leases,
        ns=ns,
        key=key,
        lease_id=lease_id,
        holder=holder,
        ttl=ttl_seconds,
        mod_revision=result.revision,
    )


class RotationLock:
    """A held rotation lock.

    It is not safe for concurrent use beyond the revision bookkeeping it
    guards internally.
    """

    def __init__(
        self,
        *,
        kv: KV,
        leases: LeaseFactory,
        ns: str,
        key: str,
        lease_id: int,
        holder: str,
        ttl: int,
        mod_revision: int,
    ) -> None:
        self._kv = kv
        self._leases = leases
        self._ns = ns
        self._key = key
        self._lease_id = lease_id
        self._holder = holder
        self._ttl = ttl
        self._mod_revision = mod_revision
        self._lock = threading.Lock()

    @property
    def lease_id(self) -> int:
        """The backing lease, mostly so tests can watch it expire."""
        return self._lease_id

    @property
    def holder(self) -> str:
        """The identity this lock was acquired with."""
        return self._holder

    @property
    def ttl(self) -> int:
        """The lease TTL in seconds."""
        return self._ttl

    @property
    def key(self) -> str:
        """The key the lock is held on."""
        return self._key

    def renew(self) -> None:
        """Extend the lease by one TTL.

        An error means the lease is gone — the caller has lost the lock
        and must stop mutating shared state rather than continuing on
        the assumption it is still exclusive.
        """
        self._leases.lease(0, self._lease_id).keepalive()

    def release(self) -> None:
        """Drop the lock."""
        try:
            self._leases.lease(0, self._lease_id).revoke()
        except Exception as exc:  # noqa: BLE001 - judged below
            if _is_lease_not_found(exc):
                # The lease is already gone, which is the state release is
                # trying to reach. Not an error.
                return
            raise

    def update_state(self, state: RotationState) -> None:
        """Record rotation progress under the lock."""
        if state is None:
            raise InvalidValueError("etcdstore: nil rotation state")
        value = marshal_rotation(state)

        with self._lock:
            expected = self._mod_revision

        result = _txn(
            self._kv,
            [compare_mod(self._key, expected)],
            [LeasePutOp(self._key, value, self._lease_id)],
        )
        if not result.succeeded:
            raise ConflictError(
                "etcdstore: the rotation state was written by another holder"
            )

        with self._lock:
            self._mod_revision = result.revision

    def state(self) -> RotationState:
        """The rotation state currently stored, held or not.

        Raises :class:`~.errors.NotFoundError` when no rotation is in
        progress, which is the normal steady state.
        """
        found = self._get(self._key)
        if found is None:
            raise NotFoundError("etcdstore: no rotation is in progress")
        return unmarshal_rotation(found.value)

    # -- the seam ----------------------------------------------------------

    def _get(self, key: str) -> KVValue | None:
        return self._kv.get(key)


def get_rotation_state(kv: KV, ns: str) -> RotationState:
    """Read the cluster's rotation state without taking the lock."""
    found = kv.get(rotation_key(ns))
    if found is None:
        raise NotFoundError("etcdstore: no rotation is in progress")
    return unmarshal_rotation(found.value)


def rotation_lock_held(kv: KV, ns: str) -> bool:
    """Report whether a node currently holds the cluster rotation lock."""
    return kv.get(rotation_key(ns)) is not None


def _txn(kv: KV, compare: list[Compare], success: list[Operation]) -> TxnResult:
    """Run a transaction."""
    return kv.transaction(compare, success)


def _discard(lease: object) -> None:
    """Release a lease the caller has decided not to use.

    The error is dropped on purpose: this only runs on an error path,
    and a lease we failed to revoke expires on its own TTL anyway.
    """
    try:
        lease.revoke()  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 - best effort
        pass


def _is_lease_not_found(exc: BaseException) -> bool:
    """Report whether ``exc`` is etcd's "the lease does not exist" error.

    The etcd client is an optional extra and cannot be imported here, so
    the check is by name and by message rather than by isinstance.
    """
    for klass in type(exc).__mro__:
        if "leasenotfound" in klass.__name__.lower().replace("_", ""):
            return True
    message = str(exc).lower()
    return "lease not found" in message or "requested lease not found" in message
