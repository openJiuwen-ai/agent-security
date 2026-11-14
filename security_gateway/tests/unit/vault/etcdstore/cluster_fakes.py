"""A fake etcd for the cluster control plane's tests.

A real etcd is reachable — ``docs/ETCD_CLIENT_CONTRACT.md`` says how —
but the cluster's unit tests run against a fake that reproduces the three
etcd behaviours the control plane's correctness rests on:

* a write under a ``mod(key) == N`` comparison succeeds only when the
  stored modification revision is ``N``, and **leaves the stored value
  untouched** when it does not;
* a ``create(key) == 0`` comparison succeeds only when the key is absent;
* a lease is bound to the keys it is attached to, so revoking it — or
  letting it expire — removes those keys.

A fake that only records the calls it was asked to make cannot catch a CAS
bug, because the bug *is* the verdict: a transaction whose comparison did
not hold must report ``succeeded=False`` and change nothing. So this fake
evaluates the comparisons against real state.

The fake is both the key-value seam and the lease factory, because the two
share the store: a key's lease is what decides whether the key survives
its lease's expiry.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from security_gateway.vault.etcdstore.cluster import LeasePutOp
from security_gateway.vault.etcdstore.store import (
    Compare,
    DeleteOp,
    KVValue,
    Operation,
    PutOp,
    TxnResult,
)

__all__ = [
    "FakeKV",
    "FakeLease",
    "FakeLeaseNotFoundError",
    "make_cluster",
    "fake_kv",
    "fake_leases",
]


class FakeLeaseNotFoundError(Exception):
    """The lease does not exist — etcd's ``ErrLeaseNotFound``."""


@dataclass
class _Entry:
    """One stored key."""

    value: bytes
    create_revision: int
    mod_revision: int
    version: int
    lease: int = 0


@dataclass
class _LeaseState:
    """One granted lease."""

    lease_id: int
    ttl: int
    alive: bool = True
    keys: set[str] = field(default_factory=set)


class FakeLease:
    """A handle onto one lease, satisfying the shared ``Lease`` protocol."""

    def __init__(self, owner: FakeKV, ttl: int, lease_id: int | None = None) -> None:
        self._owner = owner
        self._ttl = ttl
        self._lease_id = lease_id or 0

    @property
    def id(self) -> int:
        """The lease id."""
        if not self._lease_id:
            raise FakeLeaseNotFoundError("the lease has not been granted yet")
        return self._lease_id

    def grant(self) -> int:
        """Create the lease and return its id."""
        if self._lease_id:
            return self._lease_id
        self._lease_id = self._owner.grant_lease(self._ttl)
        return self._lease_id

    def revoke(self) -> None:
        """Revoke the lease, removing every key attached to it."""
        if not self._lease_id:
            return
        self._owner.revoke_lease(self._lease_id)

    def keepalive(self) -> int:
        """Send one keepalive and return the granted TTL."""
        if not self._lease_id:
            raise FakeLeaseNotFoundError("the lease has not been granted yet")
        return self._owner.keepalive_lease(self._lease_id)


class FakeKV:
    """An in-memory etcd.

    It satisfies the shared ``KV`` protocol and the lease factory protocol
    at the same time, because the two share one store.
    """

    def __init__(self) -> None:
        self._store: dict[str, _Entry] = {}
        self._revision = 0
        self._leases: dict[int, _LeaseState] = {}
        self._next_lease_id = 0

    # -- the key-value seam ------------------------------------------------

    def get(self, key: str) -> KVValue | None:
        """Read one key, or ``None`` when it does not exist."""
        entry = self._store.get(key)
        if entry is None:
            return None
        return _to_kvvalue(key, entry)

    def get_range(
        self,
        range_start: str,
        range_end: str | None = None,
        limit: int = 0,
    ) -> tuple[int, list[KVValue]]:
        """Read the range ``[range_start, range_end)``."""
        keys = sorted(self._store)
        selected = [key for key in keys if key >= range_start]
        if range_end is not None:
            selected = [key for key in selected if key < range_end]
        if limit > 0:
            selected = selected[:limit]
        return self._revision, [_to_kvvalue(key, self._store[key]) for key in selected]

    def put(self, key: str, value: bytes, lease: int = 0) -> int:
        """Write a key and return the revision the write landed at.

        A key carries at most one lease: writing it with a new lease moves
        it off the old one, which is what etcd does and what lets a node
        republish its presence marker under a fresh lease.
        """
        if lease:
            self._leases.setdefault(lease, _LeaseState(lease_id=lease, ttl=0)).keys.add(
                key
            )
        self._revision += 1
        revision = self._revision
        entry = self._store.get(key)
        if entry is None:
            self._store[key] = _Entry(
                value=bytes(value),
                create_revision=revision,
                mod_revision=revision,
                version=1,
                lease=lease,
            )
        else:
            if entry.lease and entry.lease != lease:
                self._leases.get(entry.lease, _LeaseState(entry.lease, 0)).keys.discard(
                    key
                )
            entry.value = bytes(value)
            entry.mod_revision = revision
            entry.version += 1
            entry.lease = lease
        return revision

    def delete(self, key: str) -> int:
        """Delete a key and return the revision the delete landed at.

        Deleting a key that is not there changes nothing, which is what
        etcd does: no write, no new revision.
        """
        entry = self._store.pop(key, None)
        if entry is None:
            return self._revision
        if entry.lease:
            state = self._leases.get(entry.lease)
            if state is not None:
                state.keys.discard(key)
        self._revision += 1
        return self._revision

    def transaction(
        self,
        compare: Sequence[Compare],
        success: Sequence[Operation],
        failure: Sequence[Operation] = (),
    ) -> TxnResult:
        """Run a transaction and report its verdict.

        When the comparison does not hold, **nothing is written** and the
        result's ``succeeded`` is ``False``. That is not an error, and it
        must not be reported as one.
        """
        if not all(self._evaluate(item) for item in compare):
            return TxnResult(succeeded=False, revision=self._revision)
        revisions: list[int] = []
        for op in success:
            if isinstance(op, LeasePutOp):
                revisions.append(self.put(op.key, op.value, lease=op.lease))
            elif isinstance(op, PutOp):
                revisions.append(self.put(op.key, op.value))
            elif isinstance(op, DeleteOp):
                revisions.append(self.delete(op.key))
            else:
                raise ValueError(f"etcdstore: unknown operation {type(op).__name__}")
        return TxnResult(
            succeeded=True,
            revision=revisions[-1] if revisions else self._revision,
        )

    # -- the lease factory -------------------------------------------------

    def lease(self, ttl_seconds: int, lease_id: int | None = None) -> FakeLease:
        """Return a handle onto a lease with the given TTL.

        With ``lease_id``, the handle is onto an existing lease — which is
        how a revoke or a keepalive reaches a lease granted earlier.
        """
        if lease_id is not None:
            if lease_id not in self._leases:
                raise FakeLeaseNotFoundError(
                    f"etcdserver: requested lease not found ({lease_id})"
                )
            return FakeLease(self, ttl_seconds, lease_id)
        return FakeLease(self, ttl_seconds)

    def expire_lease(self, lease_id: int) -> None:
        """Let a lease expire, the way etcd does when a holder stops renewing.

        This is the "the holder died" case: the keys attached to the lease
        disappear and the lock is free for the next candidate.
        """
        state = self._leases.get(lease_id)
        if state is None:
            raise FakeLeaseNotFoundError(
                f"etcdserver: requested lease not found ({lease_id})"
            )
        for key in list(state.keys):
            self._store.pop(key, None)
        state.keys.clear()
        state.alive = False

    # -- internals ---------------------------------------------------------

    def grant_lease(self, ttl: int) -> int:
        """Grant a lease that lives for ``ttl`` seconds."""
        self._next_lease_id += 1
        lease_id = self._next_lease_id
        self._leases[lease_id] = _LeaseState(lease_id=lease_id, ttl=ttl)
        return lease_id

    def revoke_lease(self, lease_id: int) -> None:
        """Revoke a lease and drop the keys it held."""
        state = self._leases.get(lease_id)
        if state is None or not state.alive:
            raise FakeLeaseNotFoundError(
                f"etcdserver: requested lease not found ({lease_id})"
            )
        for key in list(state.keys):
            self._store.pop(key, None)
        state.keys.clear()
        state.alive = False

    def keepalive_lease(self, lease_id: int) -> int:
        """Keep a lease alive and report the TTL it was granted."""
        state = self._leases.get(lease_id)
        if state is None or not state.alive:
            raise FakeLeaseNotFoundError(
                f"etcdserver: requested lease not found ({lease_id})"
            )
        return state.ttl

    def _evaluate(self, compare: Compare) -> bool:
        """Evaluate one comparison against the store.

        The absent-key cases matter: etcd reports a create revision, a mod
        revision and a version of ``0`` for a key that does not exist, so
        ``create == 0`` is "the key does not exist yet" and ``mod == 0``
        would match a key that was never written.
        """
        entry = self._store.get(compare.key)
        target = compare.target
        if target == "create":
            actual = entry.create_revision if entry is not None else 0
            return actual == int(compare.value)
        if target == "mod":
            actual = entry.mod_revision if entry is not None else 0
            return actual == int(compare.value)
        if target == "version":
            actual = entry.version if entry is not None else 0
            return actual == int(compare.value)
        if target == "value":
            actual = entry.value if entry is not None else b""
            return actual == bytes(compare.value)
        raise ValueError(f"etcdstore: unknown compare target {target!r}")

    # -- test helpers ------------------------------------------------------

    def raw(self, key: str) -> bytes | None:
        """The stored bytes of a key, or ``None``."""
        entry = self._store.get(key)
        return None if entry is None else entry.value

    def exists(self, key: str) -> bool:
        """Whether a key is present."""
        return key in self._store

    def lease_alive(self, lease_id: int) -> bool:
        """Whether a lease is still alive."""
        state = self._leases.get(lease_id)
        return bool(state and state.alive)

    def keys(self) -> Iterable[str]:
        """Every key in the store."""
        return tuple(sorted(self._store))


def _to_kvvalue(key: str, entry: _Entry) -> KVValue:
    return KVValue(
        key=key.encode("utf-8", "surrogateescape"),
        value=entry.value,
        mod_revision=entry.mod_revision,
        create_revision=entry.create_revision,
        version=entry.version,
        lease=entry.lease,
    )


# -- fixtures ---------------------------------------------------------------


def fake_kv() -> FakeKV:
    """A fresh fake etcd."""
    return FakeKV()


def fake_leases(kv: FakeKV) -> FakeKV:
    """The lease factory of a fake etcd.

    The fake is its own factory: the lease and the key-value seam share
    one store, because a key's lease is what decides whether the key
    survives the lease's expiry.
    """
    return kv


def make_cluster(kv: FakeKV, ns: str = "prod") -> Any:
    """A :class:`~security_gateway.vault.etcdstore.cluster.Cluster` over a fake."""
    from security_gateway.vault.etcdstore.cluster import Cluster

    return Cluster(kv, ns, kv)
