"""One process per host leads the operations that must happen once.

The leader is elected with a lease on a host-scoped etcd key. It is not
a write-ownership lock: every process in the host reads and writes the
store. Leadership only decides which process mints the first key.
"""

from __future__ import annotations

import threading
from typing import Any, cast

from .cluster import LeaseFactory, LeasePutOp
from .cluster_keys import host_leader_key
from .errors import InvalidValueError
from .lock import _discard, _is_lease_not_found
from .store import KV, compare_create

__all__ = ["HostLeader", "acquire_host_leader"]


def acquire_host_leader(
    kv: KV,
    leases: LeaseFactory,
    ns: str,
    node_id: str,
    holder: str,
    ttl_seconds: int = 10,
) -> HostLeader | None:
    """Try to become the process leading ``node_id`` on this host."""
    if not node_id:
        raise InvalidValueError("etcdstore: host leader node id must be non-empty")
    if not holder:
        raise InvalidValueError("etcdstore: host leader holder must be non-empty")
    if ttl_seconds <= 0:
        raise InvalidValueError(
            f"etcdstore: host leader ttl must be positive, got {ttl_seconds}"
        )
    leader = HostLeader(kv, leases, ns, node_id, holder, ttl_seconds)
    return leader if leader.acquire() else None


class HostLeader:
    """A held host-leader lease.

    The caller owns the heartbeat's lifecycle: :meth:`start` begins it,
    :meth:`stop` ends it, and :meth:`release` drops the lease.
    """

    def __init__(
        self,
        kv: KV,
        leases: LeaseFactory,
        ns: str,
        node_id: str,
        holder: str,
        ttl_seconds: int = 10,
    ) -> None:
        self._kv = kv
        self._leases = leases
        self._ns = ns
        self._node_id = node_id
        self._holder = holder
        self._ttl = ttl_seconds
        self._key = host_leader_key(ns, node_id)
        self._lease_id: int | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def lease_id(self) -> int | None:
        """The backing lease, or ``None`` when not held."""
        return self._lease_id

    def acquire(self) -> bool:
        """Take the host leadership if it is free."""
        if self._lease_id is not None:
            return True
        lease = self._leases.lease(self._ttl)
        lease_id = lease.grant()
        ops: list[Any] = [LeasePutOp(self._key, self._holder.encode(), lease_id)]
        try:
            result = self._kv.transaction([compare_create(self._key)], cast(Any, ops))
        except BaseException:
            _discard(lease)
            raise
        if not result.succeeded:
            _discard(lease)
            return False
        self._lease_id = lease_id
        return True

    def renew(self) -> None:
        """Extend the leadership lease by one TTL."""
        if self._lease_id is None:
            raise InvalidValueError("etcdstore: host leadership is not held")
        self._leases.lease(0, self._lease_id).keepalive()

    def release(self) -> None:
        """Drop the leadership lease."""
        lease_id = self._lease_id
        self._lease_id = None
        if lease_id is None:
            return
        try:
            self._leases.lease(0, lease_id).revoke()
        except Exception as exc:  # noqa: BLE001 - a gone lease is released
            if not _is_lease_not_found(exc):
                raise

    def start(self) -> None:
        """Start renewing the lease in the background."""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._heartbeat,
            name="cred-router-host-leader",
            daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        """Stop the heartbeat."""
        self._stop.set()
        thread = self._thread
        self._thread = None
        if thread is not None:
            thread.join(timeout=5.0)

    def _heartbeat(self) -> None:
        interval = max(self._ttl / 3.0, 0.05)
        while not self._stop.wait(interval):
            try:
                self.renew()
            except Exception:  # noqa: BLE001 - leadership is judged by this
                return
