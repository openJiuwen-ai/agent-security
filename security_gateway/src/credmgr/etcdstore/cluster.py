"""The cluster control plane: membership, presence, the generation fence.

The Go original is ``internal/credmgr/etcdstore/cluster.go``.

Keyspace. Two separate sub-trees, none of them under the credential
prefix, so the credential syncer's range over ``/creds/`` can never pick
any of this up — not even to try and fail to decode it::

    /security_gateway/<ns>/nodes/<node_id>    public key + metadata, not secret
    /security_gateway/<ns>/mint                who minted the current DEK
    /security_gateway/<ns>/presence/<node_id>  liveness marker, leased
    /security_gateway/<ns>/rotation/<node_id>  a rotation that was started
    /security_gateway/<ns>/takeover            the single takeover claim
    /security_gateway/<ns>/generation          the DEK generation fence
    /security_gateway/<ns>/last_rotation       when a rotation last completed

The rules:

* Nothing under ``/nodes/`` is secret: every value is a public key.
* The presence marker, the takeover claim and the rotation lock are
  leased: a node that stops renewing disappears on its own.
* A leased write is not optional: the presence marker *is* a leased
  write, and a marker written without its lease would mark a dead node
  present forever.
* The shared seam (``store.py``) carries no leases: the lease handle and
  the leased write live here — :class:`LeaseFactory`, :class:`LeasePutOp`.
"""

from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, runtime_checkable

from .cluster_keys import (
    LAST_ROTATION_SEGMENT,
    MINT_SEGMENT,
    NODE_PREFIX_SEGMENT,
    PRESENCE_SEGMENT,
    ROTATION_MARKER_SEGMENT,
    TAKEOVER_SEGMENT,
    NodeEntry,
    _key_text,
    _marshal_node_entry,
    _parse_int,
    _unmarshal_node_entry,
    generation_key,
    last_rotation_key,
    mint_key,
    node_key,
    nodes_prefix,
    prefix_end,
    presence_key,
    presence_prefix,
    rotation_marker_key,
    rotation_marker_prefix,
    takeover_key,
)
from .entry import unmarshal_entry
from .errors import (
    ConflictError,
    EtcdStoreError,
    InvalidValueError,
    NotFoundError,
    remap_compacted,
)
from .keys import KEYSPACE_PREFIX, creds_prefix
from .rotation import format_rfc3339_nano, parse_rfc3339_nano
from .store import (
    KV,
    Compare,
    KVValue,
    Lease,
    Operation,
    PutOp,
    TxnResult,
    compare_create,
    compare_value,
)

__all__ = [
    "KEYSPACE_PREFIX",
    "LAST_ROTATION_SEGMENT",
    "LIST_NODES_LIMIT",
    "MINT_SEGMENT",
    "NODE_PREFIX_SEGMENT",
    "PRESENCE_SEGMENT",
    "PRESENCE_TTL_SECONDS",
    "ROTATION_MARKER_SEGMENT",
    "TAKEOVER_SEGMENT",
    "TAKEOVER_TTL_SECONDS",
    "Cluster",
    "FencedError",
    "LeaseFactory",
    "LeasePutOp",
    "LeaseSupportError",
    "NodeEntry",
    "StalledMarker",
    "advance_generation",
    "claim_mint",
    "claim_takeover",
    "count_entries_below_dek_version",
    "delete_rotation_marker",
    "drop_presence",
    "ensure_generation",
    "fenced",
    "fenced_error",
    "generation",
    "generation_key",
    "get_node",
    "is_present",
    "last_rotation_at",
    "last_rotation_key",
    "list_nodes",
    "list_present",
    "mint_key",
    "mint_owner",
    "node_key",
    "nodes_prefix",
    "presence_key",
    "presence_prefix",
    "prefix_end",
    "put_presence",
    "put_rotation_marker",
    "read_generation",
    "register_node",
    "release_takeover",
    "renew_presence",
    "rotation_marker_key",
    "rotation_marker_prefix",
    "set_last_rotation_at",
    "stalled_rotation_targets",
    "stalled_rotations",
    "takeover_key",
]

_log = logging.getLogger(__name__)

#: The subtree the roster lives under.
#: The key recording which node minted the current DEK.
#: The subtree the liveness markers live under.
#: The subtree the in-flight rotation markers live under.
#: The key that arbitrates a single takeover.
#: The key recording when a rotation last completed cluster-wide.
#: Caps a roster read. A cluster with more members than this is not a
#: cluster, it is a bug; failing loudly beats silently truncating and
#: leaving a node unwrapped.
LIST_NODES_LIMIT = 1024

#: How long a node stays present after it stops renewing: long enough that
#: one slow etcd round trip is not mistaken for a death, short enough that a
#: takeover does not sit waiting.
PRESENCE_TTL_SECONDS = 15

#: Bounds how long a single node may hold the takeover claim. It has to be
#: short enough that a node which dies partway through does not block the
#: cluster indefinitely, and long enough that a takeover which is
#: progressing is not stolen out from under it.
TAKEOVER_TTL_SECONDS = 90


class LeaseSupportError(EtcdStoreError):
    """The key-value seam in use cannot carry a lease.

    Raised when a leased write reaches a ``KV`` with no lease-aware
    ``put``: dropping the lease silently would mark a dead node present
    forever.
    """


@runtime_checkable
class LeaseFactory(Protocol):
    """Mints lease handles.

    Produces a handle for a given TTL, or onto an existing lease when
    ``lease_id`` is passed.
    """

    def lease(self, ttl_seconds: int, lease_id: int | None = None) -> Lease:
        """Return a handle onto a lease with the given TTL."""
        ...


@dataclass(frozen=True)
class LeasePutOp:
    """A write inside a transaction that carries a lease.

    Deliberately not the shared ``PutOp``: a subclass would be
    translated into a plain write, silently dropping the lease.
    """

    key: str
    value: bytes
    lease: int


@dataclass(frozen=True)
class StalledMarker:
    """One stalled holder's marker: the node, and the target generation exactly as it was written.

    The value is carried unparsed: parsing it here would force one of
    the two readers to be wrong.
    """

    node_id: str
    value: str


class FencedError(EtcdStoreError):
    """``ErrFenced`` — a write arrived stamped with a DEK generation the authority does not hold.

    The writer holds a real key and produced real ciphertext; it is
    simply a key nobody else can read with any more.
    """


# -- the keyspace ----------------------------------------------------------


# -- the cluster ------------------------------------------------------------


class Cluster:
    """The cluster control plane for one namespace.

    The namespace is held on the handle, so the API stays short:
    ``claim_mint``, not ``claim_mint_in_namespace``.
    """

    def __init__(self, kv: KV, ns: str, leases: LeaseFactory) -> None:
        """``leases`` mints lease handles; it is separate from ``kv`` because the shared seam carries no leases of its own."""
        self._kv = kv
        self._ns = ns
        self._leases = leases

    @property
    def kv(self) -> KV:
        """The key-value seam this cluster talks to."""
        return self._kv

    @property
    def ns(self) -> str:
        """The namespace this cluster holds."""
        return self._ns

    @property
    def leases(self) -> LeaseFactory:
        """The lease factory this cluster mints its leases from."""
        return self._leases

    # -- the roster --------------------------------------------------------

    def register_node(self, entry: NodeEntry) -> None:
        """Publish or refresh this node's roster entry."""
        if not entry.node_id:
            raise InvalidValueError("etcdstore: register node: empty node id")
        if not entry.cert_der:
            raise InvalidValueError(f"etcdstore: register node {entry.node_id!r}: empty certificate")
        try:
            base64.b64decode(entry.cert_der, validate=True)
        except ValueError as exc:
            raise InvalidValueError(
                f"etcdstore: register node {entry.node_id!r}: certificate is not base64: {exc}"
            ) from exc
        self._kv.put(node_key(self._ns, entry.node_id), _marshal_node_entry(entry))

    def get_node(self, node_id: str) -> NodeEntry:
        """Read one roster entry, or raise ``NotFoundError``."""
        if not node_id:
            raise InvalidValueError("etcdstore: read a roster entry: empty node id")
        found = self._get(node_key(self._ns, node_id))
        if found is None:
            raise NotFoundError(f"etcdstore: no roster entry for {node_id!r}")
        return _unmarshal_node_entry(found.value, node_id)

    def list_nodes(self) -> list[NodeEntry]:
        """Return the roster sorted by node id, skipping entries that do not decode.

        An undecodable node is one nobody can wrap for, but refusing to
        serve the rest over it would turn one bad write into a
        fleet-wide outage.
        """
        prefix = nodes_prefix(self._ns)
        _, values = self._get_range(prefix, LIST_NODES_LIMIT)
        entries: list[NodeEntry] = []
        for value in values:
            try:
                entry = _unmarshal_node_entry(value.value)
            except InvalidValueError:
                continue
            if not entry.node_id or not entry.cert_der:
                continue
            entries.append(entry)
        entries.sort(key=lambda item: item.node_id)
        return entries

    def claim_mint(self, node_id: str) -> bool:
        """Elect the node that mints the first DEK.

        The guard is ``create_revision(key) == 0``, true only for a key
        that never existed, so exactly one caller can succeed however
        many race.
        """
        if not node_id:
            raise InvalidValueError("etcdstore: claim mint: empty node id")
        key = mint_key(self._ns)
        result = self._txn([compare_create(key)], [PutOp(key, node_id.encode("utf-8"))])
        # A failed transaction comparison is not an error, so this check is
        # the only thing standing between a lost race and a forked cluster.
        return result.succeeded

    def mint_owner(self) -> str:
        """Report which node minted the current DEK.

        Raises ``NotFoundError`` when the namespace has no mint record.
        """
        found = self._get(mint_key(self._ns))
        if found is None:
            raise NotFoundError(f"etcdstore: namespace {self._ns!r} has no mint record")
        return found.value.decode("utf-8", "surrogateescape")

    # -- presence ----------------------------------------------------------

    def put_presence(
        self,
        node_id: str,
        generation: int,
        ttl_seconds: int = PRESENCE_TTL_SECONDS,
    ) -> int:
        """Publish that ``node_id`` is alive and holding ``generation``.

        A new lease each time: a node partitioned long enough to lose
        its old lease should not come back holding one etcd still
        believes is alive.
        """
        lease = self._leases.lease(ttl_seconds)
        lease_id = lease.grant()
        try:
            self._put_leased(
                presence_key(self._ns, node_id),
                str(int(generation)).encode("utf-8"),
                lease_id,
            )
        except Exception:
            # Leave nothing behind: an orphaned lease keeps the node marked
            # present for the full TTL even though the write never landed.
            try:
                lease.revoke()
            except Exception:  # noqa: BLE001 - the original error matters more
                pass
            raise
        return lease_id

    def renew_presence(self, lease_id: int) -> None:
        """Extend the node's presence lease by one TTL."""
        if not lease_id:
            return
        self._leases.lease(0, lease_id).keepalive()

    def drop_presence(self, lease_id: int) -> None:
        """Revoke a presence lease without waiting for it to expire."""
        if not lease_id:
            return
        self._leases.lease(0, lease_id).revoke()

    def list_present(self) -> dict[str, int]:
        """Return the generation every live node currently claims, keyed by node id."""
        prefix = presence_prefix(self._ns)
        _, values = self._get_range(prefix, 0)
        present: dict[str, int] = {}
        for value in values:
            node_id = _key_text(value.key)[len(prefix) :]
            present[node_id] = _parse_int(value.value.decode("utf-8", "surrogateescape"))
        return present

    def is_present(self, node_id: str) -> bool:
        """Report whether one node currently holds a presence marker."""
        # Deliberately not a count-only read: it costs a response field the
        # fake does not populate, so the check would answer false for every
        # node under test.
        return self._get(presence_key(self._ns, node_id)) is not None

    # -- rotation markers --------------------------------------------------

    def put_rotation_marker(self, node_id: str, target_version: int) -> None:
        """Record that ``node_id`` started a rotation toward ``target_version``."""
        self._kv.put(
            rotation_marker_key(self._ns, node_id),
            str(int(target_version)).encode("utf-8"),
        )

    def delete_rotation_marker(self, node_id: str) -> None:
        """Clear a node's rotation marker."""
        self._kv.delete(rotation_marker_key(self._ns, node_id))

    def stalled_markers(self) -> list[StalledMarker]:
        """The single marker read both public views derive from."""
        prefix = rotation_marker_prefix(self._ns)
        _, values = self._get_range(prefix, 0)
        markers: list[StalledMarker] = []
        for value in values:
            node_id = _key_text(value.key)[len(prefix) :]
            if self.is_present(node_id):
                continue
            markers.append(
                StalledMarker(
                    node_id=node_id,
                    value=value.value.decode("utf-8", "surrogateescape"),
                )
            )
        return markers

    def stalled_rotation_targets(self) -> dict[str, int]:
        """For every node that wrote a rotation marker and is no longer present, the DEK generation that rotation was heading for."""
        targets: dict[str, int] = {}
        for marker in self.stalled_markers():
            try:
                targets[marker.node_id] = _parse_int(marker.value)
            except ValueError:
                _log.warning(
                    "rotation marker holds no readable target generation",
                    extra={"namespace": self._ns, "node_id": marker.node_id, "value": marker.value},
                )
                continue
        return targets

    def stalled_rotations(self) -> list[str]:
        """The node ids that wrote a rotation marker and are no longer present."""
        stalled = [marker.node_id for marker in self.stalled_markers()]
        # Sorted because callers rely on the ascending node id order the
        # keys-only range read used to return.
        return sorted(stalled)

    # -- the generation fence ----------------------------------------------

    def read_generation(self) -> tuple[int, bool]:
        """The authority's generation and whether the record exists."""
        found = self._get(generation_key(self._ns))
        if found is None:
            return 1, False
        return _parse_int(found.value.decode("utf-8", "surrogateescape")), True

    def generation(self) -> int:
        """The authority's current DEK generation."""
        value, _ = self.read_generation()
        return value

    def advance_generation(self, target: int) -> tuple[bool, int]:
        """Move the authority's DEK generation to ``target``.

        The rules:

        * the record already says ``target`` → nothing to do, and the call
          succeeds; a takeover whose holder had already moved the fence
          lands here, and it must not be treated as a failure.
        * the record says something below ``target`` → compare-and-set from
          what it says now to ``target``.
        * the record says something above ``target`` → refused.

        Moving a fence back would let a fenced-out writer back in, and the
        entries written under the generation the authority has left behind
        are stranded. A generation only ever moves forward.

        The compare-and-set makes the middle case safe against a second
        mover: the transaction fires only if the record still holds the
        value the caller read. The record is created when absent, at
        generation 1.

        Returns ``(advanced, current)``.
        """
        key = generation_key(self._ns)
        target_value = str(int(target)).encode("utf-8")
        for _attempt in range(4):
            current, present = self.read_generation()
            if present and current == target:
                return False, current
            if present and current > target:
                raise FencedError(
                    f"etcdstore: the authority holds generation {current}, which is ahead of "
                    f"the requested {target}; moving a generation back is refused because it "
                    "would let a fenced-out writer back in and strand the entries written "
                    "under the generation the authority has already left"
                )
            if present:
                result = self._txn(
                    [compare_value(key, str(current).encode("utf-8"))],
                    [PutOp(key, target_value)],
                )
            else:
                result = self._txn([compare_create(key)], [PutOp(key, target_value)])
            if result.succeeded:
                return True, target
            # Somebody moved the record between the read and the
            # transaction; read it again and decide afresh.
        raise ConflictError("etcdstore: the authority's generation did not settle after 4 attempts")

    def ensure_generation(self) -> None:
        """Seed the generation record at 1 when the namespace has none, so the fence comparison has something real to match."""
        key = generation_key(self._ns)
        self._txn([compare_create(key)], [PutOp(key, b"1")])

    def fenced(self, writer_generation: int) -> tuple[bool, int]:
        """Report whether a writer may not write, and what the authority holds when it may not."""
        current = self.generation()
        return current != int(writer_generation), current

    # -- the rotation gate -------------------------------------------------

    def set_last_rotation_at(self, at: datetime) -> None:
        """Record that a rotation completed at ``at``."""
        if at is None:
            raise InvalidValueError("etcdstore: last rotation time must not be zero")
        # RFC3339Nano in UTC rather than unix seconds: this one is read by
        # an operator with etcdctl as often as it is read by code.
        self._kv.put(last_rotation_key(self._ns), format_rfc3339_nano(at).encode("utf-8"))

    def last_rotation_at(self) -> datetime:
        """When a rotation last completed, or raise ``NotFoundError``.

        Not a zero time: "no record" means a cluster that has never
        rotated and is due; a caller that cannot tell them apart would
        freeze it.
        """
        found = self._get(last_rotation_key(self._ns))
        if found is None:
            raise NotFoundError(f"etcdstore: namespace {self._ns!r} has completed no rotation")
        raw = found.value.decode("utf-8", "surrogateescape")
        try:
            return parse_rfc3339_nano(raw)
        except ValueError as exc:
            # A value nobody can read is not "not found": the cluster has
            # rotated, the record of when is corrupt.
            raise InvalidValueError(f"etcdstore: last-rotation record holds {raw!r}: {exc}") from exc

    # -- the takeover ------------------------------------------------------

    def claim_takeover(self, node_id: str, ttl_seconds: int = TAKEOVER_TTL_SECONDS) -> bool:
        """Become the node responsible for resolving a stalled rotation."""
        if ttl_seconds <= 0:
            ttl_seconds = TAKEOVER_TTL_SECONDS
        key = takeover_key(self._ns)
        lease = self._leases.lease(ttl_seconds)
        lease_id = lease.grant()
        result = self._txn(
            [compare_create(key)],
            [LeasePutOp(key, node_id.encode("utf-8"), lease_id)],
        )
        if not result.succeeded:
            # Someone else holds it; this lease was never attached to
            # anything, so revoking it is just tidying up.
            try:
                lease.revoke()
            except Exception:  # noqa: BLE001 - the claim outcome matters more
                pass
            return False
        return True

    def release_takeover(self) -> None:
        """Drop the claim by revoking its lease rather than deleting the key.

        A holder returning after a partition must not delete the claim
        the current holder relies on; the release revokes the lease the
        key holds.
        """
        found = self._get(takeover_key(self._ns))
        if found is None or not found.lease:
            return
        self._leases.lease(0, found.lease).revoke()

    # -- the authority's own rows ------------------------------------------

    def count_entries_below_dek_version(self, target: int) -> int:
        """Report how many authority entries are still stamped below ``target``."""
        prefix = creds_prefix(self._ns)
        _, values = self._get_range(prefix, 0)
        below = 0
        for value in values:
            try:
                entry = unmarshal_entry(value.value)
            except InvalidValueError:
                # One unreadable row is not a reason to stop counting the
                # others; the same reasoning the roster lister uses.
                continue
            if entry.dek_version < target:
                below += 1
        return below

    # -- the seam ----------------------------------------------------------

    def _get(self, key: str) -> KVValue | None:
        try:
            return self._kv.get(key)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _get_range(self, prefix: str, limit: int) -> tuple[int, list[KVValue]]:
        try:
            return self._kv.get_range(prefix, prefix_end(prefix), limit)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _txn(self, compare: list[Compare], success: list[Operation]) -> TxnResult:
        """Run a transaction and remap a compaction error.

        The verdict is *not* interpreted here: the caller checks
        ``succeeded`` and raises the conflict.
        """
        try:
            return self._kv.transaction(compare, success)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _put_leased(self, key: str, value: bytes, lease_id: int) -> int:
        """Write a key under a lease.

        The shared seam's ``put`` has no lease parameter, so a KV that
        cannot carry one is a loud failure rather than a silent loss of
        expiry.
        """
        try:
            return self._kv.put(key, value, lease=lease_id)
        except TypeError as exc:
            raise LeaseSupportError(
                "etcdstore: this key-value seam cannot carry a lease; a leased write "
                "would mark a dead node present forever"
            ) from exc


# -- module-level functions -------------------------------------------------
#
# Free functions, so the namespace and the seam are explicit at the call
# site and the class above stays the single place the state lives.


def register_node(kv: KV, ns: str, entry: NodeEntry) -> None:
    """Publish or refresh a roster entry."""
    Cluster(kv, ns, _NullLeases()).register_node(entry)


def get_node(kv: KV, ns: str, node_id: str) -> NodeEntry:
    """Read one roster entry."""
    return Cluster(kv, ns, _NullLeases()).get_node(node_id)


def list_nodes(kv: KV, ns: str) -> list[NodeEntry]:
    """List the roster."""
    return Cluster(kv, ns, _NullLeases()).list_nodes()


def claim_mint(kv: KV, ns: str, node_id: str) -> bool:
    """Elect the minting node."""
    return Cluster(kv, ns, _NullLeases()).claim_mint(node_id)


def mint_owner(kv: KV, ns: str) -> str:
    """Report the minting node."""
    return Cluster(kv, ns, _NullLeases()).mint_owner()


def put_presence(
    kv: KV,
    leases: LeaseFactory,
    ns: str,
    node_id: str,
    generation: int,
    ttl_seconds: int = PRESENCE_TTL_SECONDS,
) -> int:
    """Publish a presence marker."""
    return Cluster(kv, ns, leases).put_presence(node_id, generation, ttl_seconds)


def renew_presence(leases: LeaseFactory, lease_id: int) -> None:
    """Renew a presence lease."""
    if not lease_id:
        return
    leases.lease(0, lease_id).keepalive()


def drop_presence(leases: LeaseFactory, lease_id: int) -> None:
    """Revoke a presence lease."""
    if not lease_id:
        return
    leases.lease(0, lease_id).revoke()


def list_present(kv: KV, ns: str) -> dict[str, int]:
    """List the presence markers."""
    return Cluster(kv, ns, _NullLeases()).list_present()


def is_present(kv: KV, ns: str, node_id: str) -> bool:
    """Report whether a node is present."""
    return Cluster(kv, ns, _NullLeases()).is_present(node_id)


def put_rotation_marker(kv: KV, ns: str, node_id: str, target_version: int) -> None:
    """Write a rotation marker."""
    Cluster(kv, ns, _NullLeases()).put_rotation_marker(node_id, target_version)


def delete_rotation_marker(kv: KV, ns: str, node_id: str) -> None:
    """Clear a rotation marker."""
    Cluster(kv, ns, _NullLeases()).delete_rotation_marker(node_id)


def stalled_rotation_targets(kv: KV, ns: str) -> dict[str, int]:
    """Report the stalled rotations and their targets."""
    return Cluster(kv, ns, _NullLeases()).stalled_rotation_targets()


def stalled_rotations(kv: KV, ns: str) -> list[str]:
    """Report the stalled rotations by node id."""
    return Cluster(kv, ns, _NullLeases()).stalled_rotations()


def read_generation(kv: KV, ns: str) -> tuple[int, bool]:
    """Read the generation record."""
    return Cluster(kv, ns, _NullLeases()).read_generation()


def generation(kv: KV, ns: str) -> int:
    """Read the authority's generation."""
    return Cluster(kv, ns, _NullLeases()).generation()


def advance_generation(kv: KV, ns: str, target: int) -> tuple[bool, int]:
    """Move the generation fence."""
    return Cluster(kv, ns, _NullLeases()).advance_generation(target)


def ensure_generation(kv: KV, ns: str) -> None:
    """Seed the generation record."""
    Cluster(kv, ns, _NullLeases()).ensure_generation()


def fenced(kv: KV, ns: str, writer_generation: int) -> tuple[bool, int]:
    """Report whether a writer is fenced out."""
    return Cluster(kv, ns, _NullLeases()).fenced(writer_generation)


def fenced_error(writer: int, authority: int) -> FencedError:
    """The error a fenced write raises.

    It names both generations and which side is wrong, because the
    verdict is an inequality and "older" is only one of the two ways to
    fail it.
    """
    side = "behind" if writer <= authority else "ahead of"
    return FencedError(
        f"etcdstore: writer is on an older DEK generation than the authority: this writer "
        f"holds generation {writer} and the authority holds {authority}, so the writer is "
        f"{side} the authority"
    )


def set_last_rotation_at(kv: KV, ns: str, at: datetime) -> None:
    """Record the last completed rotation."""
    Cluster(kv, ns, _NullLeases()).set_last_rotation_at(at)


def last_rotation_at(kv: KV, ns: str) -> datetime:
    """Read the last completed rotation."""
    return Cluster(kv, ns, _NullLeases()).last_rotation_at()


def claim_takeover(
    kv: KV, leases: LeaseFactory, ns: str, node_id: str, ttl_seconds: int = TAKEOVER_TTL_SECONDS
) -> bool:
    """Claim the takeover."""
    return Cluster(kv, ns, leases).claim_takeover(node_id, ttl_seconds)


def release_takeover(kv: KV, leases: LeaseFactory, ns: str) -> None:
    """Release the takeover claim."""
    Cluster(kv, ns, leases).release_takeover()


def count_entries_below_dek_version(kv: KV, ns: str, target: int) -> int:
    """Count the authority's rows below a generation."""
    return Cluster(kv, ns, _NullLeases()).count_entries_below_dek_version(target)


# -- helpers ----------------------------------------------------------------


class _NullLeases:
    """A lease factory that refuses to be used.

    The free functions above take only the seam; this placeholder keeps
    them honest, so a function that needs a lease asks for one
    explicitly.
    """

    def lease(self, ttl_seconds: int, lease_id: int | None = None) -> Lease:
        """Lease."""
        raise LeaseSupportError("etcdstore: this call needs a lease factory")
