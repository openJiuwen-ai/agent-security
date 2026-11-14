"""The authority's cluster half: roster, fence and handover keys.

The cluster half is written against the ``KV`` seam that
``security_gateway.vault.etcdstore`` publishes, so that the whole of it can
be driven from a fake that reproduces etcd's compare-and-swap.
:class:`ClusterStore` is a structural protocol, and anything that
implements it — this module's :class:`KVClusterStore` or the
``etcdstore``'s own ``Store`` — can be passed to the cluster-key
functions.

The keyspace
------------

::

    /security_gateway/<ns>/nodes/<node_id>
    /security_gateway/<ns>/nodes/
    /security_gateway/<ns>/mint
    /security_gateway/<ns>/presence/<node_id>
    /security_gateway/<ns>/presence/
    /security_gateway/<ns>/rotation/<node_id>
    /security_gateway/<ns>/rotation/
    /security_gateway/<ns>/takeover
    /security_gateway/<ns>/generation
    /security_gateway/<ns>/last_rotation
    /security_gateway/<ns>/handover/req/<node_id>/<nonce>
    /security_gateway/<ns>/handover/sealed/<node_id>/<nonce>

Note the asymmetry: ``generation`` sits directly under the namespace
with no segment slash, while ``nodes/``, ``presence/``, ``rotation/``,
``handover/req/`` and ``handover/sealed/`` carry one.  That asymmetry is
load-bearing for prefix scans, and it is why the helpers below are not
built from one another.
"""

from __future__ import annotations

import base64
import importlib
import json
from dataclasses import dataclass

from security_gateway.vault.etcdstore.errors import NotFoundError
from security_gateway.vault.etcdstore.keys import KEYSPACE_PREFIX, prefix_upper_bound
from security_gateway.vault.etcdstore.cluster import LeasePutOp
from security_gateway.vault.etcdstore.store import (
    KV,
    Compare,
    DeleteOp,
    PutOp,
    compare_create,
    compare_value,
)

__all__ = [
    "ClusterStore",
    "HandoverRequestEntry",
    "KVClusterStore",
    "NodeEntry",
    "RotationState",
    "generation_key",
    "handover_req_key",
    "handover_req_prefix",
    "handover_sealed_key",
    "mint_claim_key",
    "mint_key",
    "node_key",
    "nodes_prefix",
]

#: The length of the generation prefix on a stored handover answer.
#: Eight bytes big-endian keeps the value human-readable when it turns up
#: in ``etcdctl``, which is worth more than four bytes would save.
GENERATION_HEADER_SIZE = 8


def _etcd_key_helper(name: str):
    """Return the ``etcdstore``'s own key helper, if it has one."""
    module = importlib.import_module("security_gateway.vault.etcdstore.keys")
    return getattr(module, name, None)


def mint_claim_key(ns: str) -> str:
    """The leased mint claim: ``/security_gateway/<ns>/mint_claim``."""
    return f"{KEYSPACE_PREFIX}{ns}/mint_claim"


def node_key(ns: str, node_id: str) -> str:
    """The roster key: ``/security_gateway/<ns>/nodes/<node_id>``."""
    helper = _etcd_key_helper("node_key")
    if helper is not None:
        return helper(ns, node_id)
    return f"{KEYSPACE_PREFIX}{ns}/nodes/{node_id}"


def nodes_prefix(ns: str) -> str:
    """The roster subtree prefix: ``/security_gateway/<ns>/nodes/``."""
    helper = _etcd_key_helper("nodes_prefix")
    if helper is not None:
        return helper(ns)
    return f"{KEYSPACE_PREFIX}{ns}/nodes/"


def mint_key(ns: str) -> str:
    """The key recording which node minted the current DEK."""
    helper = _etcd_key_helper("mint_key")
    if helper is not None:
        return helper(ns)
    return f"{KEYSPACE_PREFIX}{ns}/mint"


def generation_key(ns: str) -> str:
    """The key recording the generation the authority's ciphertexts are written under."""
    helper = _etcd_key_helper("generation_key")
    if helper is not None:
        return helper(ns)
    return f"{KEYSPACE_PREFIX}{ns}/generation"


def handover_req_key(ns: str, node_id: str, nonce: str) -> str:
    """The key under which a node's DEK request lives."""
    helper = _etcd_key_helper("handover_req_key")
    if helper is not None:
        return helper(ns, node_id, nonce)
    return f"{KEYSPACE_PREFIX}{ns}/handover/req/{node_id}/{nonce}"


def handover_req_prefix(ns: str) -> str:
    """The prefix over every pending request in a namespace."""
    helper = _etcd_key_helper("handover_req_prefix")
    if helper is not None:
        return helper(ns)
    return f"{KEYSPACE_PREFIX}{ns}/handover/req/"


def handover_sealed_key(ns: str, node_id: str, nonce: str) -> str:
    """The key under which the holder's answer lives."""
    helper = _etcd_key_helper("handover_sealed_key")
    if helper is not None:
        return helper(ns, node_id, nonce)
    return f"{KEYSPACE_PREFIX}{ns}/handover/sealed/{node_id}/{nonce}"


@dataclass(frozen=True)
class NodeEntry:
    """What a node publishes about itself.

    None of it is secret, and none of it is trusted — the wrapping
    target is the public key, so a tampered entry can at worst waste a
    wrapping, never leak the DEK.
    """

    #: Names the node.
    node_id: str = ""

    #: The subject's whole certificate, base64. The full certificate rather
    #: than a bare public key because a wrapping node has to decide whether
    #: to seal the DEK to it, and that decision needs the issuer and the key
    #: usage — neither of which survives stripping a certificate down to its
    #: key.
    cert_der: str = ""

    #: The generation this node currently holds, which lets a wrapping node
    #: skip a stale registration.
    dek_version: int = 0


@dataclass(frozen=True)
class HandoverRequestEntry:
    """One pending request as a holder sees it."""

    #: Names the requester.
    node_id: str = ""

    #: Identifies this exchange.
    nonce: str = ""

    #: The request as the requester wrote it. It is opaque here: this layer
    #: stores bytes, and the shape belongs to whoever writes it.
    payload: bytes = b""


@dataclass(frozen=True)
class RotationState:
    """The value stored at ``/security_gateway/<ns>/rotation``.

    It carries the cross-node lock-holder identity and the in-progress
    rotation metadata, so an operator looking at ``etcdctl`` can answer
    "what is the cluster rotating right now?" without grepping logs.
    """

    #: The high-level rotation phase. The only value defined today is
    #: ``in_progress``.
    state: str = ""

    #: The stable identity of the node that acquired the rotation lock.
    holder: str = ""

    #: The DEK version the cluster is rotating *to*.
    target_dek_version: int = 0

    #: When the current rotation phase began, as RFC3339Nano.
    started_at: str = ""


#: The only rotation phase this package knows about.
ROTATION_STATE_IN_PROGRESS = "in_progress"


class ClusterStore:
    """What the cluster's own code needs of the authority.

    It is a base class rather than an abstract one: the ``etcdstore``'s
    ``Store`` satisfies it by having the same methods without inheriting
    from it, and so does :class:`KVClusterStore`. Nothing here is
    imported at module import time.
    """

    def register_node(self, entry: NodeEntry) -> None:
        """Publish or refresh this node's roster entry."""
        raise NotImplementedError

    def get_node(self, node_id: str) -> NodeEntry:
        """Read one roster entry, or raise ``NotFoundError``."""
        raise NotImplementedError

    def claim_mint(self, node_id: str) -> bool:
        """Elect the node that mints the first DEK.

        It reports whether this caller won. The guard is
        ``create_revision(key) == 0``, true only for a key that has
        never existed — so exactly one caller can ever succeed, no
        matter how many race.
        """
        raise NotImplementedError

    def mint_owner(self) -> str:
        """Report which node minted the current DEK."""
        raise NotImplementedError

    def advance_generation(self, target: int) -> tuple[bool, int]:
        """Move the authority's DEK generation to ``target``."""
        raise NotImplementedError

    def get_rotation_state(self) -> RotationState:
        """Read the rotation state, or raise ``NotFoundError``."""
        raise NotImplementedError

    def put_handover_request(self, node_id: str, nonce: str, payload: bytes) -> None:
        """Publish a request."""
        raise NotImplementedError

    def get_handover_sealed(self, node_id: str, nonce: str) -> tuple[int, bytes]:
        """Read the holder's answer, or raise ``NotFoundError``."""
        raise NotImplementedError

    def list_handover_requests(self) -> list[HandoverRequestEntry]:
        """Enumerate every pending request in the namespace."""
        raise NotImplementedError

    def put_handover_sealed(
        self, node_id: str, nonce: str, generation: int, sealed: bytes
    ) -> None:
        """Publish the holder's answer to one request."""
        raise NotImplementedError

    def delete_handover(self, node_id: str, nonce: str) -> None:
        """Remove both halves of one exchange."""
        raise NotImplementedError


class KVClusterStore(ClusterStore):
    """The cluster's half of the authority, over the ``KV`` seam.

    Every write that has to be exclusive is a compare-and-swap, and
    every one of them checks the transaction's verdict: a rejected
    comparison is not an error, it is a ``False``, and a ``False`` means
    the value was not written.
    """

    def __init__(self, kv: KV, ns: str, leases: object | None = None) -> None:
        """``kv`` is the key-value seam and ``ns`` the namespace this store speaks for."""
        self._kv = kv
        self._ns = ns
        self._leases = leases

    @property
    def kv(self) -> KV:
        """The key-value seam this store talks to."""
        return self._kv

    @property
    def ns(self) -> str:
        """The namespace this store speaks for."""
        return self._ns

    # -- the roster --------------------------------------------------------

    def register_node(self, entry: NodeEntry) -> None:
        """Publish or refresh this node's roster entry.

        It is a plain overwrite: registration is idempotent, and a node
        that restarts with the same identity must be able to re-announce
        itself.
        """
        if entry is None or not entry.node_id:
            raise ValueError("etcdstore: register node: empty node id")
        if not entry.cert_der:
            raise ValueError(
                f"etcdstore: register node {entry.node_id!r}: empty certificate"
            )
        base64.b64decode(entry.cert_der, validate=True)
        payload = json.dumps(
            {
                "node_id": entry.node_id,
                "cert_der": entry.cert_der,
                "dek_version": int(entry.dek_version),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self._kv.put(node_key(self._ns, entry.node_id), payload)

    def get_node(self, node_id: str) -> NodeEntry:
        """Read one roster entry, or raise ``NotFoundError``.

        A single-key read rather than a scan: the holder that answers a
        handover request needs the requester's certificate, and every
        request would otherwise mean reading the whole roster.
        """
        if not node_id:
            raise ValueError("etcdstore: read a roster entry: empty node id")
        value = self._kv.get(node_key(self._ns, node_id))
        if value is None:
            raise NotFoundError(f"no roster entry for {node_id!r}")
        return _unmarshal_node_entry(value.value)

    # -- the mint election -------------------------------------------------

    def claim_mint(self, node_id: str) -> bool:
        """Elect the node that mints the first DEK.

        It reports whether this caller won. The guard is
        ``create_revision(key) == 0``, true only for a key that has
        never existed — so exactly one caller can ever succeed, no
        matter how many race.
        """
        if not node_id:
            raise ValueError("etcdstore: claim mint: empty node id")
        key = mint_key(self._ns)
        result = self._kv.transaction(
            [compare_create(key)], [PutOp(key, node_id.encode("utf-8"))]
        )
        # A failed transaction comparison is not an error, so this check is
        # the only thing standing between a lost race and a forked cluster.
        return bool(result.succeeded)

    def mint_owner(self) -> str:
        """Report which node minted the current DEK."""
        value = self._kv.get(mint_key(self._ns))
        if value is None:
            raise NotFoundError(f"namespace {self._ns!r} has no mint record")
        return value.value.decode("utf-8")

    def claim_mint_leased(
        self, node_id: str, ttl_seconds: int = 30
    ) -> tuple[bool, int]:
        """Claim the first-DEK mint under a lease, when this store can lease."""
        if self._leases is None:
            return self.claim_mint(node_id), 0
        if not node_id:
            raise ValueError("etcdstore: claim mint: empty node id")
        key = mint_claim_key(self._ns)
        lease = self._leases.lease(ttl_seconds)
        lease_id = lease.grant()
        try:
            result = self._kv.transaction(
                [compare_create(key)],
                [LeasePutOp(key, node_id.encode("utf-8"), lease_id)],
            )
        except Exception:
            try:
                lease.revoke()
            except Exception:  # noqa: BLE001 - the original error matters more
                pass
            raise
        if not result.succeeded:
            try:
                lease.revoke()
            except Exception:  # noqa: BLE001 - a lost race is not an error
                pass
            return False, 0
        return True, lease_id

    def commit_mint(self, node_id: str, lease_id: int) -> bool:
        """Turn a leased claim into the permanent mint record."""
        if not node_id or not lease_id:
            return True
        claim = mint_claim_key(self._ns)
        mint = mint_key(self._ns)
        result = self._kv.transaction(
            [compare_value(claim, node_id.encode("utf-8")), compare_create(mint)],
            [PutOp(mint, node_id.encode("utf-8")), DeleteOp(claim)],
        )
        return bool(result.succeeded)

    def release_mint_claim(self, lease_id: int) -> None:
        """Drop a leased claim without committing it."""
        if not lease_id or self._leases is None:
            return
        self._leases.lease(0, lease_id).revoke()

    # -- the generation fence ----------------------------------------------

    def advance_generation(self, target: int) -> tuple[bool, int]:
        """Move the authority's DEK generation to ``target``.

        The rules:

        * the record already says ``target`` — nothing to do, and the
          call succeeds; a takeover whose holder had already moved the
          fence lands here, and it must not be treated as a failure.
        * the record says something below ``target`` — compare-and-set
          from what it says now to ``target``.
        * the record says something above ``target`` — refused.  Moving
          a fence back lets a fenced-out writer back in, and the
          entries written under the generation the authority has
          already left behind are stranded.
        """
        key = generation_key(self._ns)
        target_value = str(int(target)).encode("utf-8")
        for _ in range(4):
            current, present = self._read_generation()
            if present and current == target:
                return False, current
            if present and current > target:
                raise ValueError(
                    f"etcdstore: the authority holds generation {current}, which "
                    f"is ahead of the requested {target}; moving a generation back "
                    "is refused because it would let a fenced-out writer back in "
                    "and strand the entries written under the generation the "
                    "authority has already left"
                )
            if present:
                compare: Compare = compare_value(key, str(current).encode("utf-8"))
            else:
                compare = compare_create(key)
            result = self._kv.transaction([compare], [PutOp(key, target_value)])
            if result.succeeded:
                return True, target
            # Somebody moved the record between the read and the transaction.
            # Read it again and decide afresh: the new value may be the
            # target, which is the outcome this call wanted and the other
            # mover simply got there first, or something above it, which is
            # a refusal.
        raise RuntimeError(
            "etcdstore: the authority's generation did not settle after 4 attempts"
        )

    def _read_generation(self) -> tuple[int, bool]:
        """The authority's generation and whether the record exists."""
        value = self._kv.get(generation_key(self._ns))
        if value is None:
            return 1, False
        try:
            return int(value.value.decode("utf-8")), True
        except ValueError as exc:
            raise ValueError(
                f"etcdstore: generation record holds {value.value!r}: {exc}"
            ) from exc

    def generation(self) -> int:
        """The authority's current DEK generation."""
        current, _ = self._read_generation()
        return current

    # -- the rotation state ------------------------------------------------

    def get_rotation_state(self) -> RotationState:
        """Read the rotation state, or raise ``NotFoundError``."""
        value = self._kv.get(_rotation_key(self._ns))
        if value is None:
            raise NotFoundError(f"namespace {self._ns!r} has no rotation state")
        return _unmarshal_rotation_state(value.value)

    # -- the handover ------------------------------------------------------

    def put_handover_request(self, node_id: str, nonce: str, payload: bytes) -> None:
        """Publish a request."""
        if not node_id:
            raise ValueError("etcdstore: publish a handover request: empty node id")
        if not nonce:
            raise ValueError(
                f"etcdstore: publish a handover request for {node_id!r}: empty nonce"
            )
        self._kv.put(handover_req_key(self._ns, node_id, nonce), bytes(payload))

    def get_handover_sealed(self, node_id: str, nonce: str) -> tuple[int, bytes]:
        """Read the holder's answer, or raise ``NotFoundError``."""
        if not node_id:
            raise ValueError("etcdstore: read a handover answer: empty node id")
        if not nonce:
            raise ValueError(
                f"etcdstore: read a handover answer for {node_id!r}: empty nonce"
            )
        value = self._kv.get(handover_sealed_key(self._ns, node_id, nonce))
        if value is None:
            raise NotFoundError(f"no handover answer for {node_id!r}")
        return _decode_generation(node_id, value.value)

    def list_handover_requests(self) -> list[HandoverRequestEntry]:
        """Enumerate every pending request in the namespace.

        A key that does not parse is skipped rather than fatal: one
        malformed key must not stop the holder from answering the
        requests that are well formed.
        """
        prefix = handover_req_prefix(self._ns)
        upper, ok = prefix_upper_bound(prefix)
        range_end = upper.decode("utf-8", "surrogateescape") if ok else None
        _, values = self._kv.get_range(prefix, range_end)
        entries: list[HandoverRequestEntry] = []
        for value in values:
            key = value.key.decode("utf-8", "replace")
            prefix_length = len(prefix)
            rest = key[prefix_length:] if key.startswith(prefix) else ""
            node_id, _, nonce = rest.partition("/")
            if not node_id or not nonce or "/" in nonce:
                continue
            entries.append(
                HandoverRequestEntry(node_id=node_id, nonce=nonce, payload=value.value)
            )
        return entries

    def put_handover_sealed(
        self, node_id: str, nonce: str, generation: int, sealed: bytes
    ) -> None:
        """Publish the holder's answer to one request."""
        if not node_id:
            raise ValueError("etcdstore: publish a handover answer: empty node id")
        if not nonce:
            raise ValueError(
                f"etcdstore: publish a handover answer for {node_id!r}: empty nonce"
            )
        if not sealed:
            raise ValueError(
                f"etcdstore: publish a handover answer for {node_id!r}: empty payload"
            )
        self._kv.put(
            handover_sealed_key(self._ns, node_id, nonce),
            _encode_generation(generation, sealed),
        )

    def delete_handover(self, node_id: str, nonce: str) -> None:
        """Remove both halves of one exchange."""
        if not node_id:
            raise ValueError("etcdstore: delete a handover: empty node id")
        if not nonce:
            raise ValueError(
                f"etcdstore: delete a handover for {node_id!r}: empty nonce"
            )
        self._kv.delete(handover_req_key(self._ns, node_id, nonce))
        self._kv.delete(handover_sealed_key(self._ns, node_id, nonce))


def _rotation_key(ns: str) -> str:
    """The key that records the cross-node rotation state."""
    helper = _etcd_key_helper("rotation_key")
    if helper is not None:
        return helper(ns)
    return f"{KEYSPACE_PREFIX}{ns}/rotation"


def _encode_generation(generation: int, payload: bytes) -> bytes:
    """The stored form of a handover answer: prefix, then payload."""
    return int(generation).to_bytes(
        GENERATION_HEADER_SIZE, "big", signed=False
    ) + bytes(payload)


def _decode_generation(node_id: str, value: bytes) -> tuple[int, bytes]:
    """The inverse of :func:`_encode_generation`."""
    if len(value) < GENERATION_HEADER_SIZE:
        raise ValueError(
            f"etcdstore: the value for node {node_id!r} is {len(value)} bytes, too short to carry a generation"
        )
    raw = int.from_bytes(value[:GENERATION_HEADER_SIZE], "big")
    if raw > 0x7FFFFFFFFFFFFFFF:
        raise ValueError(
            f"etcdstore: the value for node {node_id!r} carries generation {raw}, which does not fit an int64"
        )
    return raw, value[GENERATION_HEADER_SIZE:]


def _unmarshal_node_entry(raw: bytes) -> NodeEntry:
    """Decode a roster entry."""
    parsed = json.loads(raw.decode("utf-8"))
    return NodeEntry(
        node_id=str(parsed.get("node_id", "")),
        cert_der=str(parsed.get("cert_der", "")),
        dek_version=int(parsed.get("dek_version", 0)),
    )


def _unmarshal_rotation_state(raw: bytes) -> RotationState:
    """Decode the rotation state."""
    parsed = json.loads(raw.decode("utf-8"))
    return RotationState(
        state=str(parsed.get("state", "")),
        holder=str(parsed.get("holder", "")),
        target_dek_version=int(parsed.get("target_dek_version", 0)),
        started_at=str(parsed.get("started_at", "")),
    )
