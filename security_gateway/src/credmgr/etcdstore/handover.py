"""The DEK handover: how a joining node gets the fleet's DEK.

A node that needs the fleet's DEK publishes a request and waits for a
holder to answer it. The two halves live in sibling sub-trees rather than
under one key, because the holder has to enumerate the requests and the
answers are not requests::

    /security_gateway/<ns>/handover/req/<node_id>/<nonce>       the request
    /security_gateway/<ns>/handover/sealed/<node_id>/<nonce>   the holder's answer

The answer is sealed to a key the requester generated for this one exchange
and threw away afterwards, so it opens for the requester and for nobody
else — including the authority, which holds the ciphertext and cannot
complete the agreement.

The request is deleted once the requester has what it came for. A request
left behind is a request nobody is waiting for any more, and the holder
answers it into a key that will also be left behind; the requester clears
both on its next start.

Every value in this keyspace carries the generation as an eight-byte
big-endian header in front of the payload::

    +---------------------------+------------------+
    | generation (8, big endian)| sealed ciphertext|
    +---------------------------+------------------+

Eight bytes big-endian keeps the value human-readable when it turns up in
``etcdctl``, which is worth more than four bytes would save. The header is
on every value, so a truncated value is rejected the same way wherever it
turns up.
"""

from __future__ import annotations

from dataclasses import dataclass

from .cluster import prefix_end
from .errors import InvalidValueError, NotFoundError, remap_compacted
from .keys import (
    HANDOVER_REQ_SEGMENT,
    KEYSPACE_PREFIX,
    handover_request_key,
    handover_request_prefix,
)
from .store import KV, KVValue

__all__ = [
    "GENERATION_HEADER_SIZE",
    "HANDOVER_REQ_SEGMENT",
    "HANDOVER_SEALED_SEGMENT",
    "Handover",
    "HandoverRequestEntry",
    "decode_generation",
    "encode_generation",
    "handover_request_key",
    "handover_request_prefix",
    "handover_sealed_key",
]

#: The length of the generation prefix on a stored value.
GENERATION_HEADER_SIZE = 8

#: The subtree of the holders' answers.
HANDOVER_SEALED_SEGMENT = "handover/sealed/"

#: The largest generation an ``int64`` can hold. A header above this is a
#: corrupt value, not a generation.
_MAX_INT64 = 2**63 - 1


def handover_sealed_key(ns: str, node_id: str, nonce: str) -> str:
    """The key under which the holder's answer to one request lives."""
    return f"{KEYSPACE_PREFIX}{ns}/{HANDOVER_SEALED_SEGMENT}{node_id}/{nonce}"


def encode_generation(dek_version: int, sealed: bytes) -> bytes:
    """Build the stored form: the generation prefix, then the payload."""
    payload = bytes(sealed)
    value = bytearray(GENERATION_HEADER_SIZE + len(payload))
    value[:GENERATION_HEADER_SIZE] = (int(dek_version) & 0xFFFFFFFFFFFFFFFF).to_bytes(GENERATION_HEADER_SIZE, "big")
    value[GENERATION_HEADER_SIZE:] = payload
    return bytes(value)


def decode_generation(node_id: str, value: bytes) -> tuple[int, bytes]:
    """The inverse of :func:`encode_generation`."""
    raw = bytes(value)
    if len(raw) < GENERATION_HEADER_SIZE:
        raise InvalidValueError(
            f"etcdstore: the value for node {node_id!r} is {len(raw)} bytes, too short to carry a generation"
        )
    generation = int.from_bytes(raw[:GENERATION_HEADER_SIZE], "big")
    if generation > _MAX_INT64:
        raise InvalidValueError(
            f"etcdstore: the value for node {node_id!r} carries generation {generation}, which does not fit an int64"
        )
    return generation, raw[GENERATION_HEADER_SIZE:]


@dataclass
class HandoverRequestEntry:
    """One pending request as a holder sees it."""

    #: Names the requester.
    node_id: str = ""
    #: Identifies this exchange.
    nonce: str = ""
    #: The request as the requester wrote it. It is opaque here: this layer
    #: stores bytes, and the shape belongs to whoever writes it.
    payload: bytes = b""


class Handover:
    """The DEK handover for one namespace."""

    def __init__(self, kv: KV, ns: str) -> None:
        self._kv = kv
        self._ns = ns

    @property
    def kv(self) -> KV:
        """The key-value seam this handover talks to."""
        return self._kv

    @property
    def ns(self) -> str:
        """The namespace this handover holds."""
        return self._ns

    def put_request(self, node_id: str, nonce: str, payload: bytes) -> None:
        """Publish a request."""
        if not node_id:
            raise InvalidValueError("etcdstore: publish a handover request: empty node id")
        if not nonce:
            raise InvalidValueError(f"etcdstore: publish a handover request for {node_id!r}: empty nonce")
        if not payload:
            raise InvalidValueError(f"etcdstore: publish a handover request for {node_id!r}: empty payload")
        self._kv.put(
            handover_request_key(self._ns, node_id, nonce),
            bytes(payload),
        )

    def get_request(self, node_id: str, nonce: str) -> bytes:
        """Read one request, or raise ``NotFoundError``."""
        found = self._get(handover_request_key(self._ns, node_id, nonce))
        if found is None:
            raise NotFoundError(f"etcdstore: no handover request for {node_id!r}")
        return found.value

    def list_requests(self) -> list[HandoverRequestEntry]:
        """The namespace's pending requests, ordered by node and nonce.

        A request whose key does not have the expected shape is skipped
        rather than fatal: one malformed key must not stop the holder
        from answering the requests that are well formed.
        """
        prefix = handover_request_prefix(self._ns)
        _, values = self._get_range(prefix)
        entries: list[HandoverRequestEntry] = []
        for value in values:
            key = value.key.decode("utf-8", "surrogateescape")
            if not key.startswith(prefix):
                continue
            prefix_length = len(prefix)
            rest = key[prefix_length:]
            node_id, _, nonce = rest.partition("/")
            if not node_id or not nonce or "/" in nonce:
                continue
            entries.append(HandoverRequestEntry(node_id=node_id, nonce=nonce, payload=value.value))
        entries.sort(key=lambda entry: (entry.node_id, entry.nonce))
        return entries

    def put_sealed(self, node_id: str, nonce: str, dek_version: int, sealed: bytes) -> None:
        """Store the holder's answer to one request."""
        if not node_id:
            raise InvalidValueError("etcdstore: publish a handover answer: empty node id")
        if not nonce:
            raise InvalidValueError(f"etcdstore: publish a handover answer for {node_id!r}: empty nonce")
        if not sealed:
            raise InvalidValueError(f"etcdstore: publish a handover answer for {node_id!r}: empty payload")
        self._kv.put(
            handover_sealed_key(self._ns, node_id, nonce),
            encode_generation(dek_version, sealed),
        )

    def get_sealed(self, node_id: str, nonce: str) -> tuple[int, bytes]:
        """Read the holder's answer, or raise ``NotFoundError``."""
        found = self._get(handover_sealed_key(self._ns, node_id, nonce))
        if found is None:
            raise NotFoundError(f"etcdstore: no handover answer for {node_id!r}")
        return decode_generation(node_id, found.value)

    def delete(self, node_id: str, nonce: str) -> None:
        """Remove both halves of one exchange."""
        if not node_id:
            raise InvalidValueError("etcdstore: delete a handover: empty node id")
        if not nonce:
            raise InvalidValueError(f"etcdstore: delete a handover for {node_id!r}: empty nonce")
        self._kv.delete(handover_request_key(self._ns, node_id, nonce))
        self._kv.delete(handover_sealed_key(self._ns, node_id, nonce))

    # -- the seam ----------------------------------------------------------

    def _get(self, key: str) -> KVValue | None:
        try:
            return self._kv.get(key)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _get_range(self, prefix: str) -> tuple[int, list[KVValue]]:
        try:
            return self._kv.get_range(prefix, prefix_end(prefix), 0)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise
