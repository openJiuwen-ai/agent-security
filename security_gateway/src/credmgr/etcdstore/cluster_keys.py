"""The etcd keyspace the cluster uses.

Every path the cluster writes is built here, so the layout is one thing
rather than a string in every method.  The helpers that encode and decode
a node's entry live here too, for the same reason.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from security_gateway.vault import prefix_upper_bound

from .errors import InvalidValueError
from .keys import KEYSPACE_PREFIX


@dataclass
class NodeEntry:
    """What a node publishes about itself.

    None of it is secret, and none of it is trusted: the wrapping target
    is the public key, so a tampered entry can at worst waste a
    wrapping.
    """

    #: The node's own identity.
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


NODE_PREFIX_SEGMENT = "nodes/"

MINT_SEGMENT = "mint"

PRESENCE_SEGMENT = "presence/"

ROTATION_MARKER_SEGMENT = "rotation/"

TAKEOVER_SEGMENT = "takeover"

LAST_ROTATION_SEGMENT = "last_rotation"


def node_key(ns: str, node_id: str) -> str:
    """The roster key: ``/security_gateway/<ns>/nodes/<node_id>``."""
    return f"{KEYSPACE_PREFIX}{ns}/{NODE_PREFIX_SEGMENT}{node_id}"


def nodes_prefix(ns: str) -> str:
    """The roster subtree prefix: ``/security_gateway/<ns>/nodes/``."""
    return f"{KEYSPACE_PREFIX}{ns}/{NODE_PREFIX_SEGMENT}"


def mint_key(ns: str) -> str:
    """The mint record key: ``/security_gateway/<ns>/mint``."""
    return f"{KEYSPACE_PREFIX}{ns}/{MINT_SEGMENT}"


def presence_key(ns: str, node_id: str) -> str:
    """The presence key: ``/security_gateway/<ns>/presence/<node_id>``."""
    return f"{KEYSPACE_PREFIX}{ns}/{PRESENCE_SEGMENT}{node_id}"


def presence_prefix(ns: str) -> str:
    """The presence prefix: ``/security_gateway/<ns>/presence/``."""
    return f"{KEYSPACE_PREFIX}{ns}/{PRESENCE_SEGMENT}"


def rotation_marker_key(ns: str, node_id: str) -> str:
    """The in-flight rotation marker.

    ``/security_gateway/<ns>/rotation/<node_id>``. Its presence is what tells
    the cluster that a rotation was started and never finished — the
    precondition for a takeover.
    """
    return f"{KEYSPACE_PREFIX}{ns}/{ROTATION_MARKER_SEGMENT}{node_id}"


def rotation_marker_prefix(ns: str) -> str:
    """The rotation marker prefix: ``/security_gateway/<ns>/rotation/``."""
    return f"{KEYSPACE_PREFIX}{ns}/{ROTATION_MARKER_SEGMENT}"


def takeover_key(ns: str) -> str:
    """The single takeover claim: ``/security_gateway/<ns>/takeover``.

    A compare-on-absent transaction lets exactly one node proceed; the
    key is never deleted: a later takeover waits for the first DEK to
    land.
    """
    return f"{KEYSPACE_PREFIX}{ns}/{TAKEOVER_SEGMENT}"


def host_leader_key(ns: str, node_id: str) -> str:
    """The lease key a host's processes use to elect one leader."""
    return f"{KEYSPACE_PREFIX}{ns}/leader/{node_id}"


def generation_key(ns: str) -> str:
    """The key recording the DEK generation the authority's ciphertexts are written under.

    The generation is compared inside the same transaction as the write,
    which makes it a fence rather than a check: a stale writer cannot
    slip a row in between reading and writing.
    """
    return f"{KEYSPACE_PREFIX}{ns}/generation"


def last_rotation_key(ns: str) -> str:
    """The key every node's scheduled-rotation gate reads.

    It is a sibling of the rotation lock rather than a child of it: the
    lock key is leased and disappears when the holder releases, so
    nothing could be read back from it afterwards.
    """
    return f"{KEYSPACE_PREFIX}{ns}/{LAST_ROTATION_SEGMENT}"


def prefix_end(prefix: str) -> str | None:
    """The exclusive upper bound of the range covering ``prefix``."""
    upper, ok = prefix_upper_bound(prefix)
    if not ok:
        return None
    return upper.decode("utf-8", "surrogateescape")


def _key_text(raw: bytes) -> str:
    """Decode a key for the prefix arithmetic."""
    return raw.decode("utf-8", "surrogateescape")


def _parse_int(text: str) -> int:
    """Parse a bare integer, the way Go's ``strconv.ParseInt`` does."""
    raw = text.strip()
    if raw != text or not raw or "_" in raw:
        raise ValueError(f"not an integer: {text!r}")
    return int(raw, 10)


def _marshal_node_entry(entry: NodeEntry) -> bytes:
    """The canonical JSON representation of a roster entry."""
    payload = {
        "node_id": entry.node_id,
        "cert_der": entry.cert_der,
        "dek_version": int(entry.dek_version),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _unmarshal_node_entry(raw: bytes, node_id: str = "") -> NodeEntry:
    """Parse a roster entry.

    Decoded leniently — a field that is missing keeps its zero value. A
    roster entry is written by many nodes and read by every other one,
    so refusing to serve the fleet over one unknown field is not an
    option.
    """
    try:
        document = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise InvalidValueError(f"etcdstore: decode the roster entry for {node_id!r}: {exc}") from exc
    if not isinstance(document, dict):
        raise InvalidValueError(f"etcdstore: decode the roster entry for {node_id!r}: not an object")
    version = document.get("dek_version", 0)
    if not isinstance(version, int) or isinstance(version, bool):
        version = 0
    return NodeEntry(
        node_id=str(document.get("node_id", "")),
        cert_der=str(document.get("cert_der", "")),
        dek_version=version,
    )
