"""Publish and fetch the key a rotation leaves in the authority.

A rotation mints a DEK before it re-encrypts anything.  If the rotating
process dies after that, the key exists only in its memory: the records
already rewritten cannot be opened by any other node, and the next
rotation has nothing to adopt.  The fix is to put the key in the
authority first, sealed to every node's identity certificate.  A peer
that finds the generation ahead can then unwrap the pending key with its
own private key instead of waiting for a live holder to answer a
handover request.
"""

from __future__ import annotations

import base64
import logging

from cryptography import x509
from .clusterdek import public_key_of, wrap
from .clusterdek.wrap import unwrap
from .errors import VaultError

__all__ = ["publish_pending_key", "read_pending_key"]

_LOG = logging.getLogger(__name__)


def publish_pending_key(vault, store, generation: int, dek: bytes) -> int:
    """Seal ``dek`` to every roster node and write the seals to the authority.

    Returns the number of nodes the key was sealed for.  A vault without a
    cluster identity is the legacy single-node etcd mode: there is nobody
    to hand the key to and nothing to publish.
    """
    identity = getattr(vault, "_self_identity", None)
    if identity is None:
        return 0
    anchor = getattr(vault, "_cluster_anchor", None)
    if anchor is None:
        raise VaultError("vault: a rotating cluster node has no trust anchor")
    from .etcdstore.cluster import list_nodes, list_present, publish_pending_deks

    # The roster is an append-only record of nodes that were once trusted.
    # A node that is no longer present must not receive the next generation:
    # otherwise a retired or compromised node keeps the key to every record
    # written from now on.  Presence is the liveness signal the fleet already
    # maintains, so it is also the seal list.
    present = list_present(store.kv, store.ns)
    wraps: dict[str, bytes] = {}
    for node in list_nodes(store.kv, store.ns):
        if node.node_id not in present:
            _LOG.warning(
                "skipping inactive roster node %s while publishing generation %s",
                node.node_id,
                generation,
            )
            continue
        try:
            cert = x509.load_der_x509_certificate(base64.b64decode(node.cert_der))
        except (TypeError, ValueError) as exc:
            _LOG.warning(
                "skipping roster node %s with an unreadable certificate: %s",
                node.node_id,
                exc,
            )
            continue
        try:
            anchor.verify(cert)
            wraps[node.node_id] = wrap(public_key_of(cert), dek)
        except Exception as exc:  # noqa: BLE001 - one bad roster entry must not win
            _LOG.warning(
                "skipping roster node %s that the trust anchor rejects: %s",
                node.node_id,
                exc,
            )
            continue
    if not wraps:
        raise VaultError("vault: the rotation has no node to seal its key for")
    publish_pending_deks(store.kv, store.ns, generation, wraps)
    return len(wraps)


def read_pending_key(vault, generation: int) -> bytes:
    """Open the key a crashed rotation left for this node, if there is one."""
    identity = getattr(vault, "_self_identity", None)
    store = getattr(vault, "_cluster_store", None)
    if identity is None or store is None or identity.private is None:
        return b""
    from .etcdstore.cluster import load_pending_dek

    blob = load_pending_dek(store.kv, store.ns, generation, identity.node_id)
    if not blob:
        return b""
    try:
        return unwrap(identity.private, blob)
    except Exception:  # noqa: BLE001 - a bad seal is a missing key
        return b""
