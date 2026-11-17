"""The cluster's shared key: the trust anchor and the DEK sealing.

This package distributes one shared DEK across a node fleet without ever
putting key material in plaintext in etcd, and it carries the trust
rules that decide whether a joining node may be handed the fleet's key
at all.  The trust rules are the reason the package exists: etcd's own
client authentication is the real boundary, and this is the second line
behind it — if etcd is ever started without mutual TLS, an open roster
must not be enough to harvest the DEK.

Three modules make up the package:

``anchor``
    The trust anchor. A CA bundle, a pin list, or both — with the pin
    list taking over outright when it is configured.  A missing anchor
    is an error, never a permissive default.

``wrap``
    The asymmetric sealing: an ephemeral ECDH agreement, an
    HKDF-derived key, and AES-GCM over the result.

``handover``
    The signed request a node publishes to ask for the fleet's key.
"""

from __future__ import annotations

from .anchor import (
    Anchor,
    AnchorError,
    ClusterDekError,
    ErrNoTrustAnchor,
    Fingerprint,
    new_anchor,
)
from .handover import (
    HandoverRequest,
    marshal_public_key,
    marshal_request,
    parse_public_key,
    unmarshal_request,
    verify_request,
)
from .wrap import (
    ErrCurve,
    ErrMalformed,
    public_key_of,
    unwrap,
    wrap,
)

__all__ = [
    "Anchor",
    "AnchorError",
    "ClusterDekError",
    "ErrCurve",
    "ErrMalformed",
    "ErrNoTrustAnchor",
    "Fingerprint",
    "HandoverRequest",
    "marshal_public_key",
    "new_anchor",
    "parse_public_key",
    "public_key_of",
    "unmarshal_request",
    "unwrap",
    "verify_request",
    "wrap",
    "marshal_request",
]
