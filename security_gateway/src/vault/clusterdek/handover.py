"""The signed request a node publishes to ask for the fleet's DEK.

A handover request is a node's request for the fleet's DEK.

Why the one-shot key
--------------------

The node publishes a one-shot public key, the holder seals the DEK to
it, and the node discards the private half once the handover is done.
The sealed copy is then openable by nobody, and the copy left in etcd's
write-ahead log is inert for the same reason.

Why it is signed
----------------

An unsigned request would hand the DEK to whoever asks.  Anyone who can
write to etcd can publish a request carrying a public key of their own,
and the holder — which seals the DEK to whatever key it is given — would
seal it to them.

The signature closes that.  The node signs with the same key it presents
to etcd, and the holder verifies it with the public key of the
certificate the roster already vouches for.  No new trust material is
involved: the certificate-to-identity binding is the one the trust
anchor established, and the signature only attaches a one-shot key to
it.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .wrap import ErrCurve, ErrMalformed

__all__ = [
    "HandoverRequest",
    "marshal_public_key",
    "parse_public_key",
    "unmarshal_request",
    "verify_request",
    "marshal_request",
    "unmarshal_request",
]

#: The domain separation label for the signed bytes.
HANDOVER_LABEL = b"gitcode.com/gcw_wZ6Lfs1I/credential_router/cluster-dek-handover/v1"

#: The one-shot key is always P-256. The Go hard-codes it, and the wire
#: format of the request does not carry a curve tag.
_ONE_SHOT_CURVE = ec.SECP256R1()


@dataclass
class HandoverRequest:
    """A node's request for the fleet's DEK."""

    #: Names the requesting node. It is inside the signed bytes, so a
    #: request cannot be replayed as another node's.
    node_id: str = ""

    #: The DEK generation the node is asking for. A request for a
    #: generation the fleet has moved past is stale and is not answered.
    generation: int = 0

    #: Makes the request single-use. Two requests from one node with
    #: different nonces are different requests, and the holder may seal a
    #: different DEK to each.
    nonce: str = ""

    #: The node's one-shot ECDH public key, in the uncompressed SEC1 form
    #: the wrapping code already speaks.
    public_key: bytes = b""

    #: The signature over the canonical bytes of the fields above. It is
    #: carried with the request so that the holder can verify it before
    #: sealing anything.
    signature: bytes = b""

    def signed_bytes(self) -> bytes:
        """The canonical bytes this request is signed over."""
        payload = bytearray(HANDOVER_LABEL)
        _append_field(payload, self.node_id.encode("utf-8"))
        _append_field(
            payload,
            (int(self.generation) & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"),
        )
        _append_field(payload, self.nonce.encode("utf-8"))
        _append_field(payload, self.public_key)
        return bytes(payload)

    def sign(self, priv: ec.EllipticCurvePrivateKey) -> None:
        """Sign the request with the node's own key."""
        if priv is None:
            raise ErrCurve("clusterdek: sign the handover request: nil private key")
        digest = hashlib.sha256(self.signed_bytes()).digest()
        try:
            self.signature = priv.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))
        except (ValueError, TypeError) as exc:
            raise ErrMalformed(f"clusterdek: sign the handover request: {exc}") from exc


def _append_field(dst: bytearray, field: bytes) -> None:
    """Append a length-prefixed field."""
    dst += len(field).to_bytes(4, "big")
    dst += field


def verify_request(
    pub: ec.EllipticCurvePublicKey, request: HandoverRequest | None
) -> None:
    """Check the signature against the roster's vouching certificate."""
    if pub is None:
        raise ErrCurve("clusterdek: verify the handover request: nil public key")
    if request is None:
        raise ErrMalformed("clusterdek: malformed wrapped blob: nil handover request")
    if not request.signature:
        raise ErrMalformed(
            "clusterdek: malformed wrapped blob: the handover request is not signed"
        )
    digest = hashlib.sha256(request.signed_bytes()).digest()
    try:
        pub.verify(request.signature, digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    except InvalidSignature as exc:
        raise ErrMalformed(
            "clusterdek: malformed wrapped blob: the handover request's signature does not match"
        ) from exc


def marshal_public_key(pub: ec.EllipticCurvePublicKey) -> bytes:
    """Encode an ECDSA public key in the uncompressed SEC1 form."""
    if pub is None:
        raise ErrCurve("clusterdek: encode a public key: nil public key")
    return pub.public_bytes(
        encoding=Encoding.X962, format=PublicFormat.UncompressedPoint
    )


def parse_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Decode an uncompressed SEC1 public key."""
    if not data:
        raise ErrMalformed(
            "clusterdek: malformed wrapped blob: the one-shot public key is not a point on the curve"
        )
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(_ONE_SHOT_CURVE, data)
    except ValueError as exc:
        raise ErrMalformed(
            f"clusterdek: malformed wrapped blob: the one-shot public key is not a point on the curve: {exc}"
        ) from exc


def marshal_request(request: HandoverRequest) -> bytes:
    """Encode a request for the key-value store."""
    if request is None:
        raise ErrMalformed("clusterdek: malformed wrapped blob: nil handover request")
    payload = {
        "node_id": request.node_id,
        "generation": int(request.generation),
        "nonce": request.nonce,
        "public_key": base64.b64encode(request.public_key).decode("ascii"),
        "signature": base64.b64encode(request.signature).decode("ascii"),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def unmarshal_request(data: bytes) -> HandoverRequest:
    """Decode a request from the key-value store."""
    try:
        parsed = json.loads(data.decode("utf-8"))
    except ValueError as exc:
        raise ErrMalformed(
            f"clusterdek: malformed wrapped blob: decode the handover request: {exc}"
        ) from exc
    if not isinstance(parsed, dict):
        raise ErrMalformed(
            "clusterdek: malformed wrapped blob: decode the handover request: not a JSON object"
        )
    for field in ("public_key", "signature"):
        if not isinstance(parsed.get(field, ""), str):
            raise ErrMalformed(
                f"clusterdek: malformed wrapped blob: decode the handover request: {field} is not a string"
            )
    try:
        public_key = base64.b64decode(parsed.get("public_key", ""), validate=True)
    except ValueError as exc:
        raise ErrMalformed(
            f"clusterdek: malformed wrapped blob: decode the handover request: public_key is not base64: {exc}"
        ) from exc
    try:
        signature = base64.b64decode(parsed.get("signature", ""), validate=True)
    except ValueError as exc:
        raise ErrMalformed(
            f"clusterdek: malformed wrapped blob: decode the handover request: signature is not base64: {exc}"
        ) from exc
    generation = parsed.get("generation", 0)
    if isinstance(generation, bool) or not isinstance(generation, int):
        raise ErrMalformed(
            "clusterdek: malformed wrapped blob: decode the handover request: generation is not a number"
        )
    return HandoverRequest(
        node_id=str(parsed.get("node_id", "")),
        generation=generation,
        nonce=str(parsed.get("nonce", "")),
        public_key=public_key,
        signature=signature,
    )


#: The snake_case spelling of :func:`unmarshal_request`.
unmarshal_request = unmarshal_request
