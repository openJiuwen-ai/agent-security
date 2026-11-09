"""Sealing the fleet's DEK to a key a peer generated for one exchange.

Every node syncs every credential and must therefore hold the DEK in
plaintext in memory.  What this package removes is the *other* copy —
the one a shared key-value store would otherwise keep: each node
publishes only its public key, and every node holding the DEK writes a
copy encrypted to that key.

Wire format
-----------

::

    curve tag (1 byte) || ephemeral pubkey (uncompressed SEC1) ||
    nonce (12 bytes) || ciphertext || GCM tag

The shared secret from the ephemeral ECDH is never used directly as a
key: it goes through HKDF-SHA256 with the label below so the result is
bound to this protocol and cannot be replayed against another use of the
same ephemeral exchange.  The label is also what keeps a future change
of the AEAD or KDF from silently decrypting old blobs.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from security_gateway.crypto import (
    AES_KEY_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    InvalidCiphertextError,
    aes_decrypt,
    aes_encrypt,
)

from .anchor import ClusterDekError

__all__ = [
    "ClusterDekError",
    "ErrCurve",
    "ErrMalformed",
    "KDF_LABEL",
    "public_key_of",
    "unwrap",
    "wrap",
]

#: The domain separation label for the HKDF output. It keeps this key
#: derivation from any other use of the same ephemeral key agreement, and
#: keeps a future change of the AEAD or the KDF from silently decrypting
#: old blobs.
KDF_LABEL = b"gitcode.com/gcw_wZ6Lfs1I/credential_router/cluster-dek/v1"

# Curve tags. The values are explicit rather than ordinal so reordering
# the map cannot silently reinterpret blobs written by an older build.
CURVE_TAG_P256 = 1
CURVE_TAG_P384 = 2
CURVE_TAG_P521 = 3

_CURVE_TAGS = {
    CURVE_TAG_P256: "secp256r1",
    CURVE_TAG_P384: "secp384r1",
    CURVE_TAG_P521: "secp521r1",
}

_TAG_BY_CURVE_NAME = {name: tag for tag, name in _CURVE_TAGS.items()}


class ErrMalformed(ClusterDekError):
    """The blob is too short to be a wrapped DEK."""


class ErrCurve(ClusterDekError):
    """A key on a curve this package does not handle."""


def _tag_for(curve: ec.EllipticCurve) -> int:
    """The wire tag of an elliptic curve."""
    try:
        return _TAG_BY_CURVE_NAME[curve.name]
    except KeyError:
        raise ErrCurve(f"clusterdek: unsupported elliptic curve: {curve.name}") from None


def _point_size(curve: ec.EllipticCurve) -> int:
    """The length of an uncompressed SEC1 point on the curve."""
    return (curve.key_size + 7) // 8 * 2 + 1


def _derive_kek(shared: bytes) -> bytes:
    """Derive the key-encryption key from an ECDH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=KDF_LABEL,
    ).derive(shared)


def wrap(pub: ec.EllipticCurvePublicKey, plaintext: bytes) -> bytes:
    """Encrypt ``plaintext`` for the holder of one private key."""
    if pub is None:
        raise ErrCurve("clusterdek: nil public key")
    tag = _tag_for(pub.curve)
    ephemeral = ec.generate_private_key(pub.curve)
    shared = ephemeral.exchange(ec.ECDH(), pub)
    kek = _derive_kek(shared)
    nonce, ciphertext = aes_encrypt(kek, plaintext)
    point = ephemeral.public_key().public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )
    return bytes([tag]) + point + nonce + ciphertext


def unwrap(priv: ec.EllipticCurvePrivateKey, blob: bytes) -> bytes:
    """Reverse :func:`wrap` using the matching private key."""
    if priv is None:
        raise ErrCurve("clusterdek: nil private key")
    tag = _tag_for(priv.curve)
    if not blob or blob[0] != tag:
        # Without this the tag would be decorative: the point size comes from
        # the private key anyway, so a corrupted tag would be ignored and the
        # blob would still decrypt.
        raise ErrMalformed("clusterdek: malformed wrapped blob: blob is tagged for a different curve")
    point_size = _point_size(priv.curve)
    minimum = 1 + point_size + NONCE_SIZE + TAG_SIZE
    if len(blob) < minimum:
        raise ErrMalformed(
            f"clusterdek: malformed wrapped blob: {len(blob)} bytes is shorter "
            f"than the {minimum}-byte minimum for {priv.curve.name}"
        )
    try:
        ephemeral_pub = ec.EllipticCurvePublicKey.from_encoded_point(priv.curve, blob[1 : 1 + point_size])
    except ValueError as exc:
        raise ErrMalformed(f"clusterdek: malformed wrapped blob: parse the ephemeral key: {exc}") from exc
    shared = priv.exchange(ec.ECDH(), ephemeral_pub)
    kek = _derive_kek(shared)
    nonce = blob[1 + point_size : 1 + point_size + NONCE_SIZE]
    try:
        return aes_decrypt(kek, nonce, blob[1 + point_size + NONCE_SIZE :])
    except InvalidCiphertextError as exc:
        raise ClusterDekError(f"clusterdek: open: {exc}") from exc


def public_key_of(cert: x509.Certificate) -> ec.EllipticCurvePublicKey:
    """Extract the ECDSA public key from an X.509 certificate leaf."""
    if cert is None:
        raise ErrCurve("clusterdek: no certificate presented")
    public_key = cert.public_key()
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ErrCurve(
            f"clusterdek: unsupported elliptic curve: certificate carries {type(public_key).__name__}, want ECDSA"
        )
    return public_key
