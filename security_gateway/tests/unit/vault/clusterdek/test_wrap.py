"""The wrapping tests.

Ported from ``internal/credmgr/clusterdek/wrap_test.go``. The test names
mirror the Go ones so the correspondence stays auditable.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from security_gateway.vault.clusterdek.wrap import (
    ClusterDekError,
    ErrCurve,
    public_key_of,
    unwrap,
    wrap,
)

DEK = b"0123456789abcdef"


def test_wrap_round_trips_through_the_matching_key() -> None:
    # TestwrapRoundTripsThroughTheMatchingKey
    """Test wrap round trips through the matching key."""
    key = ec.generate_private_key(ec.SECP256R1())

    blob = wrap(key.public_key(), DEK)
    assert unwrap(key, blob) == DEK


def test_wrap_is_not_deterministic() -> None:
    # TestwrapIsNotDeterministic
    """Test wrap is not deterministic."""
    key = ec.generate_private_key(ec.SECP256R1())

    first = wrap(key.public_key(), DEK)
    second = wrap(key.public_key(), DEK)
    # A deterministic blob would let anyone who read one copy read them all,
    # and would let an observer correlate which nodes share a DEK.
    assert first != second


def test_unwrap_rejects_the_wrong_key() -> None:
    # TestunwrapRejectsTheWrongKey
    """Test unwrap rejects the wrong key."""
    owner = ec.generate_private_key(ec.SECP256R1())
    stranger = ec.generate_private_key(ec.SECP256R1())

    blob = wrap(owner.public_key(), DEK)
    with pytest.raises(ClusterDekError):
        unwrap(stranger, blob)


def test_unwrap_rejects_a_tampered_blob() -> None:
    # TestunwrapRejectsATamperedBlob
    """Test unwrap rejects a tampered blob."""
    key = ec.generate_private_key(ec.SECP256R1())
    blob = wrap(key.public_key(), DEK)

    # Offset 0 is the curve tag, 66 is the first nonce byte and the last
    # offset is the GCM tag: one of each part of the wire format.
    for offset in (0, 66, len(blob) - 1):
        corrupted = bytearray(blob)
        corrupted[offset] ^= 0xFF
        with pytest.raises(ClusterDekError):
            unwrap(key, bytes(corrupted))


def test_unwrap_rejects_a_truncated_blob() -> None:
    # TestunwrapRejectsATruncatedBlob
    """Test unwrap rejects a truncated blob."""
    key = ec.generate_private_key(ec.SECP256R1())
    blob = wrap(key.public_key(), DEK)

    with pytest.raises(ClusterDekError):
        unwrap(key, blob[:-1])


@pytest.mark.parametrize(
    "curve",
    [ec.SECP256R1(), ec.SECP384R1()],
    ids=["P-256", "P-384"],
)
def test_wrap_and_unwrap_across_supported_curves(curve) -> None:
    # TestwrapAndunwrapAcrossSupportedCurves
    """Test wrap and unwrap across supported curves."""
    key = ec.generate_private_key(curve)

    blob = wrap(key.public_key(), DEK)
    assert unwrap(key, blob) == DEK


def test_unwrap_rejects_a_blob_tagged_for_another_curve() -> None:
    # Not a separate Go test, but the Go comment in wrap.go says why the
    # tag check is there: the point size comes from the private key anyway,
    # so a corrupted tag would otherwise be ignored and the blob would still
    # decrypt.
    """Test unwrap rejects a blob tagged for another curve."""
    key = ec.generate_private_key(ec.SECP256R1())
    blob = bytearray(wrap(key.public_key(), DEK))
    blob[0] = 0x02

    with pytest.raises(ClusterDekError):
        unwrap(key, bytes(blob))


def test_public_key_of_extracts_the_certificate_key(
    self_signed_ecdsa: tuple[x509.Certificate, ec.EllipticCurvePrivateKey],
) -> None:
    # Testpublic_key_ofExtractsTheCertificateKey
    """Test public key of extracts the certificate key."""
    cert, key = self_signed_ecdsa

    pub = public_key_of(cert)
    assert pub.public_numbers() == key.public_key().public_numbers()


def test_public_key_of_rejects_an_rsa_certificate(
    self_signed_rsa: x509.Certificate,
) -> None:
    # Testpublic_key_ofRejectsAnRSACertificate
    # RSA needs RSA-OAEP, not ECIES. Reporting that plainly beats a blob that
    # fails later with "couldn't decrypt".
    """Test public key of rejects an rsa certificate."""
    with pytest.raises(ErrCurve):
        public_key_of(self_signed_rsa)
