"""The PKI the clusterdek tests run against.

The Go originals generate their ECDSA keys and certificates in-process, in
``anchor_test.go`` and ``wrap_test.go``. The Python port does the same with
``cryptography``: no PEM fixture is checked in, so a test can never pass
against a stale file, and the certificates are made for the curve the test
needs rather than for whatever the fixture happened to carry.

The helpers below mirror the Go ones:

* ``build_ca`` is Go's inline CA construction in ``newAnchorPKI``;
* ``build_leaf`` is Go's ``leaf`` helper;
* ``build_self_signed`` is Go's ``selfSigned`` helper.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

#: The only extended key usage a node's etcd client certificate carries.
CLIENT_AUTH = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH])

#: The usage a certificate for some unrelated service would carry.
SERVER_AUTH = x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH])


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _key_usage(*, cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def build_ca(
    common_name: str = "cluster test CA", serial: int = 1
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Make a self-signed CA certificate and its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(hours=24))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(cert_sign=True), critical=True)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def build_leaf(
    ca_cert: x509.Certificate,
    ca_key: ec.EllipticCurvePrivateKey,
    common_name: str,
    usages: x509.ExtendedKeyUsage,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """Make a leaf certificate issued by ``ca_cert``."""
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(hours=24))
        .add_extension(_key_usage(cert_sign=False), critical=True)
        .add_extension(usages, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return cert, key


def build_self_signed(
    key: ec.EllipticCurvePrivateKey,
    common_name: str = "router-b",
    usages: x509.ExtendedKeyUsage | None = None,
) -> x509.Certificate:
    """Make a self-signed leaf certificate around ``key``."""
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(hours=1))
        .add_extension(_key_usage(cert_sign=False), critical=True)
    )
    if usages is not None:
        builder = builder.add_extension(usages, critical=False)
    return builder.sign(key, hashes.SHA256())


def pem_of(cert: x509.Certificate) -> bytes:
    """Encode a certificate as PEM."""
    return cert.public_bytes(encoding=serialization.Encoding.PEM)


@dataclass
class AnchorPKI:
    """The material Go's ``anchorPKI`` struct carries."""

    ca_cert: x509.Certificate
    ca_key: ec.EllipticCurvePrivateKey
    ca_pem_file: str
    rogue_cert: x509.Certificate
    client: x509.Certificate


@pytest.fixture
def anchor_pki(tmp_path: Path) -> AnchorPKI:
    """A CA, a client certificate from it, and one from a rogue CA."""
    ca_cert, ca_key = build_ca()
    rogue_cert, rogue_key = build_ca(common_name="rogue CA", serial=9)

    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(pem_of(ca_cert))

    attacker, _ = build_leaf(rogue_cert, rogue_key, "attacker", CLIENT_AUTH)
    client, _ = build_leaf(ca_cert, ca_key, "router-a", CLIENT_AUTH)
    return AnchorPKI(
        ca_cert=ca_cert,
        ca_key=ca_key,
        ca_pem_file=str(ca_path),
        rogue_cert=attacker,
        client=client,
    )


@pytest.fixture
def leaf():
    """A factory for leaf certificates issued by a given CA."""

    def _leaf(
        ca_cert: x509.Certificate,
        ca_key: ec.EllipticCurvePrivateKey,
        common_name: str,
        usages: x509.ExtendedKeyUsage,
    ) -> x509.Certificate:
        cert, _ = build_leaf(ca_cert, ca_key, common_name, usages)
        return cert

    return _leaf


@pytest.fixture
def self_signed_ecdsa() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A self-signed ECDSA certificate and the key behind it."""
    key = ec.generate_private_key(ec.SECP256R1())
    return build_self_signed(key), key


@pytest.fixture
def etcd_client_cert() -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey]:
    """A self-signed client-auth certificate and the key behind it.

    Go's handover test signs with the node's etcd client key and verifies
    against the public key of that node's certificate, so the two have to be
    the same key pair.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    return build_self_signed(key, common_name="router-b", usages=CLIENT_AUTH), key


@pytest.fixture
def self_signed_rsa() -> x509.Certificate:
    """A self-signed RSA certificate.

    RSA needs RSA-OAEP, not ECIES, so it has to be refused by the wrapping
    helpers rather than half-supported.
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "router-rsa")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_now() - datetime.timedelta(hours=1))
        .not_valid_after(_now() + datetime.timedelta(hours=1))
        .sign(key, hashes.SHA256())
    )
    return cert
