"""The trust anchor that decides who may be handed the fleet's key.

The Anchor decides whether a certificate presented by a node joining the
cluster may be handed the fleet's key.  It is the second line behind
etcd's own client authentication: an open roster must not be enough to
harvest the DEK when etcd is started without mutual TLS.

A pin list takes over outright: when pins are configured the CA pool is
not consulted at all.  A pin is strictly stronger than a CA, because a
compromised CA can mint a certificate that pins will not accept.
Leaving pins behind after moving off the CA is a real hazard, so
:func:`new_anchor` keeps reporting which source is in force.

A fingerprint is the hex SHA-256 of the certificate's **DER** — what
``openssl x509 -fingerprint -sha256`` prints.  It has to be copied from
the certificate itself, not computed from the public key: pinning the
certificate is what makes an expiry or a reissue show up as a change.
Pins may be written as bare hex or as ``hex:label``, where the label is
a comment for humans and is ignored here.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import Encoding

__all__ = [
    "Anchor",
    "AnchorError",
    "ErrNoTrustAnchor",
    "Fingerprint",
    "new_anchor",
    "new_anchor",
]


class ClusterDekError(Exception):
    """The base of every error this package raises.

    It is a plain :class:`Exception`, not a service error: this package
    is a protocol, not a service. Nothing here has an HTTP status.
    """


class ErrNoTrustAnchor(ClusterDekError):
    """Neither a CA bundle nor a pin list is configured.

    Answering without one would hand the fleet's key to whatever key an
    attacker wrote into the roster, which is the single thing this type
    exists to prevent. It is an error, never a permissive default.
    """


class AnchorError(ClusterDekError):
    """A certificate the anchor does not vouch for."""


class Fingerprint(str):
    """The lowercase hex SHA-256 of a certificate's DER.

    The vault calls this name directly - ``Fingerprint(cert)`` - so it is
    a class rather than a function: what it produces is a string, and the
    name is used as its constructor.
    """

    def __new__(cls, cert: x509.Certificate) -> "Fingerprint":
        """The digest of ``cert``."""
        if cert is None:
            raise AnchorError("clusterdek: no certificate presented")
        digest = hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()
        return super().__new__(cls, digest)


class Anchor:
    """Decides whether a certificate may be handed the fleet's key.

    At least one of the two sources has to be configured: a CA pool to
    chain against, or a pin list to match against. An anchor with
    neither decides nothing, and :meth:`validate` says so.
    """

    def __init__(
        self,
        *,
        roots: list[x509.Certificate] | None = None,
        pins: set[str] | None = None,
    ) -> None:
        """``roots`` is the parsed CA pool and ``pins`` the pinned fingerprints."""
        self._roots = roots
        self._pins = pins

    def pins_take_over(self) -> bool:
        """Report whether the pin list is the effective anchor."""
        return self._pins is not None

    def has_ca(self) -> bool:
        """Report whether a CA bundle was parsed, consulted or not."""
        return self._roots is not None

    def validate(self) -> None:
        """Report whether this anchor can decide anything.

        Raises :class:`ErrNoTrustAnchor` when neither source is set.
        """
        if self._roots is None and self._pins is None:
            raise ErrNoTrustAnchor("clusterdek: no trust anchor configured")

    def verify(self, cert: x509.Certificate | None) -> None:
        """Report whether ``cert`` may be handed the fleet's key.

        Raises :class:`AnchorError` when it may not, and
        :class:`ErrNoTrustAnchor` when the anchor decides nothing.
        """
        self.validate()
        if cert is None:
            raise AnchorError("clusterdek: no certificate presented")

        if self._pins is not None:
            digest = Fingerprint(cert)
            if digest not in self._pins:
                raise AnchorError(f"clusterdek: certificate {digest} is not pinned")
            return

        if self._roots is None:
            raise AnchorError("clusterdek: the anchor has no roots")
        problem = _client_chain_problem(cert, self._roots)
        if problem is not None:
            raise AnchorError(
                f"clusterdek: certificate is not issued by the cluster CA: {problem}"
            )


def new_anchor(
    ca_file: str | os.PathLike[str] | None,
    pins: Sequence[str] | None = None,
) -> Anchor:
    """Build a trust anchor from an optional CA bundle and an optional list of pinned certificate fingerprints.

    Raises :class:`ErrNoTrustAnchor` when neither a CA file nor a pin is
    configured, and :class:`ValueError` when a pin is not 32 hex-encoded
    bytes or the CA file cannot be read.
    """
    cleaned: list[str] = []
    for raw_pin in pins or ():
        pin = raw_pin.strip()
        if not pin:
            continue
        if ":" in pin:
            pin = pin.split(":", 1)[0].strip()
        try:
            raw = bytes.fromhex(pin)
        except ValueError as exc:
            raise ValueError(
                f"clusterdek: pinned certificate {pin!r} must be 32 hex-encoded bytes: {exc}"
            ) from exc
        if len(raw) != hashlib.sha256().digest_size:
            raise ValueError(
                f"clusterdek: pinned certificate {pin!r} must be {hashlib.sha256().digest_size} hex-encoded bytes"
            )
        cleaned.append(pin)

    pin_set = {pin.lower() for pin in cleaned} if cleaned else None

    roots: list[x509.Certificate] | None = None
    if ca_file is not None and str(ca_file).strip():
        try:
            pem = Path(ca_file).read_bytes()
        except OSError as exc:
            raise ValueError(f"clusterdek: read trust anchor CA: {exc}") from exc
        roots = _load_pem_certificates(pem)
        if not roots:
            raise ValueError(
                f"clusterdek: trust anchor CA {ca_file} yielded no usable certificate"
            )

    anchor = Anchor(roots=roots, pins=pin_set)
    anchor.validate()
    return anchor


#: The snake_case spelling of :func:`new_anchor`, for callers that prefer it.
new_anchor = new_anchor


def _load_pem_certificates(pem: bytes) -> list[x509.Certificate]:
    """Parse every certificate in a PEM bundle.

    A bundle that carries no certificate at all is refused by the
    caller: a CA file that parsed to nothing must not become an anchor
    that accepts everything.
    """
    certs: list[x509.Certificate] = []
    marker = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    rest = pem
    while True:
        start = rest.find(marker)
        if start < 0:
            break
        stop = rest.find(end, start)
        if stop < 0:
            break
        end_length = len(end)
        block_end = stop + end_length
        block = rest[start:block_end]
        try:
            certs.append(x509.load_pem_x509_certificate(block))
        except ValueError:
            # A block that does not parse is skipped rather than fatal: a
            # bundle may carry material this anchor does not need.
            pass
        cut = stop + end_length
        rest = rest[cut:]
    return certs


def _check_signature(child: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Report whether ``issuer`` signed ``child``."""
    public_key = issuer.public_key()
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(child.signature, child.tbs_certificate_bytes)
        else:
            return False
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _valid_now(cert: x509.Certificate) -> bool:
    """Report whether the certificate is currently valid."""
    now = _utcnow()
    return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc


def _utcnow():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc)


def _is_ca(cert: x509.Certificate) -> bool:
    """Report whether a certificate may act as an issuer."""
    try:
        constraints = cert.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
    except x509.ExtensionNotFound:
        return False
    return bool(constraints.ca)


def _may_sign_certificates(cert: x509.Certificate) -> bool:
    """Report whether the certificate's key usage permits issuing."""
    try:
        usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        return True
    return bool(usage.key_cert_sign)


def _client_chain_problem(
    leaf: x509.Certificate, pool: list[x509.Certificate]
) -> str | None:
    """Return why ``leaf`` may not be a client certificate, or None."""
    if not _valid_now(leaf):
        return "the certificate is outside its validity window"

    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except x509.ExtensionNotFound:
        eku = None
    if eku is not None:
        allowed = {
            x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            x509.oid.ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE,
        }
        if not allowed.intersection(set(eku)):
            return "the certificate is not usable for client authentication"

    chain = _build_chain(leaf, pool)
    if chain is None:
        return "the certificate does not chain to the cluster CA"

    for cert in chain:
        if not _valid_now(cert):
            return f"the certificate issued to {cert.subject.rfc4514_string()} is outside its validity window"
    return None


#: How many certificates a chain may hold before the walk gives up. Go's
#: x509 verifier stops at ten, and the bound is also what keeps a cycle in
#: the pool — a self-signed root is its own issuer — from spinning.
_MAX_CHAIN_DEPTH = 10


def _build_chain(
    leaf: x509.Certificate, pool: list[x509.Certificate]
) -> list[x509.Certificate] | None:
    """Build a chain from ``leaf`` up into the pool, or return None."""
    issuer = _find_issuer(leaf, pool)
    if issuer is None:
        return None
    chain = [leaf, issuer]
    seen = {Fingerprint(leaf), Fingerprint(issuer)}
    current = issuer
    while len(chain) < _MAX_CHAIN_DEPTH:
        parent = _find_issuer(current, pool, require_ca=True)
        if parent is None:
            return chain
        parent_fingerprint = Fingerprint(parent)
        if parent_fingerprint in seen:
            # A self-signed root is its own issuer, so the chain ends there
            # rather than walking the same certificate for ever.
            return chain
        seen.add(parent_fingerprint)
        chain.append(parent)
        current = parent
    return chain


def _find_issuer(
    cert: x509.Certificate,
    pool: list[x509.Certificate],
    *,
    require_ca: bool = False,
) -> x509.Certificate | None:
    """Return a pool certificate that signed ``cert``, if any."""
    for candidate in pool:
        if candidate.subject != cert.issuer:
            continue
        if not _check_signature(cert, candidate):
            continue
        if not _may_sign_certificates(candidate):
            continue
        if require_ca and not _is_ca(candidate):
            continue
        return candidate
    return None
