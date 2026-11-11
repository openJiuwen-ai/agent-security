"""The trust anchor tests.

Ported from ``internal/credmgr/clusterdek/anchor_test.go``. The test names
mirror the Go ones so the correspondence stays auditable.
"""

from __future__ import annotations

import pytest
from cryptography import x509
from security_gateway.vault.clusterdek.anchor import (
    Anchor,
    AnchorError,
    ErrNoTrustAnchor,
    Fingerprint,
    new_anchor,
)

#: The only extended key usage a node's etcd client certificate carries.
CLIENT_AUTH = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH])

#: The usage a certificate for some unrelated service would carry.
SERVER_AUTH = x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])


def test_anchor_refuses_without_any_trust_anchor() -> None:
    # TestAnchorRefusesWithoutAnyTrustAnchor
    """Test anchor refuses without any trust anchor."""
    with pytest.raises(ErrNoTrustAnchor):
        new_anchor("", None)
    # Blank entries must not count, or a config with a stray empty list item
    # would silently satisfy the check that keeps this mandatory.
    with pytest.raises(ErrNoTrustAnchor):
        new_anchor("", ["  ", ""])


def test_anchor_accepts_a_certificate_from_the_configured_ca(
    anchor_pki,
) -> None:
    # TestAnchorAcceptsACertificateFromTheConfiguredCA
    """Test anchor accepts a certificate from the configured ca."""
    anchor = new_anchor(anchor_pki.ca_pem_file, None)
    anchor.verify(anchor_pki.client)


def test_anchor_rejects_a_certificate_from_another_authority(
    anchor_pki,
) -> None:
    # TestAnchorRejectsACertificateFromAnotherAuthority
    """Test anchor rejects a certificate from another authority."""
    anchor = new_anchor(anchor_pki.ca_pem_file, None)
    # The whole point: a roster entry an attacker writes must not be sealed to
    # merely because its key parses.
    with pytest.raises(AnchorError):
        anchor.verify(anchor_pki.rogue_cert)


def test_anchor_rejects_a_certificate_without_client_auth(anchor_pki, leaf) -> None:
    # TestAnchorRejectsACertificateWithoutClientAuth
    """Test anchor rejects a certificate without client auth."""
    anchor = new_anchor(anchor_pki.ca_pem_file, None)
    server_only = leaf(anchor_pki.ca_cert, anchor_pki.ca_key, "some-unrelated-service", SERVER_AUTH)
    # A server certificate from the same CA must be refused: a CA that also
    # signs unrelated services would then be a path to the DEK.
    with pytest.raises(AnchorError):
        anchor.verify(server_only)


def test_anchor_pins_work_without_a_ca(anchor_pki) -> None:
    # TestAnchorPinsWorkWithoutACA
    """Test anchor pins work without a ca."""
    anchor = new_anchor("", [Fingerprint(anchor_pki.client)])
    anchor.verify(anchor_pki.client)
    with pytest.raises(AnchorError):
        anchor.verify(anchor_pki.rogue_cert)


def test_anchor_pins_take_over_when_both_are_configured(anchor_pki, leaf) -> None:
    # TestAnchorPinsTakeOverWhenBothAreConfigured
    """Test anchor pins take over when both are configured."""
    pin = Fingerprint(anchor_pki.client)

    # Pins take over outright when configured, which is the safe direction: a
    # compromised CA can mint a certificate pins will not accept. The hazard
    # is leaving pins behind after moving off the CA, so the anchor reports
    # which source is in force rather than leaving the operator to guess.
    both = new_anchor(anchor_pki.ca_pem_file, [pin])
    assert both.pins_take_over() is True
    assert both.has_ca() is True
    both.verify(anchor_pki.client)

    # A CA-issued certificate that is *not* pinned is refused outright: the
    # pool is parsed but never consulted, which is what makes pins exclusive.
    unpinned = leaf(anchor_pki.ca_cert, anchor_pki.ca_key, "ca-issued but unpinned", CLIENT_AUTH)
    with pytest.raises(AnchorError):
        both.verify(unpinned)

    # Blank pins are not an anchor, so this stays a CA-only setup and must work.
    ca_only = new_anchor(anchor_pki.ca_pem_file, ["  ", ""])
    ca_only.verify(anchor_pki.client)


def test_anchor_accepts_a_fingerprint_with_spaces(anchor_pki) -> None:
    # TestAnchorAcceptsAFingerprintWithSpaces
    """Test a fingerprint copied from openssl still verifies."""
    digest = Fingerprint(anchor_pki.client)
    spaced = " ".join(digest[i:i + 2] for i in range(0, len(digest), 2))
    anchor = new_anchor("", [spaced])
    anchor.verify(anchor_pki.client)


def test_anchor_accepts_a_labelled_upper_case_pin(anchor_pki) -> None:
    # TestAnchorAcceptsALabelledUpperCasePin
    """Test anchor accepts a labelled upper case pin."""
    digest = Fingerprint(anchor_pki.client).upper()
    anchor = new_anchor("", [digest + ":router-a on host-3"])
    anchor.verify(anchor_pki.client)


def test_anchor_rejects_a_malformed_pin() -> None:
    # TestAnchorRejectsAMalformedPin
    """Test anchor rejects a malformed pin."""
    for bad in ("not-hex", "abcd", "z" * 64, "ab" * 31):
        with pytest.raises(ValueError):
            new_anchor("", [bad])


def test_anchor_rejects_an_unusable_ca_file(tmp_path) -> None:
    # TestAnchorRejectsAnUnusableCAFile
    """Test anchor rejects an unusable ca file."""
    empty = tmp_path / "empty.pem"
    empty.write_text("# no certificates here\n")
    with pytest.raises(ValueError):
        new_anchor(str(empty), None)
    with pytest.raises(ValueError):
        new_anchor(str(tmp_path / "absent.pem"), None)


def test_verify_on_an_anchor_with_no_source_refuses() -> None:
    # TestVerifyOnANilAnchorRefuses. Go passes a nil *Anchor, which is how a
    # node that has nothing configured is represented; Python spells the same
    # state as an anchor with neither a CA nor a pin.
    """Test verify on an anchor with no source refuses."""
    anchor = Anchor()
    with pytest.raises(ErrNoTrustAnchor):
        anchor.verify(None)


def test_fingerprint_matches_openssl_format(anchor_pki) -> None:
    # TestfingerprintMatchesOpensslFormat
    """Test fingerprint matches openssl format."""
    digest = Fingerprint(anchor_pki.client)
    # openssl prints uppercase hex of the DER hash; the anchor accepts
    # either case but always stores and compares lowercase.
    assert len(digest) == 64
    assert digest.strip("0123456789abcdef") == ""


def test_fingerprint_is_over_the_certificate_not_the_key(anchor_pki, leaf) -> None:
    # Not in the Go file, but the Go comment in anchor.go says it: the same
    # key re-issued in a new certificate is a different certificate.
    """Test fingerprint is over the certificate not the key."""
    reissued = leaf(anchor_pki.ca_cert, anchor_pki.ca_key, "router-a", CLIENT_AUTH)
    assert Fingerprint(reissued) != Fingerprint(anchor_pki.client)
