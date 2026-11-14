"""The handover request tests.

Ported from ``internal/credmgr/clusterdek/handover_test.go``. The test names
mirror the Go ones so the correspondence stays auditable.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from security_gateway.vault.clusterdek.handover import (
    HandoverRequest,
    marshal_public_key,
    marshal_request,
    parse_public_key,
    unmarshal_request,
    verify_request,
)
from security_gateway.vault.clusterdek.wrap import ErrMalformed, public_key_of


def _signed_request(priv: ec.EllipticCurvePrivateKey) -> HandoverRequest:
    """The request Go's ``handoverTestRequest`` builds."""
    one_shot = ec.generate_private_key(ec.SECP256R1())
    request = HandoverRequest(
        node_id="router-b",
        generation=2,
        nonce="n-1",
        public_key=marshal_public_key(one_shot.public_key()),
    )
    request.sign(priv)
    return request


def test_handover_request_verifies_against_the_rosters_certificate() -> None:
    # TestHandoverRequestVerifiesAgainstTheRostersCertificate
    """Test handover request verifies against the rosters certificate."""
    priv = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)

    # A request that verifies against the certificate the roster vouches for
    # is the whole point: it is what tells the holder that the one-shot key
    # belongs to the node it is about to hand the DEK to.
    verify_request(priv.public_key(), request)


def test_handover_request_signed_by_another_key_is_refused() -> None:
    # TestHandoverRequestSignedByAnotherKeyIsRefused
    """Test handover request signed by another key is refused."""
    priv = ec.generate_private_key(ec.SECP256R1())
    other = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)

    # Anyone who can write to etcd can publish a request. Without the
    # signature the holder would seal the DEK to that key, and the writer
    # would have the DEK.
    with pytest.raises(ErrMalformed):
        verify_request(other.public_key(), request)


@pytest.mark.parametrize("field", ["node id", "generation", "nonce", "public key"])
def test_handover_request_rejects_every_tampered_field(field: str) -> None:
    # TestHandoverRequestRejectsEveryTamperedField
    # Every field is inside the signed bytes, so changing any of them breaks
    # the signature. The node id is the one that matters most: without it a
    # request could be replayed as another node's.
    """Test handover request rejects every tampered field."""
    priv = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)

    if field == "node id":
        request.node_id = "router-c"
    elif field == "generation":
        request.generation = 3
    elif field == "nonce":
        request.nonce = "n-2"
    else:
        other = ec.generate_private_key(ec.SECP256R1())
        request.public_key = marshal_public_key(other.public_key())

    with pytest.raises(ErrMalformed):
        verify_request(priv.public_key(), request)


def test_handover_signed_bytes_do_not_collide() -> None:
    # TestHandoverSignedBytesDoNotCollide
    """Test handover signed bytes do not collide."""
    a = HandoverRequest(node_id="ab", nonce="c", generation=1, public_key=b"\x01")
    b = HandoverRequest(node_id="a", nonce="bc", generation=1, public_key=b"\x01")
    # The length-prefixed encoding is what makes the signed bytes
    # unambiguous: two different field values must not produce the same
    # bytes, or a signature over one would verify against the other.
    assert a.signed_bytes() != b.signed_bytes()


def test_handover_request_without_a_signature_is_refused() -> None:
    # TestHandoverRequestWithoutASignatureIsRefused
    """Test handover request without a signature is refused."""
    priv = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)
    request.signature = b""

    # An unsigned request is refused rather than treated as a request that
    # happens to be harmless.
    with pytest.raises(ErrMalformed):
        verify_request(priv.public_key(), request)


def test_handover_request_survives_the_store_round_trip() -> None:
    # TestHandoverRequestSurvivesTheStoreRoundTrip
    """Test handover request survives the store round trip."""
    priv = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)

    raw = marshal_request(request)
    back = unmarshal_request(raw)

    # The request survives the trip through the store, and still verifies
    # afterwards: the bytes the store holds are the bytes that were signed.
    verify_request(priv.public_key(), back)
    assert back.node_id == request.node_id
    assert back.generation == request.generation
    assert back.nonce == request.nonce


def test_handover_request_is_signed_by_the_etcd_client_key(
    etcd_client_cert,
) -> None:
    # TestHandoverRequestIsSignedByTheEtcdClientKey
    """Test handover request is signed by the etcd client key."""
    cert, priv = etcd_client_cert
    cert_pub = public_key_of(cert)

    request = _signed_request(priv)

    # The request is signed with the node's etcd client key, and the holder
    # verifies it with the public key of that node's certificate. The binding
    # between the two is what the trust anchor already established, so the
    # handover needs no trust material of its own.
    verify_request(cert_pub, request)


def test_handover_request_names_the_generation_it_wants() -> None:
    # TestHandoverRequestNamesTheGenerationItWants
    """Test handover request names the generation it wants."""
    priv = ec.generate_private_key(ec.SECP256R1())
    request = _signed_request(priv)

    # The signature covers the request, and the request names the generation
    # the node is asking for. A holder that answers a request for a
    # generation it has moved past would hand out a DEK the fleet no longer
    # uses.
    assert request.generation == 2
    raw = marshal_request(request)
    assert b'"generation":2' in raw


# -- the one-shot key encoding ---------------------------------------------
# Go exercises marshal_public_key and parse_public_key from handover.go but has
# no test file for them; the Python port keeps both, so they are covered
# here.


def test_marshal_and_parse_public_key_round_trip() -> None:
    """Test marshal and parse public key round trip."""
    key = ec.generate_private_key(ec.SECP256R1())

    encoded = marshal_public_key(key.public_key())
    assert len(encoded) == 65  # uncompressed SEC1 point on P-256

    parsed = parse_public_key(encoded)
    assert parsed.public_numbers() == key.public_key().public_numbers()


def test_parse_public_key_rejects_a_point_that_is_not_on_the_curve() -> None:
    """Test parse public key rejects a point that is not on the curve."""
    not_a_point = b"\x04" + b"\x01" * 64

    with pytest.raises(ErrMalformed):
        parse_public_key(not_a_point)


def test_parse_public_key_rejects_an_empty_key() -> None:
    """Test parse public key rejects an empty key."""
    with pytest.raises(ErrMalformed):
        parse_public_key(b"")


def test_unmarshal_request_rejects_a_body_that_is_not_json() -> None:
    """Test unmarshal request rejects a body that is not json."""
    with pytest.raises(ErrMalformed):
        unmarshal_request(b"not json at all")


def test_unmarshal_request_rejects_a_public_key_that_is_not_base64() -> None:
    """Test unmarshal request rejects a public key that is not base64."""
    raw = b'{"node_id":"router-b","generation":2,"nonce":"n-1","public_key":"!!!not base64!!!","signature":""}'

    with pytest.raises(ErrMalformed):
        unmarshal_request(raw)


def test_a_client_auth_certificate_carries_the_etcd_client_key(
    etcd_client_cert,
) -> None:
    # Not a Go test, but the Go comment in handover.go says the request is
    # signed with the node's etcd client key and the holder verifies it with
    # the public key of that node's certificate.
    """Test a client auth certificate carries the etcd client key."""
    cert, priv = etcd_client_cert

    assert public_key_of(cert).public_numbers() == priv.public_key().public_numbers()
