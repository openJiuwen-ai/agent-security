"""The VREC container.

The Go counterpart is ``pkg/vault/codec_test.go``. The container is the
on-disk encoding of a record's fields, so its bytes are pinned down: a
change here is a change to every file the store has ever written.
"""

from __future__ import annotations

import pytest
from security_gateway.vault import (
    CONTAINER_FORMAT,
    CONTAINER_HEADER_SIZE,
    CONTAINER_MAGIC,
    ContainerField,
    InvalidRecordError,
    Type,
    decode_container,
    encode_container,
)


def _fields():
    return [
        ContainerField(
            name="endpoint",
            type=Type.STRING,
            encrypted=False,
            data=b"https://api.example.com",
        ),
        ContainerField(
            name="api_key",
            type=Type.STRING,
            encrypted=True,
            data=bytes([0x01, 0x02, 0x03, 0x04]),
        ),
        ContainerField(
            name="retries",
            type=Type.INT64,
            encrypted=False,
            data=bytes([0, 0, 0, 0, 0, 0, 0, 7]),
        ),
    ]


def test_container_round_trip():
    fields = _fields()
    decoded = decode_container(encode_container(fields))
    assert len(decoded) == len(fields)
    for got, want in zip(decoded, fields):
        assert got.name == want.name
        assert got.type == want.type
        assert got.encrypted == want.encrypted
        assert got.data == want.data


def test_the_container_bytes_are_what_the_format_says():
    """The layout is fixed by the format, not by this implementation."""
    encoded = encode_container(
        [ContainerField(name="a", type=Type.STRING, encrypted=False, data=b"xy")]
    )
    assert encoded == (
        b"VREC"
        + bytes([CONTAINER_FORMAT])
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + b"a"
        + bytes([int(Type.STRING)])
        + bytes([0])
        + (2).to_bytes(4, "big")
        + b"xy"
    )
    assert len(encoded) == CONTAINER_HEADER_SIZE + 2 + 1 + 1 + 1 + 4 + 2


def test_the_encrypted_flag_is_bit_zero():
    encoded = encode_container(
        [ContainerField(name="a", type=Type.STRING, encrypted=True, data=b"xy")]
    )
    # magic, format, count, name length, name, type, flags
    assert encoded[CONTAINER_HEADER_SIZE + 2 + 1 + 1] == 0x01


@pytest.mark.parametrize(
    ("name", "data"),
    [
        ("empty", b""),
        ("short header", b"VRE"),
        ("bad magic", b"XXXX" + b"\x01\x00\x00"),
        ("unknown format", b"VREC" + bytes([0x7F]) + b"\x00\x00"),
    ],
)
def test_decode_container_rejects_malformed_input(name, data):
    with pytest.raises(InvalidRecordError):
        decode_container(data)


def test_decode_container_rejects_a_truncated_blob():
    valid = encode_container(
        [ContainerField(name="a", type=Type.STRING, encrypted=False, data=b"x")]
    )
    for cut in range(1, len(valid)):
        with pytest.raises(InvalidRecordError):
            decode_container(valid[:cut])


def test_decode_container_rejects_a_count_larger_than_the_data():
    """A field count that claims more fields than the blob holds must be an
    error, not a read past the end of the buffer."""
    data = CONTAINER_MAGIC + bytes([CONTAINER_FORMAT]) + b"\xff\xff"
    with pytest.raises(InvalidRecordError):
        decode_container(data)


def test_decode_container_rejects_a_hostile_length():
    """A length field that claims more bytes than the blob holds must be an
    error, not an out-of-range read."""
    data = (
        CONTAINER_MAGIC
        + bytes([CONTAINER_FORMAT])
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + b"a"
        + bytes([int(Type.STRING)])
        + bytes([0])
        + (0xFFFFFFFF).to_bytes(4, "big")
    )
    with pytest.raises(InvalidRecordError):
        decode_container(data)


def test_an_unknown_type_byte_does_not_crash_the_decoder():
    """The container does not decide whether a record is readable.

    An unknown type is carried as "invalid" and the schema comparison is
    what reports the disagreement, which is what the Go original does
    because its ``Type.String`` also renders an unknown type as
    "invalid".
    """
    data = (
        CONTAINER_MAGIC
        + bytes([CONTAINER_FORMAT])
        + (1).to_bytes(2, "big")
        + (1).to_bytes(2, "big")
        + b"a"
        + bytes([99])
        + bytes([0])
        + (0).to_bytes(4, "big")
    )
    decoded = decode_container(data)
    assert decoded[0].type is Type.INVALID
    assert str(decoded[0].type) == "invalid"
