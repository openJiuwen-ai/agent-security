"""The VREC container: the on-disk encoding of a record's fields.

::

    vault container
      [0..4)   magic         4 bytes  "VREC"
      [4]      format        1 byte   0x01
      [5..7)   field count   2 bytes  big endian
      per field:
        name length      2 bytes  big endian
        name             name length bytes
        type             1 byte
        flags            1 byte   bit 0 = encrypted
        value length     4 bytes  big endian
        value            value length bytes

The magic makes a truncated or foreign blob fail loudly instead of being
decoded into plausible nonsense. The format byte leaves room to change
the encoding without guessing.

The encrypted flag is recorded per field so a reader can cross-check it
against the schema. It is not authoritative: the schema decides whether
a value is encrypted, and a flag that disagrees with it is an error.
"""

from __future__ import annotations

from dataclasses import dataclass

from .errors import InvalidRecordError
from .schema import Type

#: The container's magic. A blob that does not start with it is not ours.
CONTAINER_MAGIC = b"VREC"

#: The container format version.
CONTAINER_FORMAT = 0x01

#: The size of the container header: magic, format byte, field count.
CONTAINER_HEADER_SIZE = 4 + 1 + 2

#: Marks a field whose stored bytes are an AEAD blob rather than the value.
FLAG_ENCRYPTED = 1 << 0


@dataclass
class ContainerField:
    """One field as it appears in the container."""

    name: str
    type: Type
    encrypted: bool
    data: bytes


def _type_from_byte(code: int) -> Type:
    """Map a stored type byte onto a Type."""
    try:
        return Type(code)
    except ValueError:
        return Type.INVALID


def encode_container(fields: list[ContainerField]) -> bytes:
    """Render fields into the container format."""
    if len(fields) > 0xFFFF:
        raise InvalidRecordError(
            f"vault: container: {len(fields)} fields exceeds the {0xFFFF} limit"
        )
    out = bytearray()
    out += CONTAINER_MAGIC
    out.append(CONTAINER_FORMAT)
    out += len(fields).to_bytes(2, "big")
    for f in fields:
        name = f.name.encode("utf-8")
        if len(name) > 0xFFFF:
            raise InvalidRecordError(
                f"vault: container: field name {f.name!r} is too long"
            )
        if len(f.data) > 0xFFFFFFFF:
            raise InvalidRecordError(
                f"vault: container: field {f.name!r} value is too long"
            )
        out += len(name).to_bytes(2, "big")
        out += name
        out.append(int(f.type))
        out.append(FLAG_ENCRYPTED if f.encrypted else 0)
        out += len(f.data).to_bytes(4, "big")
        out += f.data
    return bytes(out)


def decode_container(data: bytes) -> list[ContainerField]:
    """Parse the container format."""
    if len(data) < CONTAINER_HEADER_SIZE:
        raise InvalidRecordError(
            f"vault: container: {len(data)} bytes is shorter than the header"
        )
    if data[0:4] != CONTAINER_MAGIC:
        raise InvalidRecordError(
            f"vault: container: bad magic {data[0:4]!r}"
        )
    if data[4] != CONTAINER_FORMAT:
        raise InvalidRecordError(
            f"vault: container: unsupported format 0x{data[4]:02x}"
        )
    count = int.from_bytes(data[5:7], "big")
    out: list[ContainerField] = []
    off = CONTAINER_HEADER_SIZE

    for i in range(count):
        if off + 2 > len(data):
            raise InvalidRecordError(
                f"vault: container: truncated at field {i} name length"
            )
        name_len = int.from_bytes(data[off:off + 2], "big")
        off += 2
        if off + name_len > len(data):
            raise InvalidRecordError(
                f"vault: container: truncated at field {i} name"
            )
        name = data[off:off + name_len].decode("utf-8", "replace")
        off += name_len

        if off + 2 > len(data):
            raise InvalidRecordError(
                f"vault: container: truncated at field {i} header"
            )
        typ = _type_from_byte(data[off])
        flags = data[off + 1]
        off += 2

        if off + 4 > len(data):
            raise InvalidRecordError(
                f"vault: container: truncated at field {i} value length"
            )
        val_len = int.from_bytes(data[off:off + 4], "big")
        off += 4
        if off + val_len > len(data):
            raise InvalidRecordError(
                f"vault: container: truncated at field {i} value"
            )
        val = data[off:off + val_len]
        off += val_len

        out.append(
            ContainerField(
                name=name,
                type=typ,
                encrypted=bool(flags & FLAG_ENCRYPTED),
                data=val,
            )
        )
    return out


__all__ = [
    "CONTAINER_FORMAT",
    "CONTAINER_HEADER_SIZE",
    "CONTAINER_MAGIC",
    "FLAG_ENCRYPTED",
    "ContainerField",
    "decode_container",
    "encode_container",
]
