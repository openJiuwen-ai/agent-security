"""The shape of a credential record, and how to read and write one.

The field *names* belong to whoever deploys the store — they declare them
in its configuration. A client does not know the names; it knows the
shape:

    exactly one encrypted field          the secret itself
    exactly one plain string field       the kind
    exactly one plain field, other type  the metadata (JSON)

A shape that does not match is an error, not a guess. One plain field more
or less makes "which one is the kind" ambiguous, and guessing in the face
of ambiguity means handing out a field that is not the secret.
"""

from __future__ import annotations

import base64
import json
from typing import Any


class VaultError(RuntimeError):
    """The store could not be reached, or it answered with the wrong shape."""


class Shape:
    """Which field of a record carries what.

    The names are the deployer's; this remembers which name plays which
    role.
    """

    __slots__ = ("kind", "secret", "meta")

    def __init__(self, kind: str, secret: str, meta: str) -> None:
        self.kind = kind
        self.secret = secret
        self.meta = meta

    def __repr__(self) -> str:
        return (
            f"Shape(kind={self.kind!r}, secret={self.secret!r}, "
            f"meta={self.meta!r})"
        )


def resolve_shape(schema_fields: list[dict[str, Any]]) -> Shape:
    """Work out which field is which from the schema's field table."""
    encrypted = [f["name"] for f in schema_fields if f.get("encrypted")]
    plain = [f for f in schema_fields if not f.get("encrypted")]
    kind = [f["name"] for f in plain if f.get("type") == "string"]
    meta = [f["name"] for f in plain if f.get("type") != "string"]
    if len(encrypted) != 1 or len(kind) != 1 or len(meta) != 1:
        raise VaultError(
            "the vault's schema must declare exactly one encrypted field, "
            "one plain string field and one plain field of another type; "
            f"it declares {schema_fields}"
        )
    return Shape(kind[0], encrypted[0], meta[0])


def encode_put(
    shape: Shape,
    kind: str,
    value: bytes,
    meta: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Encode an object into the fields array of a put request."""
    blob = json.dumps(meta or {}, ensure_ascii=False).encode("utf-8")
    return [
        {
            "name": shape.kind,
            "type": "string",
            "data": base64.b64encode(kind.encode("utf-8")).decode("ascii"),
        },
        {
            "name": shape.secret,
            "type": "bytes",
            "data": base64.b64encode(value).decode("ascii"),
        },
        {
            "name": shape.meta,
            "type": "bytes",
            "data": base64.b64encode(blob).decode("ascii"),
        },
    ]


def decode_payload(
    shape: Shape,
    object_fields: list[dict[str, Any]] | None,
) -> bytes | None:
    """Take the secret out of the fields of a get answer."""
    for field in object_fields or []:
        if field.get("name") == shape.secret:
            raw = field.get("data")
            if not raw:
                return b""
            return base64.b64decode(raw)
    return None
