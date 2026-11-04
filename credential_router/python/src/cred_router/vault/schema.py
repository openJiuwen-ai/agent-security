"""The schema: the shape of a record.

A schema is declared by the host service, in code. The store persists
the schema it was initialised with and refuses to open against a
different one, so the rules here are narrow on purpose: a field name is
a key in the persisted container, so it is restricted to a URL-safe
subset and bounded in length.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from .errors import InvalidSchemaError

#: The longest a field name may be. A field name is a key in the persisted
#: container, so an unbounded name is an unbounded row.
MAX_FIELD_NAME_LEN = 128

#: The persisted name of each type. These strings are part of the stored
#: schema definition, so they must not change.
_TYPE_NAMES: dict[int, str] = {
    1: "string",
    2: "bytes",
    3: "int64",
    4: "bool",
}

_NAME_TO_TYPE: dict[str, int] = {name: code for code, name in _TYPE_NAMES.items()}


class Type(IntEnum):
    """The type of a record field's value.

    A stored value carries its type tag, so a reader can tell a string
    from an int64 without consulting the schema; a disagreement between
    the tag and the schema is an error rather than a guess.
    """

    INVALID = 0
    STRING = 1
    BYTES = 2
    INT64 = 3
    BOOL = 4

    def __str__(self) -> str:
        """The type's stable, machine-readable name."""
        return _TYPE_NAMES.get(int(self), "invalid")

    def __format__(self, format_spec: str) -> str:
        return format(str(self), format_spec)

    @property
    def valid(self) -> bool:
        """Whether this is one of the defined types."""
        return int(self) in _TYPE_NAMES

    @classmethod
    def from_name(cls, name: str) -> "Type":
        """Resolve a persisted type name back to a Type."""
        code = _NAME_TO_TYPE.get(name)
        if code is None:
            raise InvalidSchemaError(f"vault: unknown field type {name!r}")
        return cls(code)


@dataclass
class FieldDef:
    """One field of a record."""

    #: The field's key. It must be unique within a schema and must match
    #: ``[A-Za-z0-9._-]+``.
    name: str

    #: The field's value type.
    type: Type = Type.INVALID

    #: Whether the field's value is stored encrypted. This flag is
    #: authoritative: the stored bytes carry a flag too, but only so a
    #: reader can detect a disagreement with the schema.
    encrypted: bool = False


@dataclass
class Schema:
    """The shape of a record.

    ``version`` must be a positive integer and there must be at least
    one field. The field order is the order the fields are written to
    the container in; the persisted form sorts them by name.
    """

    version: int = 0
    fields: list[FieldDef] = field(default_factory=list)

    def validate(self) -> None:
        """Report whether the schema is well-formed."""
        if self.version <= 0:
            raise InvalidSchemaError(
                f"version must be positive, got {self.version}"
            )
        if not self.fields:
            raise InvalidSchemaError("schema has no fields")
        seen: set[str] = set()
        for i, f in enumerate(self.fields):
            if f.name == "":
                raise InvalidSchemaError(
                    f"field {i}: name is empty"
                )
            # The limit is on bytes, not characters: the name ends up in a
            # length-prefixed field of the persisted container.
            if len(f.name.encode("utf-8")) > MAX_FIELD_NAME_LEN:
                raise InvalidSchemaError(
                    f'field "{f.name}": name exceeds {MAX_FIELD_NAME_LEN} bytes'
                )
            if not valid_field_name(f.name):
                raise InvalidSchemaError(
                    f'field "{f.name}": name must match [A-Za-z0-9._-]+'
                )
            if not f.type.valid:
                raise InvalidSchemaError(
                    f'field "{f.name}": unknown type {int(f.type)}'
                )
            if f.name in seen:
                raise InvalidSchemaError(
                    f'field "{f.name}": duplicate name'
                )
            seen.add(f.name)

    def field_lookup(self) -> dict[str, FieldDef]:
        """The schema's field definitions keyed by name."""
        return {f.name: f for f in self.fields}

    def canonical_json(self) -> bytes:
        """The schema's stable persisted representation."""
        self.validate()
        payload = {
            "version": self.version,
            "fields": [
                {"name": f.name, "type": str(f.type), "encrypted": f.encrypted}
                for f in sorted(self.fields, key=lambda f: f.name)
            ],
        }
        return json.dumps(
            payload, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def hash(self) -> bytes:
        """The SHA-256 of the schema's canonical JSON.

        The store compares it at open time to tell "the schema changed
        but nobody bumped the version" apart from "the schema
        legitimately moved to a new version". A version match with a
        hash mismatch is refused.
        """
        return hashlib.sha256(self.canonical_json()).digest()

    def describe(self) -> str:
        """Render the schema for an error message."""
        names = sorted(f.name for f in self.fields)
        return "v%d{%s}" % (self.version, ",".join(names))


def valid_field_name(name: str) -> bool:
    """Report whether ``name`` matches ``[A-Za-z0-9._-]+``."""
    if not name:
        return False
    return all(
        c.isascii() and (c.isalnum() or c in "._-") for c in name
    )


def parse_schema(definition: bytes | str) -> Schema:
    """Decode a persisted schema definition."""
    if isinstance(definition, str):
        definition = definition.encode("utf-8")
    try:
        raw: Any = json.loads(definition.decode("utf-8"))
        version = int(raw.get("version", 0))
        raw_fields = raw.get("fields") or []
        fields = [
            FieldDef(
                name=str(f.get("name", "")),
                type=Type.from_name(str(f.get("type", ""))),
                encrypted=bool(f.get("encrypted", False)),
            )
            for f in raw_fields
        ]
    except (ValueError, TypeError, AttributeError) as exc:
        raise InvalidSchemaError(f"vault: parse schema: {exc}") from exc
    out = Schema(version=version, fields=fields)
    out.validate()
    return out


__all__ = [
    "MAX_FIELD_NAME_LEN",
    "FieldDef",
    "Schema",
    "Type",
    "parse_schema",
    "valid_field_name",
]
