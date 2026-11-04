"""A record and its field values.

A value carries its type but not its encryption state: whether a field
is encrypted is a property of the schema, so a caller cannot
accidentally write a secret in the clear by forgetting to set a flag.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .errors import InvalidRecordError
from .schema import Type


@dataclass
class Value:
    """A single field's value.

    ``data`` holds the value in its canonical encoding for its type; use
    the constructors to build one and the accessors to read one.
    """

    type: Type = Type.INVALID
    data: bytes = b""

    @classmethod
    def new_string(cls, s: str) -> "Value":
        """A value holding text."""
        return cls(Type.STRING, s.encode("utf-8"))

    @classmethod
    def new_bytes(cls, b: bytes) -> "Value":
        """A value holding a copy of an opaque byte string."""
        return cls(Type.BYTES, bytes(b))

    @classmethod
    def new_int64(cls, i: int) -> "Value":
        """A value holding a signed 64-bit integer."""
        return cls(Type.INT64, int(i).to_bytes(8, "big", signed=True))

    @classmethod
    def new_bool(cls, b: bool) -> "Value":
        """A value holding a boolean."""
        return cls(Type.BOOL, b"\x01" if b else b"\x00")

    def as_string(self) -> str:
        """The value as text."""
        if self.type is not Type.STRING:
            raise InvalidRecordError(f"vault: value is {self.type}, not string")
        return self.data.decode("utf-8")

    def as_bytes(self) -> bytes:
        """The value's bytes."""
        if self.type is not Type.BYTES:
            raise InvalidRecordError(f"vault: value is {self.type}, not bytes")
        return self.data

    def as_int64(self) -> int:
        """The value as an integer.

        Fails if the value is not an int64 or is not in canonical form.
        """
        if self.type is not Type.INT64:
            raise InvalidRecordError(f"vault: value is {self.type}, not int64")
        if len(self.data) != 8:
            raise InvalidRecordError(
                f"vault: int64 value has {len(self.data)} bytes, want 8"
            )
        return int.from_bytes(self.data, "big", signed=True)

    def as_bool(self) -> bool:
        """The value as a boolean.

        Fails if the value is not a bool or is not in canonical form.
        """
        if self.type is not Type.BOOL:
            raise InvalidRecordError(f"vault: value is {self.type}, not bool")
        if len(self.data) != 1 or self.data[0] not in (0, 1):
            raise InvalidRecordError(
                f"vault: bool value has {len(self.data)} bytes, want 1"
            )
        return self.data[0] == 1

    def validate(self) -> None:
        """Check that the value's data matches its type's canonical encoding.

        A value built by hand can be malformed, and writing it would
        persist something the read path cannot decode.
        """
        if self.type is Type.STRING:
            try:
                self.data.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise InvalidRecordError(
                    f"vault: string value is not valid utf-8: {exc}"
                ) from exc
            return
        if self.type is Type.BYTES:
            return
        if self.type is Type.INT64:
            if len(self.data) != 8:
                raise InvalidRecordError(
                    f"vault: int64 value has {len(self.data)} bytes, want 8"
                )
            return
        if self.type is Type.BOOL:
            if len(self.data) != 1 or self.data[0] not in (0, 1):
                raise InvalidRecordError(
                    f"vault: bool value has {len(self.data)} bytes, want 1"
                )
            return
        raise InvalidRecordError(f"vault: unknown value type {int(self.type)}")


@dataclass
class Record:
    """A stored object: an id plus its fields, keyed by field name.

    A record that omits a field the schema declares is written with that
    field absent, which is different from writing it empty.
    """

    id: str = ""
    fields: dict[str, Value] = field(default_factory=dict)

    def get(self, name: str) -> Value | None:
        """The value of the named field, or None when it is not set."""
        return self.fields.get(name)

    def set(self, name: str, value: Value) -> None:
        """Set the value of the named field."""
        self.fields[name] = value

    def get_string(self, name: str) -> str:
        """The named field as text."""
        return self._require(name).as_string()

    def get_bytes(self, name: str) -> bytes:
        """The named field's bytes."""
        return self._require(name).as_bytes()

    def get_int64(self, name: str) -> int:
        """The named field as an integer."""
        return self._require(name).as_int64()

    def get_bool(self, name: str) -> bool:
        """The named field as a boolean."""
        return self._require(name).as_bool()

    def _require(self, name: str) -> Value:
        value = self.fields.get(name)
        if value is None:
            raise InvalidRecordError(f'field "{name}" is not set')
        return value


__all__ = ["Record", "Value"]
