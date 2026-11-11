"""The JSON value stored in etcd, and the codec that reads and writes it.

The on-wire JSON is a contract: every node in the cluster reads it, and the
field names and semantics are frozen by the design document. Do not rename
a field. The value is written verbatim — no re-encoding, no re-ordering —
because the bytes a node writes are the bytes its peers decode.

Two details of the encoding are easy to get wrong:

* ``api_key_cipher`` is base64 on the wire. Go's ``encoding/json`` encodes
  a ``[]byte`` as base64 by default, and that is exactly the lossless form
  wanted: the ciphertext is opaque bytes that callers must not inspect or
  log, and base64 carries it through a JSON string unchanged.

* The JSON bytes have to match what Go's ``encoding/json`` produces for
  the same value, because a Go node has to be able to read them. That
  rules out ``json.dumps``: Go escapes ``<``, ``>`` and ``&`` so that a
  payload cannot be smuggled into an HTML page, it escapes U+2028 and
  U+2029, and it writes a backspace as ``\\u0008`` where Python writes
  ``\\b``. The encoder below therefore does its own escaping, the way Go
  does.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from .errors import InvalidValueError

__all__ = [
    "Entry",
    "RecordEntry",
    "Timestamp",
    "ZERO_TIMESTAMP",
    "marshal_entry",
    "marshal_record",
    "unmarshal_entry",
    "unmarshal_record",
]

_HEX = "0123456789abcdef"

#: The RFC3339 grammar Go's ``time.RFC3339Nano`` accepts: a date, a ``T``
#: separator, a time, an optional fractional part of any length, and a
#: zone that is either ``Z`` or an explicit offset.
_RFC3339_RE = re.compile(
    r"^(?P<date>\d{4}-\d{2}-\d{2})[Tt](?P<time>\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<frac>\d+))?(?P<offset>[Zz]|[+-]\d{2}:\d{2})$"
)


def _go_string(value: str) -> str:
    """Render a string the way Go's ``encoding/json`` does."""
    escaped = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            escaped.append('\\"')
        elif ch == "\\":
            escaped.append("\\\\")
        elif ch == "\n":
            escaped.append("\\n")
        elif ch == "\r":
            escaped.append("\\r")
        elif ch == "\t":
            escaped.append("\\t")
        elif code < 0x20:
            escaped.append(f"\\u00{_HEX[code >> 4]}{_HEX[code & 0xF]}")
        elif ch == "<":
            escaped.append("\\u003c")
        elif ch == ">":
            escaped.append("\\u003e")
        elif ch == "&":
            escaped.append("\\u0026")
        elif code == 0x2028:
            escaped.append("\\u2028")
        elif code == 0x2029:
            escaped.append("\\u2029")
        else:
            escaped.append(ch)
    escaped.append('"')
    return "".join(escaped)


def _go_base64(value: bytes) -> str:
    """Render bytes the way Go's ``encoding/json`` renders a ``[]byte``."""
    return base64.b64encode(value).decode("ascii")


def _normalize_rfc3339nano(text: str) -> str:
    """Return the canonical RFC3339Nano form of ``text``.

    Raises :class:`~.errors.InvalidValueError` when the text is not an
    RFC3339 timestamp.
    """
    match = _RFC3339_RE.match(text)
    if match is None:
        raise InvalidValueError(f"etcdstore: not an RFC3339 timestamp: {text!r}")
    frac = match.group("frac") or ""
    frac = frac.rstrip("0")
    offset = match.group("offset")
    if offset in ("Z", "z"):
        offset = "Z"
    stamp = f"{match.group('date')}T{match.group('time')}"
    if frac:
        stamp += "." + frac
    return stamp + offset


@dataclass(frozen=True)
class Timestamp:
    """An RFC3339Nano timestamp, kept as the text that goes on the wire.

    Python's ``datetime`` holds microseconds; Go's ``time.Time`` holds
    nanoseconds, and the wire carries nanoseconds. Keeping the canonical
    text rather than a ``datetime`` is what makes the round trip
    lossless: a value another node wrote with nine fractional digits
    comes back out with nine fractional digits, not six.
    """

    #: The canonical RFC3339Nano text.
    text: str

    def __post_init__(self) -> None:
        text = _normalize_rfc3339nano(self.text)
        # The pattern checks the shape only; a value such as
        # "2024-02-31T25:61:61Z" has the right shape and no meaning.
        try:
            datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
        except ValueError as exc:
            raise InvalidValueError(
                f"etcdstore: invalid RFC3339 timestamp: {text!r}"
            ) from exc
        object.__setattr__(self, "text", text)

    def __str__(self) -> str:
        return self.text

    @classmethod
    def now(cls) -> Timestamp:
        """The current time, in UTC."""
        return cls.from_datetime(datetime.now(timezone.utc))

    @classmethod
    def from_datetime(cls, value: datetime) -> Timestamp:
        """Build a timestamp from a ``datetime``.

        A naive datetime is refused: a timestamp without a zone cannot
        be compared against another node's, which is the whole point of
        writing RFC3339 rather than a bare number.
        """
        offset = value.utcoffset()
        if offset is None:
            raise InvalidValueError("etcdstore: a timestamp needs a timezone")
        stamp = f"{value.year:04d}-{value.month:02d}-{value.day:02d}T{value.hour:02d}:{value.minute:02d}:{value.second:02d}"
        micro = value.microsecond
        if micro:
            frac = f"{micro:06d}".rstrip("0")
            stamp += "." + frac
        if offset == timedelta(0):
            return cls(stamp + "Z")
        total = int(offset.total_seconds())
        sign = "+" if total >= 0 else "-"
        total = abs(total)
        return cls(f"{stamp}{sign}{total // 3600:02d}:{(total % 3600) // 60:02d}")

    def to_datetime(self) -> datetime:
        """The timestamp as a ``datetime``.

        Sub-microsecond digits are dropped: ``datetime`` cannot hold
        them. The value is informational, never a compare-and-swap
        token, so the loss does not change what any decision is made on.
        """
        text = self.text
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        return datetime.fromisoformat(text)

    def unix_seconds(self) -> int:
        """The timestamp as unix seconds, for the local mirror."""
        return int(self.to_datetime().timestamp())


#: Go's zero ``time.Time``, which is what a missing timestamp decodes to.
ZERO_TIMESTAMP = Timestamp("0001-01-01T00:00:00Z")


@dataclass
class Entry:
    """The JSON value stored under a credential's proxy key.

    It carries the DEK-encrypted upstream secret plus the non-secret
    identity and metadata fields the proxy needs to reconstruct a
    credential row at request time.
    """

    #: The DEK-encrypted upstream API key (or, for MCP bearer / query
    #: injection, the secret to inject). It is opaque bytes — callers
    #: MUST NOT inspect or log it. It travels as base64 because that is
    #: what Go's ``encoding/json`` does with a ``[]byte``, and base64 is
    #: the lossless form.
    api_key_cipher: bytes = b""

    #: Names the injection rule used by the proxy (openai / anthropic /
    #: google / mcp_bearer / mcp_query). Treated as an enum on the wire;
    #: an unknown value is a configuration error and makes the proxy fall
    #: back to the "passthrough" rule rather than crash.
    auth_type: str = ""

    #: The natural-key identity of this credential. It is immutable for
    #: the lifetime of a given proxy_key: changing one of these is the
    #: operation of creating a new proxy_key, not editing the existing
    #: one.
    user_id: str = ""

    #: The upstream base URL. Immutable, like :attr:`user_id`.
    api_base: str = ""

    #: The third part of the natural-key identity. Immutable, like
    #: :attr:`user_id`.
    key_tag: str = ""

    #: The DEK version that produced :attr:`api_key_cipher`. On read it
    #: MUST match the local active DEK version; a mismatch indicates the
    #: entry was rotated and the local cache must re-decrypt (or be
    #: evicted by the watcher).
    dek_version: int = 0

    #: The etcd ModRevision of the key at write time. It MUST equal the
    #: response header revision of the Put/Txn that produced this value.
    #: It is the compare-and-swap expected value used when a record is
    #: updated or removed, and it is mirrored into the local sqlite
    #: row_version column so that an in-flight write can be compared
    #: against the authoritative etcd state without an extra round trip.
    mod_revision: int = 0

    #: When the entry was created, as RFC3339Nano.
    created_at: Timestamp = field(default=ZERO_TIMESTAMP)

    #: When the entry was last changed, as RFC3339Nano.
    updated_at: Timestamp = field(default=ZERO_TIMESTAMP)


@dataclass
class RecordEntry:
    """The JSON value stored under the namespace's record key.

    It is the generic counterpart of :class:`Entry`: the payload is
    opaque bytes owned by the caller, and everything else is the
    bookkeeping the authority needs — which key generation produced the
    payload, which schema version it was written under, and which
    revision it sits at.
    """

    #: The caller-owned payload. The store never inspects it; it travels
    #: as base64, which round-trips losslessly.
    data: bytes = b""

    #: The schema version the payload was written under. The authority
    #: does not interpret it; a reader that holds records from more than
    #: one schema version needs it to know how to decode each one.
    schema_version: int = 0

    #: The key generation that produced :attr:`data`. On read it must
    #: match the local active generation.
    dek_version: int = 0

    #: The etcd ModRevision of the key at write time. It is the
    #: compare-and-swap token an update or a removal compares against,
    #: and the authority stamps it on the way out — the copy persisted in
    #: the payload is not authoritative.
    mod_revision: int = 0

    #: When the record was created, as RFC3339Nano.
    created_at: Timestamp = field(default=ZERO_TIMESTAMP)

    #: When the record was last changed, as RFC3339Nano.
    updated_at: Timestamp = field(default=ZERO_TIMESTAMP)


def marshal_entry(entry: Entry) -> bytes:
    """The canonical JSON representation of ``entry``.

    A ``None`` entry raises :class:`~.errors.InvalidValueError` rather
    than panicking — library code never panics.
    """
    if entry is None:
        raise InvalidValueError("etcdstore: nil entry")
    parts = [
        '"api_key_cipher":' + _go_string(_go_base64(entry.api_key_cipher)),
        '"auth_type":' + _go_string(entry.auth_type),
        '"user_id":' + _go_string(entry.user_id),
        '"api_base":' + _go_string(entry.api_base),
        '"key_tag":' + _go_string(entry.key_tag),
        '"dek_version":' + str(int(entry.dek_version)),
        '"mod_revision":' + str(int(entry.mod_revision)),
        '"created_at":' + _go_string(entry.created_at.text),
        '"updated_at":' + _go_string(entry.updated_at.text),
    ]
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def marshal_record(record: RecordEntry) -> bytes:
    """The canonical JSON representation of ``record``."""
    if record is None:
        raise InvalidValueError("etcdstore: nil record")
    parts = [
        '"data":' + _go_string(_go_base64(record.data)),
        '"schema_version":' + str(int(record.schema_version)),
        '"dek_version":' + str(int(record.dek_version)),
        '"mod_revision":' + str(int(record.mod_revision)),
        '"created_at":' + _go_string(record.created_at.text),
        '"updated_at":' + _go_string(record.updated_at.text),
    ]
    return ("{" + ",".join(parts) + "}").encode("utf-8")


def _load_object(raw: bytes, what: str) -> dict[str, object]:
    """Parse ``raw`` into a JSON object, rejecting anything else."""
    if not raw:
        raise InvalidValueError("etcdstore: empty value")
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise InvalidValueError(
            f"etcdstore: unmarshal {what}: {exc}", cause=exc
        ) from exc
    if not isinstance(parsed, dict):
        raise InvalidValueError(f"etcdstore: unmarshal {what}: not a JSON object")
    return parsed


def _want_str(parsed: dict[str, object], name: str, what: str) -> str:
    """Read a string field.

    Go marshals a nil string as ``null``; it means "absent".
    """
    value = parsed.get(name, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise InvalidValueError(f"etcdstore: unmarshal {what}: {name} is not a string")
    return value


def _want_int(parsed: dict[str, object], name: str, what: str) -> int:
    value = parsed.get(name, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidValueError(f"etcdstore: unmarshal {what}: {name} is not a number")
    return value


def _want_bytes(parsed: dict[str, object], name: str, what: str) -> bytes:
    """Read a base64 field.

    Go marshals a nil ``[]byte`` as ``null`` and an empty one as ``""``;
    both mean "no payload", so ``null`` reads as the empty byte string.
    """
    value = parsed.get(name, "")
    if value is None:
        return b""
    if not isinstance(value, str):
        raise InvalidValueError(f"etcdstore: unmarshal {what}: {name} is not a string")
    # Go's decoder ignores newlines inside base64; strip the whitespace
    # rather than rejecting it, so a value written by a tool that wrapped
    # its base64 still reads.
    packed = "".join(value.split())
    try:
        return base64.b64decode(packed, validate=True)
    except ValueError as exc:
        raise InvalidValueError(
            f"etcdstore: unmarshal {what}: {name} is not base64: {exc}", cause=exc
        ) from exc


def _want_timestamp(parsed: dict[str, object], name: str, what: str) -> Timestamp:
    value = parsed.get(name, "")
    if not isinstance(value, str):
        raise InvalidValueError(f"etcdstore: unmarshal {what}: {name} is not a string")
    if not value:
        return ZERO_TIMESTAMP
    try:
        return Timestamp(value)
    except InvalidValueError as exc:
        raise InvalidValueError(
            f"etcdstore: unmarshal {what}: {name} is not an RFC3339 timestamp: {exc}",
            cause=exc,
        ) from exc


def unmarshal_entry(raw: bytes) -> Entry:
    """Parse the JSON produced by :func:`marshal_entry`."""
    parsed = _load_object(raw, "entry")
    return Entry(
        api_key_cipher=_want_bytes(parsed, "api_key_cipher", "entry"),
        auth_type=_want_str(parsed, "auth_type", "entry"),
        user_id=_want_str(parsed, "user_id", "entry"),
        api_base=_want_str(parsed, "api_base", "entry"),
        key_tag=_want_str(parsed, "key_tag", "entry"),
        dek_version=_want_int(parsed, "dek_version", "entry"),
        mod_revision=_want_int(parsed, "mod_revision", "entry"),
        created_at=_want_timestamp(parsed, "created_at", "entry"),
        updated_at=_want_timestamp(parsed, "updated_at", "entry"),
    )


def unmarshal_record(raw: bytes) -> RecordEntry:
    """Parse the JSON produced by :func:`marshal_record`."""
    parsed = _load_object(raw, "record")
    return RecordEntry(
        data=_want_bytes(parsed, "data", "record"),
        schema_version=_want_int(parsed, "schema_version", "record"),
        dek_version=_want_int(parsed, "dek_version", "record"),
        mod_revision=_want_int(parsed, "mod_revision", "record"),
        created_at=_want_timestamp(parsed, "created_at", "record"),
        updated_at=_want_timestamp(parsed, "updated_at", "record"),
    )
