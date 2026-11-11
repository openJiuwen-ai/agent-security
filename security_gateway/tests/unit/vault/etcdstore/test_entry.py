"""The JSON value stored in etcd, and its codec.

The Go original is ``internal/credmgr/etcdstore/entry.go``.
"""

from __future__ import annotations

import base64
import json

import pytest
from security_gateway.vault.etcdstore.entry import (
    ZERO_TIMESTAMP,
    Entry,
    RecordEntry,
    Timestamp,
    marshal_entry,
    marshal_record,
    unmarshal_entry,
    unmarshal_record,
)
from security_gateway.vault.etcdstore.errors import InvalidValueError

_EXPECTED_FIELDS = [
    "api_key_cipher",
    "auth_type",
    "user_id",
    "api_base",
    "key_tag",
    "dek_version",
    "mod_revision",
    "created_at",
    "updated_at",
]


def _entry() -> Entry:
    return Entry(
        api_key_cipher=b"\x00\x01\x02",
        auth_type="openai",
        user_id="acct-1",
        api_base="https://api.example.test/v1",
        key_tag="primary",
        dek_version=1,
        mod_revision=12345,
        created_at=Timestamp("2026-01-01T00:00:00.123456789Z"),
        updated_at=Timestamp("2026-01-01T00:00:00.123456789Z"),
    )


def test_the_json_is_exactly_what_go_would_write() -> None:
    # The bytes have to match Go's encoding/json, because a Go node has
    # to be able to read them: compact separators, the field names of
    # the design document, and the field order Go's struct declares.
    """Test the json is exactly what go would write."""
    assert marshal_entry(_entry()) == (
        b'{"api_key_cipher":"AAEC","auth_type":"openai","user_id":"acct-1",'
        b'"api_base":"https://api.example.test/v1","key_tag":"primary",'
        b'"dek_version":1,"mod_revision":12345,'
        b'"created_at":"2026-01-01T00:00:00.123456789Z",'
        b'"updated_at":"2026-01-01T00:00:00.123456789Z"}'
    )


def test_the_field_names_are_the_frozen_ones() -> None:
    """Test the field names are the frozen ones."""
    parsed = json.loads(marshal_entry(_entry()))
    assert list(parsed) == _EXPECTED_FIELDS


def test_the_entry_round_trips() -> None:
    """Test the entry round trips."""
    entry = _entry()
    assert unmarshal_entry(marshal_entry(entry)) == entry


def test_the_api_key_cipher_is_base64_on_the_wire() -> None:
    """Test the api key cipher is base64 on the wire."""
    entry = _entry()
    raw = marshal_entry(entry)
    parsed = json.loads(raw)
    assert parsed["api_key_cipher"] == base64.b64encode(entry.api_key_cipher).decode()
    assert parsed["api_key_cipher"] == "AAEC"
    # ... and it comes back as the original bytes.
    assert unmarshal_entry(raw).api_key_cipher == entry.api_key_cipher


def test_the_api_key_cipher_keeps_arbitrary_bytes() -> None:
    """Test the api key cipher keeps arbitrary bytes."""
    cipher = bytes(range(256))
    entry = _entry()
    entry.api_key_cipher = cipher
    assert unmarshal_entry(marshal_entry(entry)).api_key_cipher == cipher


def test_the_timestamps_are_rfc3339nano() -> None:
    """Test the timestamps are rfc3339nano."""
    parsed = json.loads(marshal_entry(_entry()))
    assert parsed["created_at"] == "2026-01-01T00:00:00.123456789Z"
    assert parsed["updated_at"] == "2026-01-01T00:00:00.123456789Z"


def test_the_timestamps_round_trip_losslessly() -> None:
    # Nanoseconds have to survive: a node that reads a value another node
    # wrote and writes it back must produce the same bytes, or every
    # rewrite looks like a change.
    """Test the timestamps round trip losslessly."""
    entry = _entry()
    entry.created_at = Timestamp("2026-01-01T00:00:00.000000001Z")
    entry.updated_at = Timestamp("2026-01-01T00:00:00.999999999Z")
    decoded = unmarshal_entry(marshal_entry(entry))
    assert decoded.created_at.text == "2026-01-01T00:00:00.000000001Z"
    assert decoded.updated_at.text == "2026-01-01T00:00:00.999999999Z"
    assert decoded == entry


def test_a_timestamp_without_a_fraction_is_written_without_one() -> None:
    # RFC3339Nano drops the fraction when it is zero, and Go does the
    # same, so the bytes match.
    """Test a timestamp without a fraction is written without one."""
    entry = _entry()
    entry.created_at = Timestamp("2026-01-01T00:00:00Z")
    assert b'"created_at":"2026-01-01T00:00:00Z"' in marshal_entry(entry)


def test_trailing_zeros_in_the_fraction_are_dropped() -> None:
    # Go's RFC3339Nano trims them, so a value written by Go comes back
    # in the same shape.
    """Test trailing zeros in the fraction are dropped."""
    assert Timestamp("2026-01-01T00:00:00.123456000Z").text == (
        "2026-01-01T00:00:00.123456Z"
    )


def test_a_timestamp_keeps_its_offset() -> None:
    """Test a timestamp keeps its offset."""
    assert Timestamp("2026-01-01T00:00:00+08:00").text == "2026-01-01T00:00:00+08:00"


def test_a_timestamp_converts_to_unix_seconds() -> None:
    # The local SQLite mirror keeps unix seconds; the wire keeps
    # RFC3339Nano. The conversion belongs to this layer.
    """Test a timestamp converts to unix seconds."""
    assert Timestamp("2026-01-01T00:00:00Z").unix_seconds() == 1767225600


def test_a_timestamp_made_from_a_datetime_keeps_its_microseconds() -> None:
    """Test a timestamp made from a datetime keeps its microseconds."""
    from datetime import datetime, timezone

    stamp = Timestamp.from_datetime(
        datetime(2026, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc)
    )
    assert stamp.text == "2026-01-01T00:00:00.123456Z"
    assert stamp.to_datetime() == datetime(
        2026, 1, 1, 0, 0, 0, 123456, tzinfo=timezone.utc
    )


def test_a_naive_datetime_is_refused() -> None:
    """Test a naive datetime is refused."""
    from datetime import datetime

    with pytest.raises(InvalidValueError):
        Timestamp.from_datetime(datetime(2026, 1, 1))


def test_a_malformed_timestamp_is_refused() -> None:
    """Test a malformed timestamp is refused."""
    with pytest.raises(InvalidValueError):
        Timestamp("2026-01-01 00:00:00")
    with pytest.raises(InvalidValueError):
        Timestamp("not a timestamp")


def test_the_json_escapes_the_way_go_does() -> None:
    # Go escapes <, > and & so a payload cannot be smuggled into an HTML
    # page, escapes the JavaScript line separators, and writes a
    # backspace as  where Python writes \b.
    """Test the json escapes the way go does."""
    entry = _entry()
    entry.user_id = "<a&b>\b "
    raw = marshal_entry(entry)
    assert b'"user_id":"\\u003ca\\u0026b\\u003e\\u0008\\u2028"' in raw
    assert b"\\b" not in raw


def test_the_json_is_compact() -> None:
    """Test the json is compact."""
    raw = marshal_entry(_entry())
    assert b": " not in raw
    assert b", " not in raw


def test_an_unknown_field_is_ignored() -> None:
    """Test an unknown field is ignored."""
    # The key is shared with the Go implementation, whose decoder drops
    # what it does not know; refusing here would lock a newer node out.
    document = json.loads(marshal_entry(_entry()))
    document["extra_field"] = 1
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    assert unmarshal_entry(raw) == _entry()


def test_an_empty_value_is_refused() -> None:
    """Test an empty value is refused."""
    with pytest.raises(InvalidValueError):
        unmarshal_entry(b"")


def test_a_field_of_the_wrong_type_is_refused() -> None:
    """Test a field of the wrong type is refused."""
    raw = marshal_entry(_entry()).replace(b'"dek_version":1', b'"dek_version":"1"')
    with pytest.raises(InvalidValueError):
        unmarshal_entry(raw)


def test_a_value_that_is_not_an_object_is_refused() -> None:
    """Test a value that is not an object is refused."""
    with pytest.raises(InvalidValueError):
        unmarshal_entry(b"[1,2,3]")


def test_a_missing_field_decodes_to_the_zero_value() -> None:
    # Go leaves a missing field at its zero value rather than failing.
    """Test a missing field decodes to the zero value."""
    entry = unmarshal_entry(b'{"auth_type":"openai"}')
    assert entry.auth_type == "openai"
    assert entry.api_key_cipher == b""
    assert entry.dek_version == 0
    assert entry.mod_revision == 0
    assert entry.created_at == ZERO_TIMESTAMP


def test_a_null_field_decodes_to_the_zero_value() -> None:
    """Test a null field decodes to the zero value.

    Go marshals a nil ``[]byte`` as ``null``; it means "no payload".
    """
    entry = unmarshal_entry(b'{"auth_type":"openai","api_key_cipher":null}')
    assert entry.api_key_cipher == b""


# -- the generic record ----------------------------------------------------


def test_the_record_round_trips() -> None:
    """Test the record round trips."""
    record = RecordEntry(
        data=b"\x00\xffpayload",
        schema_version=3,
        dek_version=2,
        mod_revision=99,
        created_at=Timestamp("2026-01-01T00:00:00Z"),
        updated_at=Timestamp("2026-01-02T03:04:05.5Z"),
    )
    assert unmarshal_record(marshal_record(record)) == record


def test_the_record_fields_are_the_frozen_ones() -> None:
    """Test the record fields are the frozen ones."""
    parsed = json.loads(marshal_record(RecordEntry()))
    assert list(parsed) == [
        "data",
        "schema_version",
        "dek_version",
        "mod_revision",
        "created_at",
        "updated_at",
    ]


def test_the_record_payload_is_base64_on_the_wire() -> None:
    """Test the record payload is base64 on the wire."""
    record = RecordEntry(data=b"\x00\xff")
    parsed = json.loads(marshal_record(record))
    assert parsed["data"] == base64.b64encode(b"\x00\xff").decode()
