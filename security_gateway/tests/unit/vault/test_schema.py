"""The schema rules.

The Go counterpart is ``TestSchemaValidate``,
``TestSchemaHashIgnoresFieldOrder`` and
``TestSchemaCanonicalJSONRoundTrip`` in
``tests/unit/vault/vault_test.go``, plus the schema half of
``pkg/vault/schema.go``.
"""

from __future__ import annotations

import pytest
from security_gateway.vault import (
    FieldDef,
    InvalidSchemaError,
    Schema,
    Type,
    is_additive,
    parse_schema,
)

from .conftest import make_test_schema


@pytest.mark.parametrize(
    ("name", "candidate", "valid"),
    [
        ("valid", make_test_schema(), True),
        (
            "zero version",
            Schema(version=0, fields=make_test_schema().fields),
            False,
        ),
        ("no fields", Schema(version=1), False),
        (
            "empty name",
            Schema(version=1, fields=[FieldDef(name="", type=Type.STRING)]),
            False,
        ),
        (
            "bad name",
            Schema(version=1, fields=[FieldDef(name="a b", type=Type.STRING)]),
            False,
        ),
        (
            "duplicate name",
            Schema(
                version=1,
                fields=[
                    FieldDef(name="a", type=Type.STRING),
                    FieldDef(name="a", type=Type.STRING),
                ],
            ),
            False,
        ),
        (
            "bad type",
            Schema(version=1, fields=[FieldDef(name="a", type=Type.INVALID)]),
            False,
        ),
    ],
)
def test_schema_validate(name, candidate, valid):
    if valid:
        candidate.validate()
    else:
        with pytest.raises(InvalidSchemaError):
            candidate.validate()


def test_a_field_name_is_restricted_to_a_url_safe_subset():
    """A name outside the subset would make the container harder to inspect."""
    for good in ("a", "A1", "a.b", "a_b", "a-b", "x" * 128):
        Schema(version=1, fields=[FieldDef(name=good, type=Type.STRING)]).validate()
    for bad in ("a b", "a/b", "a:b", "a+b", "ä", "a\n", "x" * 129):
        with pytest.raises(InvalidSchemaError):
            Schema(version=1, fields=[FieldDef(name=bad, type=Type.STRING)]).validate()


def test_schema_hash_ignores_field_order():
    """The schema hash is stable under field reordering."""
    a = Schema(
        version=1,
        fields=[
            FieldDef(name="a", type=Type.STRING),
            FieldDef(name="b", type=Type.STRING, encrypted=True),
        ],
    )
    b = Schema(
        version=1,
        fields=[
            FieldDef(name="b", type=Type.STRING, encrypted=True),
            FieldDef(name="a", type=Type.STRING),
        ],
    )

    assert a.hash() == b.hash()

    c = Schema(
        version=1,
        fields=[
            FieldDef(name="b", type=Type.STRING, encrypted=True),
            FieldDef(name="a", type=Type.BYTES),
        ],
    )
    assert a.hash() != c.hash()


def test_schema_canonical_json_round_trip():
    original = make_test_schema()
    canonical = original.canonical_json()
    parsed = parse_schema(canonical)
    assert original.hash() == parsed.hash()


def test_the_canonical_json_is_the_persisted_shape():
    """The bytes are what the store keeps, so they are pinned down here."""
    canonical = make_test_schema().canonical_json()
    assert canonical == (
        b'{"version":1,"fields":['
        b'{"name":"api_key","type":"string","encrypted":true},'
        b'{"name":"endpoint","type":"string","encrypted":false}]}'
    )


def test_the_type_names_are_the_persisted_ones():
    """The type name goes into the stored schema, so it must not change."""
    assert str(Type.STRING) == "string"
    assert str(Type.BYTES) == "bytes"
    assert str(Type.INT64) == "int64"
    assert str(Type.BOOL) == "bool"
    assert str(Type.INVALID) == "invalid"


def test_a_type_code_that_is_not_defined_is_refused():
    """The Go type is a uint8, so any byte is a type there.

    Python refuses the code instead: the value would have no name, and the
    name is what goes into the persisted schema.
    """
    with pytest.raises(ValueError):
        Type(99)


def test_parse_schema_rejects_an_unknown_type_name():
    with pytest.raises(InvalidSchemaError):
        parse_schema(b'{"version":1,"fields":[{"name":"a","type":"widget"}]}')


def test_parse_schema_rejects_bytes_that_are_not_json():
    with pytest.raises(InvalidSchemaError):
        parse_schema(b"not json at all")


def test_is_additive():
    """Additive schema changes are recognised."""
    old = Schema(
        version=1,
        fields=[
            FieldDef(name="a", type=Type.STRING),
            FieldDef(name="b", type=Type.STRING, encrypted=True),
        ],
    )

    # A new field is additive: the old records are still readable.
    assert is_additive(
        old,
        Schema(
            version=2,
            fields=[
                FieldDef(name="a", type=Type.STRING),
                FieldDef(name="b", type=Type.STRING, encrypted=True),
                FieldDef(name="c", type=Type.STRING),
            ],
        ),
    )

    # A changed type is not.
    assert not is_additive(
        old,
        Schema(
            version=2,
            fields=[
                FieldDef(name="a", type=Type.BYTES),
                FieldDef(name="b", type=Type.STRING, encrypted=True),
            ],
        ),
    )

    # A changed encryption state is not.
    assert not is_additive(
        old,
        Schema(
            version=2,
            fields=[
                FieldDef(name="a", type=Type.STRING),
                FieldDef(name="b", type=Type.STRING, encrypted=False),
            ],
        ),
    )

    # A removal is not.
    assert not is_additive(
        old,
        Schema(version=2, fields=[FieldDef(name="a", type=Type.STRING)]),
    )

    # A rename is not.
    assert not is_additive(
        old,
        Schema(
            version=2,
            fields=[
                FieldDef(name="a", type=Type.STRING),
                FieldDef(name="c", type=Type.STRING, encrypted=True),
            ],
        ),
    )
