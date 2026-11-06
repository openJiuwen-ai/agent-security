"""Listing records.

The Go counterpart is ``tests/unit/vault/list_test.go``.
"""

from __future__ import annotations


from .conftest import put_record

from security_gateway.vault import Config, FieldDef, Record, Schema, Type, Value, Vault


def test_list_returns_only_the_records_under_the_prefix(vault):
    for id in ["a/one", "a/two", "b/one"]:
        put_record(vault, id)

    entries = vault.list("a/")
    assert len(entries) == 2
    for entry in entries:
        assert entry.id in ("a/one", "a/two")


def test_list_with_an_empty_prefix_returns_everything(vault):
    for id in ["a", "ab", "b"]:
        put_record(vault, id)

    entries = vault.list("")
    assert len(entries) == 3


def test_list_prefix_boundary(vault):
    """The prefix scan brackets the range with the prefix and the prefix
    with its last byte incremented.

    The ids here are chosen to sit on both sides of that boundary: "ab" is
    under the prefix "a", and "b" is the first id that is not.
    """
    for id in ["a", "ab", "abc", "b", "ba"]:
        put_record(vault, id)

    entries = vault.list("a")
    assert [entry.id for entry in entries] == ["a", "ab", "abc"]


def test_list_carries_only_the_fields_that_are_not_encrypted(vault):
    put_record(vault, "a/one")

    entries = vault.list("a/")
    assert len(entries) == 1
    assert "api_key" not in entries[0].fields
    endpoint = entries[0].fields.get("endpoint")
    assert endpoint is not None
    assert endpoint.as_string() == "https://example.test"


def test_list_of_an_empty_store_is_empty(vault):
    assert vault.list("anything") == []


def test_the_vault_holds_whatever_shape_it_is_given(tmp_path):
    """The vault stores whatever shape the caller declares.

    This test uses a shape that has nothing to do with the one the other
    tests use, to make sure nothing in the vault is quietly built around a
    particular set of field names.
    """
    schema = Schema(
        version=1,
        fields=[
            FieldDef(name="label", type=Type.STRING),
            FieldDef(name="secret", type=Type.BYTES, encrypted=True),
            FieldDef(name="count", type=Type.INT64),
            FieldDef(name="on", type=Type.BOOL),
        ],
    )
    store = Vault.open(Config(data_dir=str(tmp_path)), schema)
    try:
        store.put(
            Record(
                id="thing/one",
                fields={
                    "label": Value.new_string("a-label"),
                    "secret": Value.new_bytes(b"sk-abc"),
                    "count": Value.new_int64(7),
                    "on": Value.new_bool(True),
                },
            )
        )

        entries = store.list("thing/")
        assert len(entries) == 1
        assert "secret" not in entries[0].fields
        assert "label" in entries[0].fields
    finally:
        store.close()
