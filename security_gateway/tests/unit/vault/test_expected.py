"""Expected-field guards on the vault's writes."""

from __future__ import annotations

import pytest
from security_gateway.vault import (
    Config,
    ConflictError,
    FieldDef,
    InvalidRecordError,
    NotFoundError,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)
from security_gateway.vault.rotate import rotate_dek


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef("endpoint", Type.STRING),
            FieldDef("api_key", Type.STRING, encrypted=True),
        ],
    )


def _record(endpoint: str = "https://api.test", key: str = "old") -> Record:
    return Record(
        id="cred-1",
        fields={
            "endpoint": Value.new_string(endpoint),
            "api_key": Value.new_string(key),
        },
    )


@pytest.fixture
def vault(tmp_path):
    store = Vault.open(Config(data_dir=str(tmp_path)), _schema())
    try:
        yield store
    finally:
        store.close()


def _expected(record: Record, *names: str) -> dict[str, Value]:
    return {name: record.fields[name] for name in names}


def test_a_matching_expected_field_allows_the_write(vault):
    vault.put(_record())
    old = vault.get("cred-1")

    vault.put(_record(key="new"), expected={"api_key": old.get("api_key")})

    assert vault.get("cred-1").get_string("api_key") == "new"


def test_a_mismatched_expected_field_refuses_the_write(vault):
    vault.put(_record())

    with pytest.raises(ConflictError, match="api_key"):
        vault.put(
            _record(key="new"),
            expected={"api_key": Value.new_string("not-the-old-value")},
        )

    assert vault.get("cred-1").get_string("api_key") == "old"


def test_expected_fields_are_checked_after_a_key_rotation(vault):
    vault.put(_record())
    old = vault.get("cred-1")
    rotate_dek(vault)

    vault.put(_record(key="new"), expected={"api_key": old.get("api_key")})

    assert vault.get("cred-1").get_string("api_key") == "new"


def test_passing_every_field_is_a_record_level_guard(vault):
    vault.put(_record())
    old = vault.get("cred-1")
    vault.put(_record(endpoint="https://changed.test"))

    with pytest.raises(ConflictError, match="endpoint"):
        vault.put(_record(key="new"), expected=_expected(old, "endpoint", "api_key"))


def test_a_write_with_expected_on_a_missing_record_is_not_found(vault):
    with pytest.raises(NotFoundError):
        vault.put(
            _record(),
            expected={"api_key": Value.new_string("old")},
        )


def test_delete_honours_expected_fields(vault):
    vault.put(_record())
    old = vault.get("cred-1")

    with pytest.raises(ConflictError, match="api_key"):
        vault.delete("cred-1", expected={"api_key": Value.new_string("nope")})
    assert vault.get("cred-1").get_string("api_key") == "old"

    vault.delete("cred-1", expected={"api_key": old.get("api_key")})
    with pytest.raises(NotFoundError):
        vault.get("cred-1")


def test_an_unknown_expected_field_is_refused(vault):
    with pytest.raises(InvalidRecordError, match="not declared"):
        vault.put(_record(), expected={"missing": Value.new_string("x")})


def test_an_expected_field_with_the_wrong_type_is_refused(vault):
    with pytest.raises(InvalidRecordError, match="type"):
        vault.put(_record(), expected={"api_key": Value.new_int64(1)})


def test_a_stale_cache_does_not_let_an_expected_write_through(tmp_path):
    first = Vault.open(
        Config(data_dir=str(tmp_path), cache_max_entries=10),
        _schema(),
        _allow_duplicate=True,
    )
    second = Vault.open(
        Config(data_dir=str(tmp_path)), _schema(), _allow_duplicate=True
    )
    try:
        first.put(_record())
        old = first.get("cred-1")
        second.put(_record(key="changed-elsewhere"))

        with pytest.raises(ConflictError, match="api_key"):
            first.put(_record(key="new"), expected={"api_key": old.get("api_key")})
        assert second.get("cred-1").get_string("api_key") == "changed-elsewhere"
    finally:
        first.close()
        second.close()
