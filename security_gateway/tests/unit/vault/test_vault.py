"""The vault's behaviour.

The Go counterpart is ``tests/unit/vault/vault_test.go``.
"""

from __future__ import annotations

import os
import shutil
import stat

import pytest
from security_gateway.vault import (
    Config,
    FieldDef,
    InvalidError,
    InvalidRecordError,
    KeyMismatchError,
    NotFoundError,
    Record,
    Schema,
    SchemaMismatchError,
    Type,
    UndecryptableError,
    Value,
    Vault,
)

from .conftest import (
    call_rotate_dek,
    make_test_schema,
    put_record,
    read_raw_data,
    write_raw_data,
)


def test_open_creates_key_material(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        s1 = tmp_path / "secrets" / "s1.bin.1"
        assert s1.exists()
        assert s1.stat().st_size == 32
        assert stat.S_IMODE(s1.stat().st_mode) == 0o600
    finally:
        vault.close()


def test_put_get_round_trip(vault):
    vault.put(
        Record(
            id="cred-1",
            fields={
                "endpoint": Value.new_string("https://api.example.com/v1"),
                "api_key": Value.new_string("stored-value"),
            },
        )
    )

    got = vault.get("cred-1")
    assert got.get_string("endpoint") == "https://api.example.com/v1"
    assert got.get_string("api_key") == "stored-value"


def test_the_encrypted_field_is_not_stored_in_the_clear(tmp_path):
    """The encrypted field never appears in plaintext on disk."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        vault.put(
            Record(
                id="cred-1",
                fields={
                    "endpoint": Value.new_string("https://api.example.com/v1"),
                    "api_key": Value.new_string("stored-value"),
                },
            )
        )
        data = read_raw_data(str(tmp_path / "vault.db"), "cred-1")
        assert b"stored-value" not in data
        assert b"https://api.example.com/v1" in data
    finally:
        vault.close()


def test_get_of_an_unknown_id_is_not_found(vault):
    with pytest.raises(NotFoundError):
        vault.get("nope")


def test_delete_record(vault):
    vault.put(
        Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
    )
    vault.delete("cred-1")
    with pytest.raises(NotFoundError):
        vault.get("cred-1")
    with pytest.raises(NotFoundError):
        vault.delete("cred-1")


def test_put_rejects_a_field_outside_the_schema(vault):
    record = Record(
        id="cred-1",
        fields={
            "api_key": Value.new_string("stored-value"),
            "not_in_schema": Value.new_string("x"),
        },
    )
    with pytest.raises(InvalidRecordError):
        vault.put(record)


def test_put_rejects_the_wrong_field_type(vault):
    record = Record(
        id="cred-1", fields={"api_key": Value.new_bytes(b"stored-value")}
    )
    with pytest.raises(InvalidRecordError):
        vault.put(record)


def test_open_refuses_a_schema_older_than_the_store(tmp_path):
    newer = make_test_schema()
    newer.version = 2
    vault = Vault.open(Config(data_dir=str(tmp_path)), newer)
    vault.close()

    # The vault's data was written under a newer schema than the code
    # declares. Reading it with the older schema would misread records.
    with pytest.raises(SchemaMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())


def test_open_refuses_a_schema_change_without_a_version_bump(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()

    changed = make_test_schema()
    changed.fields[1].type = Type.BYTES
    with pytest.raises(SchemaMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), changed)


def test_open_accepts_an_additive_schema_change(tmp_path):
    """An additive schema change opens with a higher version."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.put(
        Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
    )
    vault.close()

    extended = make_test_schema()
    extended.version = 2
    extended.fields.append(FieldDef(name="region", type=Type.STRING))

    vault2 = Vault.open(Config(data_dir=str(tmp_path)), extended)
    try:
        got = vault2.get("cred-1")
        assert got.get_string("api_key") == "stored-value"
        # A record written under the old schema does not have the new field.
        assert got.get("region") is None
    finally:
        vault2.close()


def test_open_refuses_a_non_additive_schema_change(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()

    changed = make_test_schema()
    changed.version = 2
    changed.fields[1].type = Type.BYTES
    with pytest.raises(SchemaMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), changed)


def test_open_refuses_a_removed_field(tmp_path):
    """A removal leaves the old records unreadable."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()

    changed = make_test_schema()
    changed.version = 2
    changed.fields = [FieldDef(name="endpoint", type=Type.STRING)]
    with pytest.raises(SchemaMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), changed)


def test_open_refuses_a_changed_encryption_state(tmp_path):
    """Turning a secret into a plain field would serve it in the clear."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()

    changed = make_test_schema()
    changed.version = 2
    changed.fields[1].encrypted = False
    with pytest.raises(SchemaMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), changed)


def test_a_rotation_keeps_the_records_readable(tmp_path):
    """A rotation leaves every record readable."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        for record_id in ["cred-1", "cred-2", "cred-3"]:
            put_record(vault, record_id)

        before = read_raw_data(str(tmp_path / "vault.db"), "cred-1")

        call_rotate_dek(vault)

        for record_id in ["cred-1", "cred-2", "cred-3"]:
            got = vault.get(record_id)
            # The value is the one that was written: a rotation changes
            # the key the record is sealed under, not what it says.
            assert got.get_string("api_key") == "value-for-" + record_id

        after = read_raw_data(str(tmp_path / "vault.db"), "cred-1")
        assert before != after

        status = vault.status()
        assert status.dek_version == 2
        assert status.straggler_count == 0
    finally:
        vault.close()


def test_a_rotation_is_refused_while_one_is_in_progress(tmp_path):
    """A rotation is refused while another rotation is in progress."""
    import sqlite3

    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        conn = sqlite3.connect(
            str(tmp_path / "vault.db"), isolation_level=None, timeout=5.0
        )
        try:
            conn.execute("UPDATE vault_key_metadata SET pending_dek_version = 99")
        finally:
            conn.close()

        from security_gateway.vault import RotationInProgressError

        with pytest.raises(RotationInProgressError):
            call_rotate_dek(vault)
    finally:
        vault.close()


def test_get_of_a_corrupted_record_is_undecryptable_not_not_found(tmp_path):
    """A record that exists but cannot be opened is not an absent record.

    Reporting it as absent would let a caller cache a negative answer for a
    live secret.
    """
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        vault.put(
            Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
        )
        db_path = str(tmp_path / "vault.db")
        data = bytearray(read_raw_data(db_path, "cred-1"))
        # The encrypted field is written last, so this lands inside its
        # authentication tag.
        data[-1] ^= 0xFF
        write_raw_data(db_path, "cred-1", bytes(data))

        with pytest.raises(UndecryptableError) as excinfo:
            vault.get("cred-1")
        assert not isinstance(excinfo.value, NotFoundError)
    finally:
        vault.close()


def test_status_reports_the_store_state(vault):
    vault.put(
        Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
    )

    status = vault.status()
    assert status.schema_version == 1
    assert status.record_count == 1
    assert status.dek_version == 1
    assert status.crypto_mode == "aes"
    assert len(status.schema_hash) == 64


def test_open_fails_when_the_key_material_is_missing(tmp_path):
    """Opening fails when the key material file is missing."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.put(
        Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
    )
    vault.close()

    # A database without the shard that completes the key is a vault whose
    # key material does not match, which is a different thing from corrupt
    # data.
    other = tmp_path / "other"
    other.mkdir()
    shutil.copyfile(tmp_path / "vault.db", other / "vault.db")

    with pytest.raises(KeyMismatchError):
        Vault.open(Config(data_dir=str(other)), make_test_schema())


def test_open_refuses_a_store_with_records_but_no_key_metadata(tmp_path):
    """Opening refuses records that have no key metadata."""
    import sqlite3

    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.put(
        Record(id="cred-1", fields={"api_key": Value.new_string("stored-value")})
    )
    vault.close()

    conn = sqlite3.connect(
        str(tmp_path / "vault.db"), isolation_level=None, timeout=5.0
    )
    try:
        conn.execute("DELETE FROM vault_key_metadata")
    finally:
        conn.close()

    with pytest.raises(KeyMismatchError):
        Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())


def test_open_refuses_a_data_directory_others_can_write_to(tmp_path):
    os.chmod(tmp_path, 0o777)
    with pytest.raises(InvalidError) as excinfo:
        Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    assert "writable by others" in str(excinfo.value)


def test_open_accepts_a_sticky_data_directory(tmp_path):
    """The sticky bit stops anyone from removing what belongs to somebody
    else, which is what makes a shared directory safe."""
    os.chmod(tmp_path, 0o1777)
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()


def test_the_database_file_is_not_world_readable(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        vault.put(
            Record(
                id="id-1",
                fields={"endpoint": Value.new_string("https://example.com")},
            )
        )
        mode = stat.S_IMODE(os.stat(tmp_path / "vault.db").st_mode)
        assert mode & 0o077 == 0
    finally:
        vault.close()


def test_the_store_holds_whatever_shape_it_is_given(tmp_path):
    """Nothing in the vault is quietly built around a particular set of
    field names."""
    schema = Schema(
        version=1,
        fields=[
            FieldDef(name="label", type=Type.STRING),
            FieldDef(name="secret", type=Type.BYTES, encrypted=True),
            FieldDef(name="count", type=Type.INT64),
            FieldDef(name="on", type=Type.BOOL),
        ],
    )
    vault = Vault.open(Config(data_dir=str(tmp_path)), schema)
    try:
        vault.put(
            Record(
                id="thing/one",
                fields={
                    "label": Value.new_string("a-label"),
                    "secret": Value.new_bytes(b"abc"),
                    "count": Value.new_int64(7),
                    "on": Value.new_bool(True),
                },
            )
        )
        got = vault.get("thing/one")
        assert got.get_string("label") == "a-label"
        assert got.get_bytes("secret") == b"abc"
        assert got.get_int64("count") == 7
        assert got.get_bool("on") is True
    finally:
        vault.close()


def test_a_record_may_omit_a_field(tmp_path):
    """A field that is absent is not the same as a field that is empty."""
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    try:
        vault.put(
            Record(id="cred-1", fields={"endpoint": Value.new_string("https://x")})
        )
        got = vault.get("cred-1")
        assert got.get("api_key") is None
        assert got.get_string("endpoint") == "https://x"
    finally:
        vault.close()


def test_close_is_idempotent(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), make_test_schema())
    vault.close()
    vault.close()
