"""The SQLite layer.

The Go counterpart is ``pkg/vault/store.go`` and the CRUD helpers it
holds. The DDL is part of the contract with the Go implementation, so the
tables and their columns are checked here.
"""

from __future__ import annotations

import pytest
from security_gateway.vault import (
    KEY_META_DDL,
    RECORD_DDL,
    SCHEMA_DDL,
    SYNC_STATE_DDL,
    bootstrap_schema,
    count_records,
    count_stragglers,
    delete_record,
    get_record,
    insert_schema_entry,
    list_records,
    open_db,
    prefix_upper_bound,
    put_record,
    read_schema_entries,
    select_stragglers,
    update_record_cipher,
)
from security_gateway.vault.store import RecordRow, SchemaEntry, table_columns


def test_the_four_tables_are_created(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        assert table_columns(db, "vault_record") == {
            "id",
            "schema_version",
            "data",
            "dek_version",
            "row_version",
            "source_revision",
            "created_at",
            "updated_at",
        }
        assert table_columns(db, "vault_schema") == {
            "version",
            "hash",
            "definition",
            "created_at",
        }
        assert table_columns(db, "vault_key_metadata") == {
            "id",
            "active_dek_version",
            "pending_dek_version",
            "crypto_mode",
            "active_config_shard",
            "pending_config_shard",
            "file_shard_version",
            "file_shard_rotated_at",
            "last_rotate_at",
            "rotation_period",
            "wrapped_dek",
            "pending_wrapped_dek",
            "superseded_dek_version",
            "superseded_wrapped_dek",
            "updated_at",
        }
        assert table_columns(db, "vault_sync_state") == {
            "id",
            "last_applied_rev",
            "updated_at",
        }
    finally:
        db.close()


def test_the_bootstrap_is_idempotent(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        bootstrap_schema(db)
        assert count_records(db) == 0
    finally:
        db.close()


def test_the_ddl_is_the_go_ddl():
    """The statements are the Go ones, so a Go build reads what we write."""
    assert "CREATE TABLE IF NOT EXISTS vault_record" in RECORD_DDL
    assert "source_revision INTEGER NOT NULL DEFAULT 0" in RECORD_DDL
    assert "CREATE TABLE IF NOT EXISTS vault_schema" in SCHEMA_DDL
    assert "CREATE TABLE IF NOT EXISTS vault_key_metadata" in KEY_META_DDL
    assert "CHECK (id = 1)" in KEY_META_DDL
    assert "CREATE TABLE IF NOT EXISTS vault_sync_state" in SYNC_STATE_DDL


def test_the_database_file_is_not_world_readable(tmp_path):
    import os
    import stat

    db_path = str(tmp_path / "vault.db")
    open_db(db_path).close()
    mode = stat.S_IMODE(os.stat(db_path).st_mode)
    assert mode & 0o077 == 0


@pytest.mark.parametrize(
    ("prefix", "expected"),
    [
        ("a", b"b"),
        ("a/", b"a0"),
        (b"a\xff", b"b"),
        (b"a\xffb", b"a\xffc"),
    ],
)
def test_prefix_upper_bound(prefix, expected):
    upper, ok = prefix_upper_bound(prefix)
    assert ok is True
    assert upper == expected


def test_an_empty_prefix_has_no_upper_bound():
    """Nothing follows the empty prefix, so there is nothing to bound it."""
    upper, ok = prefix_upper_bound("")
    assert ok is False
    assert upper == b""


def test_a_prefix_of_only_ff_bytes_has_no_upper_bound():
    """Nothing sorts above it, so the lower bound is all there is."""
    upper, ok = prefix_upper_bound(b"\xff")
    assert ok is False
    assert upper == b""
    upper, ok = prefix_upper_bound(b"\xff\xff")
    assert ok is False


def test_the_crud_round_trip(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        assert get_record(db, "nope") is None

        put_record(
            db,
            RecordRow(
                id="a",
                schema_version=1,
                data=b"payload",
                dek_version=1,
            ),
        )
        row = get_record(db, "a")
        assert row is not None
        assert row.data == b"payload"
        assert row.dek_version == 1
        assert row.row_version == 1
        assert row.created_at > 0

        # A second write replaces the row and bumps its version.
        put_record(
            db,
            RecordRow(
                id="a",
                schema_version=1,
                data=b"payload2",
                dek_version=2,
            ),
        )
        row = get_record(db, "a")
        assert row.data == b"payload2"
        assert row.dek_version == 2
        assert row.row_version == 2

        assert count_records(db) == 1
        assert delete_record(db, "a") is True
        assert delete_record(db, "a") is False
        assert get_record(db, "a") is None
    finally:
        db.close()


def test_the_straggler_queries_look_at_the_dek_version(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        for i, dek in enumerate([1, 1, 2]):
            put_record(
                db,
                RecordRow(
                    id=f"r{i}",
                    schema_version=1,
                    data=b"x",
                    dek_version=dek,
                ),
            )
        assert count_stragglers(db, 2) == 2
        rows = select_stragglers(db, 2, 10)
        assert [r.id for r in rows] == ["r0", "r1"]
        assert len(select_stragglers(db, 2, 1)) == 1
    finally:
        db.close()


def test_the_row_version_guard_protects_a_concurrent_write(tmp_path):
    """A rotation must not overwrite a write that landed after it read."""
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        put_record(
            db,
            RecordRow(
                id="a", schema_version=1, data=b"old", dek_version=1, row_version=1
            ),
        )
        assert update_record_cipher(db, "a", 1, b"new", 2) is True
        assert get_record(db, "a").data == b"new"
        # The stale version no longer matches, so the update is skipped.
        assert update_record_cipher(db, "a", 1, b"newer", 2) is False
    finally:
        db.close()


def test_the_schema_entries_are_read_back_in_version_order(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        insert_schema_entry(db, SchemaEntry(version=2, hash=b"h2", definition="{}"))
        insert_schema_entry(db, SchemaEntry(version=1, hash=b"h1", definition="{}"))
        entries = read_schema_entries(db)
        assert [e.version for e in entries] == [1, 2]
    finally:
        db.close()


def test_the_prefix_scan_brackets_exactly_the_prefix_set(tmp_path):
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        for record_id in ["a", "ab", "abc", "b", "ba"]:
            put_record(
                db,
                RecordRow(id=record_id, schema_version=1, data=b"x", dek_version=1),
            )
        assert [r.id for r in list_records(db, "a")] == ["a", "ab", "abc"]
        assert [r.id for r in list_records(db, "b")] == ["b", "ba"]
        assert [r.id for r in list_records(db, "")] == [
            "a",
            "ab",
            "abc",
            "b",
            "ba",
        ]
        assert list_records(db, "zzz") == []
    finally:
        db.close()


def test_the_prefix_scan_works_with_a_non_ascii_prefix(tmp_path):
    """The upper bound is a byte sequence, not a character sequence."""
    db = open_db(str(tmp_path / "vault.db"))
    try:
        bootstrap_schema(db)
        for record_id in ["é", "éx", "ê", "f"]:
            put_record(
                db,
                RecordRow(id=record_id, schema_version=1, data=b"x", dek_version=1),
            )
        assert [r.id for r in list_records(db, "é")] == ["é", "éx"]
    finally:
        db.close()
