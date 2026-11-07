"""Shared fixtures for the vault tests.

The Go counterpart is the helper functions at the top of
``tests/unit/vault/vault_test.go``.
"""

from __future__ import annotations

import sqlite3

import pytest
from security_gateway.vault import Config, FieldDef, Record, Schema, Type, Value, Vault
from security_gateway.vault.rotate import rotate_dek


def make_test_schema() -> Schema:
    """The schema the Go tests use."""
    return Schema(
        version=1,
        fields=[
            FieldDef(name="endpoint", type=Type.STRING),
            FieldDef(name="api_key", type=Type.STRING, encrypted=True),
        ],
    )


@pytest.fixture
def schema() -> Schema:
    """A fresh copy of the test schema."""
    return make_test_schema()


@pytest.fixture
def data_dir(tmp_path) -> str:
    """A private directory to hold a store."""
    return str(tmp_path)


@pytest.fixture
def vault(data_dir: str, schema: Schema):
    """An open store in a temporary directory."""
    opened = Vault.open(Config(data_dir=data_dir), schema)
    try:
        yield opened
    finally:
        opened.close()


def read_raw_data(db_path: str, record_id: str) -> bytes:
    """A record's stored bytes, straight out of the database."""
    conn = sqlite3.connect(db_path, isolation_level=None, timeout=5.0)
    try:
        row = conn.execute(
            "SELECT data FROM vault_record WHERE id = ?", (record_id,)
        ).fetchone()
    finally:
        conn.close()
    if row is None:
        raise AssertionError(f"the store holds no record {record_id!r}")
    return bytes(row[0])


def write_raw_data(db_path: str, record_id: str, data: bytes) -> None:
    """Overwrite a record's stored bytes."""
    conn = sqlite3.connect(db_path, isolation_level=None, timeout=5.0)
    try:
        conn.execute("UPDATE vault_record SET data = ? WHERE id = ?", (data, record_id))
    finally:
        conn.close()


def call_rotate_dek(vault: Vault) -> None:
    """Rotate the store's data encryption key."""
    rotate_dek(vault)


def put_record(vault: Vault, record_id: str) -> None:
    """Write a record with both fields set."""
    vault.put(
        Record(
            id=record_id,
            fields={
                "endpoint": Value.new_string("https://example.test"),
                "api_key": Value.new_string("value-for-" + record_id),
            },
        )
    )
