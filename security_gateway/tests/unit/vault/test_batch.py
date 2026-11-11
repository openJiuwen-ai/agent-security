"""Batch reads and deletes."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from security_gateway.vault import (
    BatchDeleteResult,
    UndecryptableError,
    Value,
    batch_delete,
    batch_get,
)

from .conftest import put_record
from .test_undecryptable import _row_with_garbage_ciphertext


def test_batch_get_returns_found_records_in_input_order(vault):
    put_record(vault, "b")
    put_record(vault, "a")

    found = batch_get(vault, ["a", "missing", "b", "a"])

    assert list(found) == ["a", "b"]
    assert found["a"].get_string("api_key") == "secret-for-a"
    assert found["b"].get_string("api_key") == "secret-for-b"


def test_batch_get_of_an_empty_batch_is_empty(vault):
    assert batch_get(vault, []) == {}


def test_batch_delete_reports_deleted_and_missing_without_duplicates(vault):
    put_record(vault, "a")
    put_record(vault, "b")

    result = batch_delete(vault, ["a", "missing", "a", "b", "missing"])

    assert isinstance(result, BatchDeleteResult)
    assert result.deleted == ["a", "b"]
    assert result.missing == ["missing"]
    assert not result.ok
    assert vault.list("") == []


def test_batch_delete_of_known_ids_is_ok(vault):
    put_record(vault, "a")

    result = batch_delete(vault, ["a"])

    assert result.deleted == ["a"]
    assert result.missing == []
    assert result.ok


def test_batch_delete_keeps_the_value_of_the_records_it_leaves(vault):
    put_record(vault, "keep")
    put_record(vault, "drop")

    batch_delete(vault, ["drop", "missing"])

    kept = vault.get("keep")
    assert kept.get_string("api_key") == "secret-for-keep"
    assert kept.get("endpoint") is not None
    assert isinstance(kept.get("endpoint"), Value)


def test_batch_get_does_not_treat_an_unreadable_record_as_missing(vault):
    _row_with_garbage_ciphertext(vault, "cred-1")

    with pytest.raises(UndecryptableError):
        batch_get(vault, ["cred-1", "absent"])


def test_batch_get_uses_one_select_with_in(vault, monkeypatch):
    put_record(vault, "a")
    put_record(vault, "b")
    statements = []
    original = vault.db.query_all

    def spy(sql, params=()):
        statements.append((sql, params))
        return original(sql, params)

    monkeypatch.setattr(vault.db, "query_all", spy)

    batch_get(vault, ["a", "missing", "b"])

    selects = [sql for sql, _ in statements if "FROM vault_record" in sql]
    assert len(selects) == 1
    assert " IN (" in selects[0]


def test_batch_delete_uses_one_delete_with_in(vault, monkeypatch):
    put_record(vault, "a")
    put_record(vault, "b")
    statements = []
    original = vault.db.query_all

    def spy(sql, params=()):
        statements.append((sql, params))
        return original(sql, params)

    monkeypatch.setattr(vault.db, "query_all", spy)

    result = batch_delete(vault, ["a", "missing", "b"])

    deletes = [
        sql for sql, _ in statements if sql.startswith("DELETE FROM vault_record")
    ]
    assert len(deletes) == 1
    assert " IN (" in deletes[0]
    assert result.deleted == ["a", "b"]
    assert result.missing == ["missing"]


def test_batch_delete_delegates_one_transaction_in_etcd_mode():
    calls = []

    def delete_records_cas(ids):
        calls.append(list(ids))
        return ["a"], ["b"]

    vault = SimpleNamespace(
        authority=SimpleNamespace(
            store=SimpleNamespace(delete_records_cas=delete_records_cas)
        )
    )

    result = batch_delete(vault, ["a", "b", "a"])

    assert calls == [["a", "b"]]
    assert result.deleted == ["a"]
    assert result.missing == ["b"]
