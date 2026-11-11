"""The vault's read cache: hits, expiry, eviction and invalidation."""

from __future__ import annotations

import pytest
from security_gateway.vault import Config, FieldDef, Schema, Type, Vault
from security_gateway.vault.cache import RecordCache
from security_gateway.vault.record import Record, Value


def _record(record_id: str, value: str = "secret") -> Record:
    return Record(
        id=record_id,
        fields={"value": Value.new_string(value)},
    )


def test_a_hit_returns_a_copy() -> None:
    cache = RecordCache(2)
    cache.put("a", _record("a"))

    first = cache.get("a")
    assert first is not None
    first.fields["value"] = Value.new_string("changed")
    first.id = "other"

    second = cache.get("a")
    assert second is not None
    assert second.id == "a"
    assert second.get_string("value") == "secret"
    assert cache.stats() == (2, 0)


def test_an_entry_expires() -> None:
    now = [100.0]
    cache = RecordCache(2, ttl=10.0, clock=lambda: now[0])
    cache.put("a", _record("a"))

    now[0] = 111.0
    assert cache.get("a") is None
    assert cache.stats() == (0, 1)


def test_the_least_recently_used_entry_is_evicted() -> None:
    cache = RecordCache(2)
    cache.put("a", _record("a"))
    cache.put("b", _record("b"))
    assert cache.get("a") is not None
    cache.put("c", _record("c"))

    assert cache.get("b") is None
    assert cache.get("a") is not None
    assert cache.get("c") is not None


def test_delete_and_clear() -> None:
    cache = RecordCache(2)
    cache.put("a", _record("a"))
    cache.put("b", _record("b"))
    cache.delete("a")
    assert cache.get("a") is None
    assert len(cache) == 1
    cache.clear()
    assert len(cache) == 0


def _vault(tmp_path, cache_max_entries: int = 10) -> Vault:
    return Vault.open(
        Config(
            data_dir=str(tmp_path),
            cache_max_entries=cache_max_entries,
            cache_ttl=60.0,
        ),
        Schema(version=1, fields=[FieldDef("value", Type.STRING, encrypted=True)]),
    )


def test_a_vault_get_does_not_query_the_store_twice(tmp_path, monkeypatch) -> None:
    vault = _vault(tmp_path)
    try:
        vault.put(_record("a"))
        calls = [0]
        from security_gateway.vault import vault as vault_module

        original = vault_module.get_record

        def counting(db, record_id):
            calls[0] += 1
            return original(db, record_id)

        monkeypatch.setattr(vault_module, "get_record", counting)

        assert vault.get("a").get_string("value") == "secret"
        assert vault.get("a").get_string("value") == "secret"
        assert calls[0] == 0  # the write populated the cache
    finally:
        vault.close()


def test_delete_evicts_the_entry(tmp_path) -> None:
    vault = _vault(tmp_path)
    try:
        vault.put(_record("a"))
        assert vault.get("a").get_string("value") == "secret"
        vault.delete("a")
        from security_gateway.vault.errors import NotFoundError

        with pytest.raises(NotFoundError):
            vault.get("a")
    finally:
        vault.close()


def test_put_replaces_the_cached_value(tmp_path) -> None:
    vault = _vault(tmp_path)
    try:
        vault.put(_record("a", "one"))
        assert vault.get("a").get_string("value") == "one"
        vault.put(_record("a", "two"))
        assert vault.get("a").get_string("value") == "two"
    finally:
        vault.close()


def test_the_cache_is_off_by_default(tmp_path) -> None:
    vault = Vault.open(
        Config(data_dir=str(tmp_path)),
        Schema(version=1, fields=[FieldDef("value", Type.STRING, encrypted=True)]),
    )
    try:
        assert vault._cache is None
    finally:
        vault.close()
