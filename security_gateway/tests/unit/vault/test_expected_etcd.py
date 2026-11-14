"""Expected-field guards through an etcd authority."""

from __future__ import annotations

import pytest
from tests.unit.vault.etcdstore.cluster_fakes import FakeKV

from security_gateway.vault import (
    Config,
    ConflictError,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)
from security_gateway.vault.etcd import EtcdAuthority
from security_gateway.vault.etcdstore.cluster import generation_key
from security_gateway.vault.etcdstore.store import Store


NS = "expected"


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef("endpoint", Type.STRING),
            FieldDef("api_key", Type.STRING, encrypted=True),
        ],
    )


def _record(key: str = "old") -> Record:
    return Record(
        id="cred-1",
        fields={
            "endpoint": Value.new_string("https://api.test"),
            "api_key": Value.new_string(key),
        },
    )


@pytest.fixture
def vault(tmp_path):
    store = Vault.open(Config(data_dir=str(tmp_path)), _schema())
    authority = EtcdAuthority.from_store(
        Store(kv=FakeKV(), ns=NS, generation_key=generation_key(NS))
    )
    store.authority = authority
    try:
        yield store
    finally:
        store.close()


def test_etcd_expected_field_allows_the_write(vault):
    vault.put(_record())
    old = vault.get("cred-1")

    vault.put(_record("new"), expected={"api_key": old.get("api_key")})

    assert vault.get("cred-1").get_string("api_key") == "new"
    stored = vault.authority.store.get_record("cred-1")
    assert stored is not None


def test_etcd_expected_field_refuses_the_write(vault):
    vault.put(_record())
    before = vault.authority.store.get_record("cred-1").data

    with pytest.raises(ConflictError, match="api_key"):
        vault.put(
            _record("new"),
            expected={"api_key": Value.new_string("wrong")},
        )

    assert vault.authority.store.get_record("cred-1").data == before
    assert vault.get("cred-1").get_string("api_key") == "old"


def test_etcd_delete_honours_expected_fields(vault):
    vault.put(_record())
    old = vault.get("cred-1")

    with pytest.raises(ConflictError, match="api_key"):
        vault.delete("cred-1", expected={"api_key": Value.new_string("wrong")})
    assert vault.authority.store.get_record("cred-1") is not None

    vault.delete("cred-1", expected={"api_key": old.get("api_key")})
    with pytest.raises(Exception):
        vault.authority.store.get_record("cred-1")
