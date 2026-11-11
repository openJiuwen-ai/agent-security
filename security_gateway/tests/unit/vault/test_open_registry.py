"""One process holds at most one Vault per store or etcd namespace."""

from __future__ import annotations

import pytest
from security_gateway.vault import Config, InvalidError, Vault
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.vault import _release_registry, _reserve_registry

from .conftest import make_test_schema


def test_opening_the_same_data_dir_twice_in_one_process_fails(vault, data_dir, schema):
    with pytest.raises(InvalidError, match="already open in this process"):
        Vault.open(Config(data_dir=data_dir), schema)


def test_a_closed_store_can_be_opened_again(tmp_path):
    schema = make_test_schema()
    first = Vault.open(Config(data_dir=str(tmp_path)), schema)
    first.close()

    second = Vault.open(Config(data_dir=str(tmp_path)), schema)
    second.close()


def test_the_same_namespace_with_a_different_data_dir_fails(tmp_path):
    schema = make_test_schema()
    etcd = EtcdConfig(
        endpoints=("http://127.0.0.1:2379",), namespace="fleet", node_id="node-a"
    )
    first = Config(data_dir=str(tmp_path / "a"), etcd=etcd)
    key = _reserve_registry(str(tmp_path / "a" / "vault.db"), first.data_dir, first)
    try:
        with pytest.raises(InvalidError, match="etcd namespace"):
            Vault.open(
                Config(data_dir=str(tmp_path / "b"), etcd=etcd),
                schema,
            )
    finally:
        _release_registry(key)


def test_the_same_data_dir_with_a_different_namespace_fails(vault):
    etcd = EtcdConfig(
        endpoints=("http://127.0.0.1:2379",), namespace="other", node_id="node-a"
    )
    with pytest.raises(InvalidError, match="already open in this process"):
        Vault.open(
            Config(
                data_dir=vault.secrets_dir.rsplit("/", 1)[0],
                etcd=etcd,
            ),
            vault.schema,
        )


def test_the_same_data_dir_with_a_different_db_path_fails(
    vault, data_dir, schema, tmp_path
):
    with pytest.raises(InvalidError, match="already open in this process"):
        Vault.open(
            Config(data_dir=data_dir, db_path=str(tmp_path / "other.db")),
            schema,
        )


def test_etcd_without_a_node_id_is_refused(tmp_path):
    etcd = EtcdConfig(endpoints=("http://127.0.0.1:2379",))
    with pytest.raises(InvalidError, match="node_id"):
        Vault.open(
            Config(data_dir=str(tmp_path), etcd=etcd),
            make_test_schema(),
        )
