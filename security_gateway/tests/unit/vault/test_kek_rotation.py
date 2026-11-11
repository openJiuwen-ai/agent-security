"""KEK rotation: S1 and S2 are rewrapped, records are not rewritten."""

from __future__ import annotations

import os

import pytest
from security_gateway.vault import (
    Config,
    KeyMismatchError,
    SHARD_SIZE,
    Vault,
    rotate_s1,
    rotate_s2,
)
from security_gateway.vault.keys import load_s1_from_file, read_key_meta, s1_path

from .conftest import put_record, read_raw_data


def _open(data_dir, schema):
    return Vault.open(Config(data_dir=data_dir), schema)


def test_rotate_s1_moves_the_file_shard_without_reencrypting_records(
    vault, data_dir, schema
):
    put_record(vault, "cred-1")
    before_meta = read_key_meta(vault.db)
    before_data = read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1")
    old_wrapped = before_meta.wrapped_dek

    rotate_s1(vault)

    after_meta = read_key_meta(vault.db)
    assert after_meta.file_shard_version == before_meta.file_shard_version + 1
    assert after_meta.wrapped_dek != old_wrapped
    assert read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1") == before_data
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"

    secrets = os.path.join(data_dir, "secrets")
    assert os.path.exists(s1_path(secrets, before_meta.file_shard_version))
    assert os.path.exists(s1_path(secrets, after_meta.file_shard_version))

    vault.close()
    reopened = _open(data_dir, schema)
    try:
        assert reopened.get("cred-1").get_string("api_key") == "secret-for-cred-1"
        assert (
            read_key_meta(reopened.db).file_shard_version
            == after_meta.file_shard_version
        )
    finally:
        reopened.close()


def test_rotate_s2_changes_the_config_shard_without_reencrypting_records(
    vault, data_dir, schema
):
    put_record(vault, "cred-1")
    before_meta = read_key_meta(vault.db)
    before_data = read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1")
    old_wrapped = before_meta.wrapped_dek

    rotate_s2(vault)

    after_meta = read_key_meta(vault.db)
    assert after_meta.active_config_shard != before_meta.active_config_shard
    assert after_meta.file_shard_version == before_meta.file_shard_version
    assert after_meta.wrapped_dek != old_wrapped
    assert read_raw_data(os.path.join(data_dir, "vault.db"), "cred-1") == before_data
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"

    vault.close()
    reopened = _open(data_dir, schema)
    try:
        assert reopened.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        reopened.close()


def test_rotate_s1_uses_the_operator_shard_and_rotate_s2_still_works(vault):
    put_record(vault, "cred-1")
    shard = bytes(range(SHARD_SIZE))

    rotate_s1(vault, shard=shard)
    meta = read_key_meta(vault.db)
    assert (
        load_s1_from_file(s1_path(vault.secrets_dir, meta.file_shard_version)) == shard
    )

    rotate_s2(vault, shard=b"\x01" * SHARD_SIZE)
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"


def test_rotate_s1_rejects_a_wrong_sized_shard(vault):
    put_record(vault, "cred-1")
    before = read_key_meta(vault.db)

    with pytest.raises(KeyMismatchError):
        rotate_s1(vault, shard=b"short")

    after = read_key_meta(vault.db)
    assert after.file_shard_version == before.file_shard_version
    assert after.wrapped_dek == before.wrapped_dek
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"
