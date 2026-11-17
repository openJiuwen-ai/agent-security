"""KEK rotation: S1 and S2 are rewrapped, records are not rewritten."""

from __future__ import annotations

import os

import pytest

from security_gateway.vault import (
    SHARD_SIZE,
    Config,
    KeyMismatchError,
    Vault,
    rotate_s1,
    rotate_s2,
)
from security_gateway.vault import rotate as rotate_module
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


def test_a_crash_after_writing_s1_before_the_metadata_keeps_the_old_shard(
    vault, data_dir, schema, monkeypatch
):
    """S1 is written before the metadata moves.

    A crash in between leaves an orphan file and an unchanged row; the
    store must keep opening with the old shard, and a retry must be able to
    finish the rotation.
    """
    put_record(vault, "cred-1")
    before = read_key_meta(vault.db)
    old_s1 = load_s1_from_file(s1_path(vault.secrets_dir, before.file_shard_version))

    def boom(*args, **kwargs):
        raise RuntimeError("the metadata write died")

    with monkeypatch.context() as patch:
        patch.setattr(rotate_module, "update_key_meta", boom)
        with pytest.raises(RuntimeError, match="metadata write died"):
            rotate_s1(vault)

    vault.close()
    reopened = _open(data_dir, schema)
    try:
        after = read_key_meta(reopened.db)
        assert after.file_shard_version == before.file_shard_version
        assert (
            load_s1_from_file(s1_path(reopened.secrets_dir, after.file_shard_version))
            == old_s1
        )
        assert reopened.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        reopened.close()

    retry = _open(data_dir, schema)
    try:
        rotate_s1(retry)
        assert retry.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        retry.close()


def test_a_half_written_s1_file_is_ignored_by_the_next_open(
    vault, data_dir, schema, monkeypatch
):
    """A crash in the middle of the new shard's write leaves a short file.

    The metadata never moved, so the old shard is still the one in use;
    a retry must truncate the short file and write the whole shard.
    """
    from security_gateway.vault import keys as keys_module

    put_record(vault, "cred-1")
    before = read_key_meta(vault.db)
    real_write = os.write

    def half_write(fd, data):
        real_write(fd, data[: SHARD_SIZE // 2])
        raise OSError("the disk filled up")

    monkeypatch.setattr(keys_module.os, "write", half_write)
    with pytest.raises(OSError):
        rotate_s1(vault)

    after = read_key_meta(vault.db)
    assert after.file_shard_version == before.file_shard_version
    assert after.wrapped_dek == before.wrapped_dek
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"

    monkeypatch.undo()
    rotate_s1(vault)
    assert vault.get("cred-1").get_string("api_key") == "secret-for-cred-1"

    vault.close()
    reopened = _open(data_dir, schema)
    try:
        assert reopened.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        reopened.close()


def test_a_crash_before_s2_metadata_keeps_the_old_config_shard(
    vault, data_dir, schema, monkeypatch
):
    put_record(vault, "cred-1")
    before = read_key_meta(vault.db)

    def boom(*args, **kwargs):
        raise RuntimeError("the metadata write died")

    with monkeypatch.context() as patch:
        patch.setattr(rotate_module, "update_key_meta", boom)
        with pytest.raises(RuntimeError, match="metadata write died"):
            rotate_s2(vault)

    vault.close()
    reopened = _open(data_dir, schema)
    try:
        after = read_key_meta(reopened.db)
        assert after.active_config_shard == before.active_config_shard
        assert after.wrapped_dek == before.wrapped_dek
        assert reopened.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        reopened.close()

    retry = _open(data_dir, schema)
    try:
        rotate_s2(retry)
        assert retry.get("cred-1").get_string("api_key") == "secret-for-cred-1"
    finally:
        retry.close()
