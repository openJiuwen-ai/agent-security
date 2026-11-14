"""The data directory's cross-process mode and configuration guard."""

from __future__ import annotations

import types

import pytest
from security_gateway.vault.errors import InvalidError
from security_gateway.vault.mode import DataDirGuard


def _cfg(
    tmp_path, *, multi=False, namespace="security_gateway-vault", node_id="node-a"
):
    etcd = types.SimpleNamespace(
        endpoints=("http://127.0.0.1:2379",),
        namespace=namespace,
        node_id=node_id,
        identity_cert_file="",
        identity_key_file="",
        identity_ca_file="/id-ca.pem",
        trusted_cert_sha256=(),
        fetch_timeout=30.0,
        tls=types.SimpleNamespace(
            ca_file="/ca.pem", cert_file="/c.pem", key_file="/k.pem"
        ),
    )
    return types.SimpleNamespace(
        data_dir=str(tmp_path),
        db_path="",
        crypto_mode="aes-gcm",
        multi_process=multi,
        etcd=etcd,
    )


def test_a_second_single_process_guard_is_refused(tmp_path):
    first = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path), None)
    try:
        with pytest.raises(InvalidError, match="another process already uses"):
            DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path), None)
    finally:
        first.close()


def test_multi_process_guards_share_one_directory(tmp_path):
    first = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path, multi=True), None)
    second = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path, multi=True), None)
    third = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path, multi=True), None)
    try:
        with pytest.raises(InvalidError, match="different vault configuration"):
            DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path), None)
    finally:
        third.close()
        second.close()
        first.close()


def test_a_different_configuration_is_refused_after_close(tmp_path):
    first = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path, multi=True), None)
    first.close()
    with pytest.raises(InvalidError, match="different vault configuration"):
        DataDirGuard.acquire(
            str(tmp_path), _cfg(tmp_path, multi=True, namespace="other"), None
        )


def test_closing_releases_the_directory(tmp_path):
    first = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path), None)
    first.close()
    second = DataDirGuard.acquire(str(tmp_path), _cfg(tmp_path), None)
    second.close()
