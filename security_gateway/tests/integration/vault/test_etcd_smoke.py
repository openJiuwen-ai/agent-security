"""A real etcd round trip catches imports the unit tests never execute."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from security_gateway.vault import Config, Record, Schema, Type, Vault, Value
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.schema import FieldDef

from ._etcd import drop_namespace


def _endpoint() -> str:
    return os.environ.get("CRED_ROUTER_ETCD_ENDPOINT", "")


pytestmark = pytest.mark.skipif(not _endpoint(), reason="set CRED_ROUTER_ETCD_ENDPOINT")


def _identity(directory: Path) -> tuple[Path, Path, Fingerprint]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "smoke")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_file = directory / "smoke.crt"
    key_file = directory / "smoke.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file, Fingerprint(cert)


def test_the_store_writes_and_reads_through_etcd(tmp_path):
    cert, key, pin = _identity(tmp_path)
    namespace = f"smoke-{uuid.uuid4().hex}"
    schema = Schema(
        version=1,
        fields=[FieldDef(name="api_key", type=Type.STRING, encrypted=True)],
    )
    cfg = Config(
        data_dir=str(tmp_path / "vault"),
        etcd=EtcdConfig(
            endpoints=(_endpoint(),),
            namespace=namespace,
            node_id="smoke",
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            trusted_cert_sha256=(pin,),
            fetch_timeout=2.0,
        ),
    )
    try:
        vault = Vault.open(cfg, schema)
        try:
            vault.put(
                Record(id="smoke", fields={"api_key": Value.new_string("secret")})
            )
            assert vault.get("smoke").fields["api_key"] == Value.new_string("secret")
        finally:
            vault.close()
    finally:
        drop_namespace(_endpoint(), namespace)
