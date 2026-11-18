"""The etcd authority over TLS/mTLS, not just validated TLS fields.

The unit suite proves that a partial TLS configuration is refused.  This
test proves the other half: a real etcd configured with a client CA and a
client certificate accepts the vault, and the vault reads and writes
through that connection.  It starts its own etcd so it does not depend on
the developer's plaintext instance.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from security_gateway.vault import (
    Config,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
    VaultError,
)
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig, EtcdTLSConfig

ETCD = "/tmp/etcd-deb/usr/bin/etcd"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(not os.path.exists(ETCD), reason="no etcd binary"),
]


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _certificate(
    directory: Path,
    name: str,
    *,
    ca: tuple[x509.Certificate, ec.EllipticCurvePrivateKey] | None = None,
    server: bool = False,
) -> tuple[x509.Certificate, ec.EllipticCurvePrivateKey, Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = subject if ca is None else ca[0].subject
    signing_key = key if ca is None else ca[1]
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca is None, path_length=None), critical=True)
    )
    if ca is not None:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
    cert = builder.sign(signing_key, hashes.SHA256())
    cert_file = directory / f"{name}.crt"
    key_file = directory / f"{name}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert, key, cert_file, key_file


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="value", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
        ],
    )


def _record(value: str) -> Record:
    return Record(
        id="record",
        fields={
            "value": Value.new_string(value),
            "secret": Value.new_string("secret-" + value),
        },
    )


@pytest.fixture
def tls_etcd(tmp_path):
    directory = tmp_path / "pki"
    directory.mkdir()
    ca_cert, ca_key, ca_file, _ca_key_file = _certificate(directory, "ca")
    _server_cert, _server_key, server_file, server_key_file = _certificate(
        directory, "server", ca=(ca_cert, ca_key), server=True
    )
    client_cert, _client_key, client_file, client_key_file = _certificate(
        directory, "client", ca=(ca_cert, ca_key)
    )
    client_port = _free_port()
    peer_port = _free_port()
    data = tmp_path / "etcd"
    process = subprocess.Popen(
        [
            ETCD,
            "--data-dir", str(data),
            "--listen-client-urls", f"https://127.0.0.1:{client_port}",
            "--advertise-client-urls", f"https://127.0.0.1:{client_port}",
            "--cert-file", str(server_file),
            "--key-file", str(server_key_file),
            "--trusted-ca-file", str(ca_file),
            "--client-cert-auth",
            "--listen-peer-urls", f"http://127.0.0.1:{peer_port}",
            "--initial-advertise-peer-urls", f"http://127.0.0.1:{peer_port}",
            "--initial-cluster", f"default=http://127.0.0.1:{peer_port}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("TLS etcd exited before accepting connections")
            try:
                with socket.create_connection(("127.0.0.1", client_port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("TLS etcd did not listen in time")
        yield {
            "endpoint": f"https://127.0.0.1:{client_port}",
            "ca": str(ca_file),
            "client_cert": str(client_file),
            "client_key": str(client_key_file),
            "pin": Fingerprint(client_cert),
        }
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def test_the_authority_works_over_mtls(tls_etcd, tmp_path):
    namespace = "tls-" + uuid.uuid4().hex[:12]
    cert = tls_etcd["client_cert"]
    key = tls_etcd["client_key"]
    config = Config(
        data_dir=str(tmp_path / "store"),
        etcd=EtcdConfig(
            endpoints=(tls_etcd["endpoint"],),
            namespace=namespace,
            node_id="node-a",
            tls=EtcdTLSConfig(
                ca_file=tls_etcd["ca"],
                cert_file=cert,
                key_file=key,
            ),
            identity_cert_file=cert,
            identity_key_file=key,
            trusted_cert_sha256=(tls_etcd["pin"],),
            fetch_timeout=2.0,
        ),
    )
    vault = Vault.open(config, _schema())
    try:
        vault.put(_record("over-tls"))
        assert vault.get("record") == _record("over-tls")
    finally:
        vault.close()


def test_a_client_without_the_trusted_ca_is_refused(tls_etcd, tmp_path):
    namespace = "tls-no-ca-" + uuid.uuid4().hex[:12]
    config = Config(
        data_dir=str(tmp_path / "store-no-ca"),
        etcd=EtcdConfig(
            endpoints=(tls_etcd["endpoint"],),
            namespace=namespace,
            node_id="node-a",
            tls=EtcdTLSConfig(
                ca_file=tls_etcd["ca"],
                cert_file=tls_etcd["client_cert"],
                key_file=tls_etcd["client_key"],
            ),
            identity_cert_file=tls_etcd["client_cert"],
            identity_key_file=tls_etcd["client_key"],
            trusted_cert_sha256=(tls_etcd["pin"],),
            fetch_timeout=0.5,
        ),
    )
    # A wrong CA is not a valid certificate chain; the client must not fall
    # back to plaintext.
    config.etcd.tls = EtcdTLSConfig(
        ca_file=str(tmp_path / "missing-ca.pem"),
        cert_file=tls_etcd["client_cert"],
        key_file=tls_etcd["client_key"],
    )
    with pytest.raises(VaultError):
        Vault.open(config, _schema()).close()
