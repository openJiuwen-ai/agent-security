"""A long random operation sequence against a real etcd must stay readable.

The unit fuzz exercises one call at a time.  This test keeps a vault open
across puts, deletes, overwrites and rotations, then reopens it: the
mirror, the authority and the local key metadata have to agree after an
arbitrary history, not just after a scripted one.
"""

from __future__ import annotations

import os
import random
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from security_gateway.vault import (
    Config,
    FieldDef,
    NotFoundError,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.clusterkey.clusterkey import ClusterKeyError
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.rotate import rotate_dek

from ._etcd import drop_namespace

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get(ETCD_ENDPOINT_ENV),
        reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
    ),
]


def _endpoint() -> str:
    return os.environ[ETCD_ENDPOINT_ENV].strip()


def _identity(directory: Path, name: str = "node-a") -> tuple[Path, Path, Fingerprint]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
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
    return cert_file, key_file, Fingerprint(cert)


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


@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
@pytest.mark.parametrize("seed", range(3))
def test_a_random_history_against_real_etcd_reopens_readable(tmp_path, seed):
    directory = tmp_path / f"state-{seed}"
    directory.mkdir()
    cert, key, pin = _identity(directory)
    namespace = "state-" + uuid.uuid4().hex[:12]

    def cfg() -> Config:
        return Config(
            data_dir=str(directory / "store"),
            multi_process=True,
            etcd=EtcdConfig(
                endpoints=(_endpoint(),),
                namespace=namespace,
                node_id="node-a",
                trusted_cert_sha256=(pin,),
                identity_cert_file=str(cert),
                identity_key_file=str(key),
                fetch_timeout=2.0,
            ),
        )

    rng = random.Random(seed)
    vault = Vault.open(cfg(), _schema())
    try:
        for _ in range(30):
            choice = rng.randrange(10)
            try:
                if choice < 5:
                    vault.put(_record(f"v{rng.randrange(4)}"))
                elif choice < 8:
                    vault.get("record")
                elif choice < 9:
                    vault.delete("record")
                else:
                    rotate_dek(vault)
            except NotFoundError:
                pass
    finally:
        vault.close()

    reopened = Vault.open(cfg(), _schema())
    try:
        try:
            record = reopened.get("record")
        except NotFoundError:
            return
        assert record == _record(record.fields["value"].as_string())
    finally:
        reopened.close()
        drop_namespace(_endpoint(), namespace)


def test_a_node_id_cannot_swap_its_certificate(tmp_path):
    """The roster binds a node id to one certificate; a new key is refused."""
    first = tmp_path / "first"
    first.mkdir()
    cert, key, pin = _identity(first)
    second = tmp_path / "second"
    second.mkdir()
    cert2, key2, pin2 = _identity(second)
    namespace = "swap-" + uuid.uuid4().hex[:12]

    def config(use_second: bool) -> Config:
        return Config(
            data_dir=str(tmp_path / ("second" if use_second else "first-store")),
            multi_process=True,
            etcd=EtcdConfig(
                endpoints=(_endpoint(),),
                namespace=namespace,
                node_id="node-a",
                trusted_cert_sha256=(pin, pin2),
                identity_cert_file=str(cert2 if use_second else cert),
                identity_key_file=str(key2 if use_second else key),
                fetch_timeout=2.0,
            ),
        )

    vault = Vault.open(config(False), _schema())
    vault.put(_record("before"))
    vault.close()

    with pytest.raises(ClusterKeyError, match="different certificate"):
        Vault.open(config(True), _schema()).close()
    drop_namespace(_endpoint(), namespace)
