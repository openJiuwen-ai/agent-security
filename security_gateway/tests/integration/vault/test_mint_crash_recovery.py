"""A local key written before the mint commit must not outlive the race."""

from __future__ import annotations

import multiprocessing
import os
import secrets
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tests._fuzz_rng import FuzzRandom
from security_gateway.vault import Config, FieldDef, Record, Schema, Type, Value, Vault
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.clusterkey.authority import KVClusterStore
from security_gateway.vault.clusterkey.clusterkey import PendingMint
from security_gateway.vault.errors import RotationInProgressError
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.etcdstore.cluster_keys import presence_key

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
    not os.environ.get(ETCD_ENDPOINT_ENV),
    reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
)
]


def _endpoint() -> str:
    return os.environ[ETCD_ENDPOINT_ENV].strip()


def _identity(directory: Path, node: str) -> tuple[Path, Path, Fingerprint]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node)])
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
    cert_file = directory / f"{node}.crt"
    key_file = directory / f"{node}.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_file, key_file, Fingerprint(cert)


@pytest.fixture
def namespace() -> str:
    return "mint-crash-" + uuid.uuid4().hex[:12]


@pytest.fixture
def client(namespace):
    import etcd3

    host, _, port = _endpoint().removeprefix("http://").partition(":")
    connection = etcd3.Etcd3Client(host=host, port=int(port or 2379))
    try:
        yield connection
    finally:
        connection.delete_prefix(f"/security_gateway/{namespace}/")
        connection.close()


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="api_key", type=Type.STRING, encrypted=True),
        ],
    )


def _record(record_id: str, secret: str) -> Record:
    return Record(id=record_id, fields={"api_key": Value.new_string(secret)})


def _config(
    directory: Path,
    node: str,
    namespace: str,
    cert: Path,
    key: Path,
    pins: tuple[Fingerprint, ...],
) -> Config:
    return Config(
        data_dir=str(directory),
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(_endpoint(),),
            namespace=namespace,
            node_id=node,
            trusted_cert_sha256=tuple(str(pin) for pin in pins),
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            fetch_timeout=1.0,
        ),
    )


def test_a_local_key_written_before_a_lost_race_is_discarded(
    tmp_path: Path, namespace: str, monkeypatch
) -> None:
    identities = {
        node: _identity(tmp_path, node) for node in ("node-a", "node-b")
    }
    pins = tuple(value[2] for value in identities.values())
    cert_a, key_a, _ = identities["node-a"]
    cert_b, key_b, _ = identities["node-b"]
    config_a = _config(tmp_path / "a", "node-a", namespace, cert_a, key_a, pins)
    config_b = _config(tmp_path / "b", "node-b", namespace, cert_b, key_b, pins)

    original = PendingMint.commit

    def crash_before_claim(self) -> bool:
        raise RuntimeError("killed before the mint commit")

    monkeypatch.setattr(PendingMint, "commit", crash_before_claim)
    with pytest.raises(RuntimeError):
        Vault.open(config_a, _schema())
    monkeypatch.setattr(PendingMint, "commit", original)

    winner = Vault.open(config_b, _schema())
    try:
        winner.put(_record("winner", "from-node-b"))
    finally:
        winner.close()

    restarted = Vault.open(config_a, _schema())
    try:
        restarted.put(_record("after", "from-node-a"))
        assert restarted.get("after").get("api_key").as_string() == "from-node-a"
    finally:
        restarted.close()


def test_a_recovery_candidate_is_not_used_before_its_commit(
    tmp_path: Path, namespace: str, client, monkeypatch
) -> None:
    identities = {
        node: _identity(tmp_path, node) for node in ("node-a", "node-b")
    }
    pins = tuple(value[2] for value in identities.values())
    cert_a, key_a, _ = identities["node-a"]
    cert_b, key_b, _ = identities["node-b"]
    config_a = _config(tmp_path / "a", "node-a", namespace, cert_a, key_a, pins)
    config_b = _config(tmp_path / "b", "node-b", namespace, cert_b, key_b, pins)

    old = Vault.open(config_b, _schema())
    try:
        old.put(_record("old", "before-recovery"))
    finally:
        old.close()
    client.delete(presence_key(namespace, "node-b"))

    original = KVClusterStore.recover_mint

    def crash_before_recover(self, *args, **kwargs) -> bool:
        raise RuntimeError("killed before the recovery commit")

    monkeypatch.setattr(KVClusterStore, "recover_mint", crash_before_recover)
    with pytest.raises(RuntimeError):
        Vault.open(config_a, _schema())
    monkeypatch.setattr(KVClusterStore, "recover_mint", original)

    restarted = Vault.open(config_a, _schema())
    try:
        restarted.put(_record("new", "after-recovery"))
        assert restarted.get("new").get("api_key").as_string() == "after-recovery"
    finally:
        restarted.close()


def _hold_a_recovered_key(
    config: Config, ready: str, stop: multiprocessing.synchronize.Event
) -> None:
    vault = Vault.open(config, _schema())
    try:
        vault.put(_record("winner", "from-node-c"))
        Path(ready).write_text("1", encoding="utf-8")
        stop.wait(60)
    finally:
        vault.close()


def test_a_recovery_loser_adopts_the_winners_key(
    tmp_path: Path, namespace: str, monkeypatch
) -> None:
    identities = {
        node: _identity(tmp_path, node) for node in ("node-b", "node-c", "node-d")
    }
    pins = tuple(value[2] for value in identities.values())
    cert_b, key_b, _ = identities["node-b"]
    cert_c, key_c, _ = identities["node-c"]
    cert_d, key_d, _ = identities["node-d"]
    config_b = _config(tmp_path / "b", "node-b", namespace, cert_b, key_b, pins)
    config_c = _config(tmp_path / "c", "node-c", namespace, cert_c, key_c, pins)
    config_d = _config(tmp_path / "d", "node-d", namespace, cert_d, key_d, pins)

    owner = Vault.open(config_b, _schema())
    owner.close()

    original = PendingMint.commit

    def crash_before_claim(self) -> bool:
        raise RuntimeError("killed before the recovery commit")

    monkeypatch.setattr(PendingMint, "commit", crash_before_claim)
    with pytest.raises(RuntimeError):
        Vault.open(config_d, _schema())
    monkeypatch.setattr(PendingMint, "commit", original)

    context = multiprocessing.get_context("fork")
    stop = context.Event()
    ready = tmp_path / "ready"
    child = context.Process(
        target=_hold_a_recovered_key,
        args=(config_c, str(ready), stop),
    )
    child.start()
    try:
        deadline = 30.0
        while not ready.exists() and deadline > 0:
            child.join(0.05)
            deadline -= 0.05
        assert ready.exists(), "node-c did not recover the fleet's key"

        restarted = Vault.open(config_d, _schema())
        try:
            deadline = time.monotonic() + 10.0
            while True:
                try:
                    assert (
                        restarted.get("winner").get("api_key").as_string()
                        == "from-node-c"
                    )
                    break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
        finally:
            restarted.close()
    finally:
        stop.set()
        child.join(10)
        if child.is_alive():
            child.kill()
            child.join()


MINT_FUZZ_SEED = int(
    os.environ.get("MINT_FUZZ_SEED", secrets.randbelow(1 << 32))
)


@pytest.mark.parametrize(
    "offset", range(6), ids=lambda offset: f"seed={MINT_FUZZ_SEED + offset}"
)
def test_random_mint_commit_failures_are_recoverable(
    tmp_path: Path, namespace: str, monkeypatch, offset: int
) -> None:
    seed = MINT_FUZZ_SEED + offset
    rng = FuzzRandom(seed)
    case = tmp_path / f"case-{offset}"
    case.mkdir()
    identities = {
        node: _identity(case, node) for node in ("node-a", "node-b")
    }
    pins = tuple(value[2] for value in identities.values())
    cert_a, key_a, _ = identities["node-a"]
    cert_b, key_b, _ = identities["node-b"]
    case_namespace = f"{namespace}-{offset}"
    config_a = _config(case / "a", "node-a", case_namespace, cert_a, key_a, pins)
    config_b = _config(case / "b", "node-b", case_namespace, cert_b, key_b, pins)

    original = PendingMint.commit
    fail_with_false = rng.choice((False, True))
    error = rng.choice((RuntimeError, OSError, ValueError))

    if fail_with_false:

        def fail(self) -> bool:
            return False

        expected = RotationInProgressError
    else:

        def fail(self) -> bool:
            raise error("injected mint commit failure")

        expected = error

    monkeypatch.setattr(PendingMint, "commit", fail)
    try:
        with pytest.raises(expected):
            Vault.open(config_a, _schema())
    finally:
        monkeypatch.setattr(PendingMint, "commit", original)

    winner = Vault.open(config_b, _schema())
    try:
        winner.put(_record("winner", f"from-node-b-{seed}"))
    finally:
        winner.close()

    restarted = Vault.open(config_a, _schema())
    try:
        restarted.put(_record("after", f"from-node-a-{seed}"))
        assert (
            restarted.get("after").get("api_key").as_string()
            == f"from-node-a-{seed}"
        )
    finally:
        restarted.close()
