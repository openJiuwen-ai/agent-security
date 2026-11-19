"""Kill a process at a random point during startup, initialization, or recovery.

A kill in the middle of opening a store must leave it reopenable: either
the operation completed, or the next owner can finish it.  These tests use
a real process and a real etcd so the kill lands in the same code paths a
deployment uses.
"""

from __future__ import annotations

import os
import random
import secrets
import signal
import subprocess
import sys
import time
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
    Record,
    Schema,
    Type,
    Value,
    Vault,
)
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig

from ._etcd import drop_namespace

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"
WORKER = Path(__file__).with_name("_startup_worker.py")
BASE_SEED = int(os.environ.get("API_FUZZ_SEED", secrets.randbits(31)))


def _seeds(count: int) -> list[int]:
    return [BASE_SEED + offset for offset in range(count)]


def _id(seed: int) -> str:
    return f"seed={seed}"

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get(ETCD_ENDPOINT_ENV),
        reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
    ),
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


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
        ],
    )


def _record(i: int) -> Record:
    return Record(
        id=f"record-{i}",
        fields={
            "name": Value.new_string(f"name-{i}"),
            "secret": Value.new_string(f"secret-{i}"),
        },
    )


def _config(
    directory: Path,
    namespace: str,
    cert: Path,
    key: Path,
    pin: Fingerprint,
    node: str = "node-a",
) -> Config:
    return Config(
        data_dir=str(directory),
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(_endpoint(),),
            namespace=namespace,
            node_id=node,
            trusted_cert_sha256=(str(pin),),
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            fetch_timeout=2.0,
        ),
    )


def _kill_after(
    config: Config,
    started: Path,
    delay: float,
    action: str = "open",
) -> None:
    cert = config.etcd.identity_cert_file
    key = config.etcd.identity_key_file
    pin = config.etcd.trusted_cert_sha256[0]
    process = subprocess.Popen(
        [
            sys.executable,
            str(WORKER),
            "--data-dir", config.data_dir,
            "--endpoint", config.etcd.endpoints[0],
            "--namespace", config.etcd.namespace,
            "--node", config.etcd.node_id,
            "--cert", cert,
            "--key", key,
            "--pin", pin,
            "--started", str(started),
            "--action", action,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        deadline = time.monotonic() + 30
        while not started.exists():
            if process.poll() is not None:
                return
            if time.monotonic() > deadline:
                raise AssertionError("worker never started")
            time.sleep(0.01)
        time.sleep(delay)
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=10)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)


@pytest.mark.parametrize("seed", _seeds(6), ids=_id)
def test_a_kill_during_initialization_does_not_brick_the_store(tmp_path, seed):
    rng = random.Random(seed)
    namespace = "startup-init-" + uuid.uuid4().hex[:12]
    cert, key, pin = _identity(tmp_path, "node-a")
    directory = tmp_path / f"init-{seed}"
    config = _config(directory, namespace, cert, key, pin)
    try:
        _kill_after(config, tmp_path / f"init-{seed}.started", rng.uniform(0.0, 0.25))
        vault = Vault.open(config, _schema())
        try:
            vault.put(_record(seed))
            assert vault.get(f"record-{seed}") == _record(seed)
        finally:
            vault.close()
    finally:
        drop_namespace(_endpoint(), namespace)


@pytest.mark.parametrize("seed", _seeds(6), ids=_id)
def test_a_kill_during_startup_keeps_existing_records_readable(tmp_path, seed):
    rng = random.Random(seed)
    namespace = "startup-read-" + uuid.uuid4().hex[:12]
    cert, key, pin = _identity(tmp_path, "node-a")
    directory = tmp_path / f"read-{seed}"
    config = _config(directory, namespace, cert, key, pin)
    try:
        vault = Vault.open(config, _schema())
        try:
            for i in range(10):
                vault.put(_record(i))
        finally:
            vault.close()
        _kill_after(config, tmp_path / f"read-{seed}.started", rng.uniform(0.0, 0.15))
        vault = Vault.open(config, _schema())
        try:
            for i in range(10):
                assert vault.get(f"record-{i}") == _record(i)
        finally:
            vault.close()
    finally:
        drop_namespace(_endpoint(), namespace)


def test_a_random_crash_at_any_recovery_phase(tmp_path):
    """Mix initialization, startup, adoption, and mint recovery crashes.

    Each iteration picks a phase, kills the worker after a random delay,
    and requires the next open to leave a usable store.  The seed and
    phase are in the failure message so a failure can be replayed.
    """
    import etcd3

    rng = random.Random(BASE_SEED)
    host, _, port = _endpoint().removeprefix("http://").partition(":")
    for iteration in range(12):
        namespace = "startup-mixed-" + uuid.uuid4().hex[:12]
        cert_a, key_a, pin_a = _identity(tmp_path, "node-a")
        cert_b, key_b, pin_b = _identity(tmp_path, "node-b")
        config_a = _config(
            tmp_path / f"mixed-a-{iteration}", namespace, cert_a, key_a, pin_a
        )
        config_b = _config(
            tmp_path / f"mixed-b-{iteration}",
            namespace,
            cert_b,
            key_b,
            pin_b,
            "node-b",
        )
        phase = rng.choice(("init", "startup", "mint-recover"))
        owner = None
        delay = -1.0
        try:
            if phase == "startup":
                owner = Vault.open(config_a, _schema())
                for i in range(3):
                    owner.put(_record(100 + i))
                owner.close()
                owner = None
            elif phase == "mint-recover":
                owner = Vault.open(config_b, _schema())
                for i in range(3):
                    owner.put(_record(100 + i))
                owner.close()
                owner = None
                client = etcd3.Etcd3Client(host=host, port=int(port or 2379))
                try:
                    client.delete(f"/security_gateway/{namespace}/presence/node-b")
                finally:
                    client.close()
            delay = rng.uniform(0.0, 0.3)
            _kill_after(
                config_a,
                tmp_path / f"mixed-{iteration}.started",
                delay,
            )

            vault = Vault.open(config_a, _schema())
            try:
                if phase == "startup":
                    assert vault.get("record-100") == _record(100)
                else:
                    vault.put(_record(iteration + 200))
                    assert vault.get(f"record-{iteration + 200}") == _record(
                        iteration + 200
                    )
            finally:
                vault.close()
        except Exception as exc:  # noqa: BLE001 - attach phase and seed to every failure
            pytest.fail(
                f"phase={phase} seed={BASE_SEED} iteration={iteration} "
                f"delay={delay:.3f}: {exc}"
            )
        finally:
            if owner is not None:
                owner.close()
            drop_namespace(_endpoint(), namespace)
