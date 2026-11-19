"""A rotation process dies in the etcd mode; the fleet keeps serving.

The crash happens after the authority's generation moved and the records
were rewritten, but before the rotator committed its local key metadata.
A second process on the same node and a process on another node keep
writing and reading throughout.  After the crash the fleet must still be
able to read the records, adopt the key the dead rotator published, and
finish another rotation.

The test runs only when ``CRED_ROUTER_ETCD_ENDPOINT`` names a reachable
etcd.  The identities are ephemeral and pinned, so the endpoint does not
need TLS.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from security_gateway.vault import Config, Record, Schema, Type, Value, Vault, rotate_dek
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.errors import RotationInProgressError
from security_gateway.vault.rotate import count_stragglers
from security_gateway.vault.schema import FieldDef

WORKER = Path(__file__).with_name("_etcd_crash_worker.py")
NODES = ("node-a", "node-b")


def _skip_without_etcd() -> str:
    endpoint = os.environ.get("CRED_ROUTER_ETCD_ENDPOINT", "").strip()
    if not endpoint:
        pytest.skip("set CRED_ROUTER_ETCD_ENDPOINT to run the etcd crash test")
    return endpoint


def _identity(directory: Path, node: str) -> tuple[Path, Path, Fingerprint]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, node)])
    now = datetime.now(timezone.utc)
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
            FieldDef(name="endpoint", type=Type.STRING),
            FieldDef(name="api_key", type=Type.BYTES, encrypted=True),
        ],
    )


def _record(record_id: str, secret: bytes) -> Record:
    return Record(
        id=record_id,
        fields={
            "endpoint": Value.new_string("https://api.example.test/v1"),
            "api_key": Value.new_bytes(secret),
        },
    )


def _config(
    directory: Path,
    node: str,
    endpoint: str,
    namespace: str,
    pins: tuple[str, ...],
    cert: Path,
    key: Path,
) -> Config:
    return Config(
        data_dir=str(directory / node / "vault"),
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(endpoint,),
            namespace=namespace,
            node_id=node,
            trusted_cert_sha256=pins,
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            fetch_timeout=15.0,
        ),
    )


def _wait_for(path: Path, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() > deadline:
            raise AssertionError(f"{path} did not appear")
        time.sleep(0.02)


def test_a_rotation_crash_leaves_the_fleet_serving(tmp_path):
    endpoint = _skip_without_etcd()
    namespace = f"crash-{os.getpid()}"
    identities = {node: _identity(tmp_path, node) for node in NODES}
    pins = tuple(identity[2] for identity in identities.values())
    go = tmp_path / "go"
    stop = tmp_path / "stop"
    env = dict(os.environ)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    env.update(
        {
            "CRASH_ENDPOINT": endpoint,
            "CRASH_NS": namespace,
            "CRASH_PINS": ",".join(pins),
            "CRASH_GO": str(go),
            "CRASH_STOP": str(stop),
            "CRASH_SECONDS": "30",
        }
    )

    cert, key, _pin = identities["node-a"]
    bootstrap = Vault.open(
        _config(tmp_path, "node-a", endpoint, namespace, pins, cert, key), _schema()
    )
    try:
        bootstrap.put(_record("sentinel", b"survives the crash"))
    finally:
        bootstrap.close()

    processes: dict[str, subprocess.Popen[str]] = {}
    try:
        for node in NODES:
            cert, key, _pin = identities[node]
            worker = f"steady-{node}"
            child_env = dict(env)
            child_env.update(
                {
                    "CRASH_ROLE": "steady",
                    "CRASH_WORKER": worker,
                    "CRASH_DIR": str(tmp_path / node / "vault"),
                    "CRASH_NODE": node,
                    "CRASH_CERT": str(cert),
                    "CRASH_KEY": str(key),
                    "CRASH_ACK": str(tmp_path / f"{worker}-"),
                }
            )
            processes[worker] = subprocess.Popen(
                [sys.executable, str(WORKER)],
                env=child_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        for worker in processes:
            _wait_for(tmp_path / f"{worker}-ready", 120)
        go.write_text("1")

        cert, key, _pin = identities["node-a"]
        crash_env = dict(env)
        crash_env.update(
            {
                "CRASH_ROLE": "crash",
                "CRASH_WORKER": "crash-a",
                "CRASH_DIR": str(tmp_path / "node-a" / "vault"),
                "CRASH_NODE": "node-a",
                "CRASH_CERT": str(cert),
                "CRASH_KEY": str(key),
                "CRASH_ACK": str(tmp_path / "crash-a-"),
            }
        )
        crasher = subprocess.Popen(
            [sys.executable, str(WORKER)],
            env=crash_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        out, err = crasher.communicate(timeout=180)
        assert crasher.returncode == 17, (
            f"the rotator did not die at the crash point ({crasher.returncode})\n"
            f"stdout:\n{out}\nstderr:\n{err}"
        )

        stop.write_text("1")
        results = {}
        for worker, process in processes.items():
            worker_out, worker_err = process.communicate(timeout=120)
            assert process.returncode == 0, (
                f"{worker} failed ({process.returncode})\n"
                f"stdout:\n{worker_out}\nstderr:\n{worker_err}"
            )
            results[worker] = json.loads(
                [line for line in worker_out.splitlines() if line.strip()][-1]
            )
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)

    for worker, result in results.items():
        assert not result["errors"], f"{worker}: {result['errors']}"
        assert result["writes"] > 0 and result["reads"] > 0

    cert, key, _pin = identities["node-b"]
    verifier = Vault.open(
        _config(tmp_path, "node-b", endpoint, namespace, pins, cert, key), _schema()
    )
    try:
        assert verifier.authority is not None
        generation = verifier.authority.generation()
        assert generation >= 2, f"the authority is on generation {generation}"
        if verifier.keys.cur().version < generation:
            assert verifier.refresh_from_fleet()
        assert verifier.get("sentinel").get_bytes("api_key") == b"survives the crash"
        for worker in results:
            record_id = f"steady-{worker}"
            assert (
                verifier.get(record_id)
                .get_bytes("api_key")
                .startswith(f"secret-{worker}-".encode())
            )
        assert count_stragglers(verifier, generation, verifier.authority.store) == 0

        deadline = time.monotonic() + 90
        while True:
            try:
                rotate_dek(verifier, verifier.authority.store)
                break
            except RotationInProgressError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(1)
        assert verifier.authority.generation() == generation + 1
        assert verifier.get("sentinel").get_bytes("api_key") == b"survives the crash"
    finally:
        verifier.close()
