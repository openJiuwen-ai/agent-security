"""The three-node, three-process-per-node vault load test.

Every process is a separate OS process with its own router-style vault
handle.  The three processes of a node share the node's vault data
directory; the nodes share an etcd authority.  Every process writes,
reads, and triggers a key rotation on its own -- this is the case that
proves there is no passive reader tier.

The test runs only when ``CRED_ROUTER_ETCD_ENDPOINT`` names a reachable
etcd.  It creates three ephemeral ECDSA identities and pins them for the
fleet's key handover, so the endpoint does not have to run TLS.
"""

from __future__ import annotations

import json
import os
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

from tests.integration.vault._etcd import drop_namespace
from security_gateway.vault import Config, Record, Schema, Type, Value, Vault
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.schema import FieldDef

WORKER = Path(__file__).with_name("_fleet_worker.py")
NODES = ("node-a", "node-b", "node-c")
PROCESSES_PER_NODE = 3
SECONDS = 40.0
ROUNDS = 1
RECORDS = 6


def _skip_without_etcd() -> str:
    endpoint = os.environ.get("CRED_ROUTER_ETCD_ENDPOINT", "").strip()
    if not endpoint:
        pytest.skip("set CRED_ROUTER_ETCD_ENDPOINT to run the nine-process fleet test")
    return endpoint


def _identity(directory: Path, node: str) -> tuple[Path, Path, str]:
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
    pins: tuple[str, ...],
    cert: Path,
    key: Path,
    namespace: str | None = None,
) -> Config:
    return Config(
        data_dir=str(directory / node / "vault"),
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(endpoint,),
            namespace=namespace or f"fleet-{os.getpid()}",
            node_id=node,
            trusted_cert_sha256=pins,
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            fetch_timeout=15.0,
        ),
    )


def test_three_nodes_and_three_processes_each_run_tpcc(tmp_path):
    endpoint = _skip_without_etcd()
    identities = {node: _identity(tmp_path, node) for node in NODES}
    pins = tuple(identity[2] for identity in identities.values())
    namespace = f"fleet-{uuid.uuid4().hex}"
    go_file = tmp_path / "go"
    env = dict(os.environ)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    env.update(
        {
            "FLEET_ENDPOINT": endpoint,
            "FLEET_NS": namespace,
            "FLEET_PINS": ",".join(pins),
            "FLEET_GO_FILE": str(go_file),
            "FLEET_SECONDS": str(SECONDS),
            "FLEET_ROUNDS": str(ROUNDS),
            "FLEET_RECORDS": str(RECORDS),
        }
    )

    sentinel_id = "rotation-sentinel"
    sentinel_secret = b"the same plaintext before and after the rotation"
    cert, key, _pin = identities["node-a"]
    bootstrap = Vault.open(
        _config(
            tmp_path, "node-a", endpoint, pins, cert, key, namespace
        ),
        _schema(),
    )
    try:
        bootstrap.put(_record(sentinel_id, sentinel_secret))
        assert bootstrap.authority is not None
        sentinel = bootstrap.authority.store.get_record(sentinel_id)
        assert sentinel is not None
        sentinel_ciphertext = bytes(sentinel.data)
        sentinel_generation = sentinel.dek_version
    except BaseException:
        bootstrap.close()
        raise

    processes: dict[str, subprocess.Popen[str]] = {}
    try:
        for node in NODES:
            cert, key, _pin = identities[node]
            for index in range(PROCESSES_PER_NODE):
                worker = f"{node}-{index}"
                child_env = dict(env)
                child_env.update(
                    {
                        "FLEET_DIR": str(tmp_path / node / "vault"),
                        "FLEET_NODE": node,
                        "FLEET_CERT": str(cert),
                        "FLEET_KEY": str(key),
                        "FLEET_WORKER": worker,
                        "FLEET_ROTATE_PREFIX": str(tmp_path / "rotate-round-"),
                        "FLEET_ACK_PREFIX": str(tmp_path / f"ack-{worker}-"),
                        "FLEET_LOG_FILE": str(tmp_path / f"{worker}.log"),
                    }
                )
                processes[worker] = subprocess.Popen(
                    [sys.executable, str(WORKER)],
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
        # Let every process get through Vault.open; the start file then
        # releases all nine at once.
        deadline = time.monotonic() + 120
        while True:
            missing = [
                worker
                for worker in processes
                if not (tmp_path / f"ack-{worker}-ready").exists()
            ]
            if not missing:
                break
            if time.monotonic() > deadline:
                pytest.fail(f"workers did not open: {missing[:3]}")
            time.sleep(0.05)
        go_file.write_text("1")

        # Publish one rotation round at a time.  Every worker sees the
        # same marker through the filesystem and calls rotate_dek at the
        # same time; the acks make the parent wait for the slowest one
        # before opening the next round.
        for round_index in range(ROUNDS):
            (tmp_path / f"rotate-round-{round_index}").write_text("1")
            deadline = time.monotonic() + 180
            while True:
                missing = [
                    worker
                    for worker in processes
                    if not (tmp_path / f"ack-{worker}-{round_index}").exists()
                ]
                if not missing:
                    break
                if time.monotonic() > deadline:
                    dumped = {}
                    for worker, process in processes.items():
                        try:
                            out, err = process.communicate(timeout=40)
                        except subprocess.TimeoutExpired:
                            process.kill()
                            out, err = process.communicate()
                        Path(tmp_path / f"{worker}.out").write_text(out)
                        Path(tmp_path / f"{worker}.err").write_text(err)
                        dumped[worker] = (process.returncode, out[-300:], err[-300:])
                    pytest.fail(
                        f"round {round_index}: no ack from {missing[:3]}; "
                        f"workers={dumped}"
                    )
                time.sleep(0.05)

        results = {}
        for worker, process in processes.items():
            out, err = process.communicate(timeout=SECONDS + 120)
            assert process.returncode == 0, (
                f"{worker} failed ({process.returncode})\nstdout:\n{out}\nstderr:\n{err}"
            )
            lines = [line for line in out.splitlines() if line.strip()]
            assert lines, f"{worker} printed no result\nstderr:\n{err}"
            results[worker] = json.loads(lines[-1])
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)
        bootstrap.close()
        go_file.unlink(missing_ok=True)

    assert len(results) == len(NODES) * PROCESSES_PER_NODE
    total_retries = 0
    for worker, result in results.items():
        assert not result["errors"], f"{worker}: {result['errors']}"
        assert result["writes"] > 0 and result["reads"] > 0
        assert result["attempts"] == ROUNDS, (
            f"{worker} made {result['attempts']} rotation attempts, want {ROUNDS}"
        )
        total_retries += result["retries"]
    assert sum(result["rotations"] for result in results.values()) >= 1
    assert total_retries > 0, (
        "no worker was refused the fleet lock; the rotation rounds did not overlap"
    )

    # A fresh process must see the fleet's final generation and every
    # record, including the records written by the other nodes.
    cert, key, _pin = identities["node-a"]
    verifier = Vault.open(
        _config(
            tmp_path, "node-a", endpoint, pins, cert, key, namespace
        ),
        _schema(),
    )
    try:
        assert verifier.authority is not None
        expected = 1 + sum(result["rotations"] for result in results.values())
        assert verifier.authority.generation() == expected, (
            f"the authority is on generation {verifier.authority.generation()}, "
            f"want {expected} (one per successful rotation)"
        )
        getattr(verifier, "_reconcile_mirror")()
        rotated = verifier.authority.store.get_record(sentinel_id)
        assert rotated is not None
        assert rotated.dek_version > sentinel_generation
        assert bytes(rotated.data) != sentinel_ciphertext
        assert verifier.get(sentinel_id).get_bytes("api_key") == sentinel_secret
        for worker in results:
            for index in range(RECORDS):
                record_id = f"{worker}-{index}"
                got = verifier.get(record_id).get_bytes("api_key")
                expected = f"secret-{worker}-{record_id}".encode()
                assert got == expected, f"{record_id}: {got!r} != {expected!r}"
    finally:
        verifier.close()
        drop_namespace(endpoint, namespace)


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)
def test_the_fleet_keeps_serving_when_one_process_per_node_dies(tmp_path):
    """SIGKILL one process on every node while the fleet writes and rotates.

    The survivors must keep writing and reading their own records, and the
    sentinel must still decrypt after the round.  The dead processes leave
    their leases behind; the fleet has to keep working through the TTL and
    the generation fence.
    """
    endpoint = _skip_without_etcd()
    identities = {node: _identity(tmp_path, node) for node in NODES}
    pins = tuple(identity[2] for identity in identities.values())
    namespace = f"fleet-crash-{uuid.uuid4().hex}"
    go_file = tmp_path / "go"
    env = dict(os.environ)
    env["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"
    env.update(
        {
            "FLEET_ENDPOINT": endpoint,
            "FLEET_NS": namespace,
            "FLEET_PINS": ",".join(pins),
            "FLEET_GO_FILE": str(go_file),
            "FLEET_SECONDS": "25",
            "FLEET_ROUNDS": "1",
            "FLEET_RECORDS": "2",
        }
    )

    cert, key, _pin = identities["node-a"]
    bootstrap = Vault.open(
        _config(
            tmp_path, "node-a", endpoint, pins, cert, key, namespace=namespace
        ),
        _schema(),
    )
    try:
        bootstrap.put(_record("sentinel", b"survives the crash matrix"))
    except BaseException:
        bootstrap.close()
        raise

    processes: dict[str, subprocess.Popen[str]] = {}
    try:
        for node in NODES:
            cert, key, _pin = identities[node]
            for index in range(PROCESSES_PER_NODE):
                worker = f"{node}-{index}"
                child_env = dict(env)
                child_env.update(
                    {
                        "FLEET_DIR": str(tmp_path / node / "vault"),
                        "FLEET_NODE": node,
                        "FLEET_CERT": str(cert),
                        "FLEET_KEY": str(key),
                        "FLEET_WORKER": worker,
                        "FLEET_ROTATE_PREFIX": str(tmp_path / "rotate-round-"),
                        "FLEET_ACK_PREFIX": str(tmp_path / f"ack-{worker}-"),
                        "FLEET_LOG_FILE": str(tmp_path / f"{worker}.log"),
                    }
                )
                processes[worker] = subprocess.Popen(
                    [sys.executable, str(WORKER)],
                    env=child_env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

        deadline = time.monotonic() + 120
        while True:
            missing = [
                worker
                for worker in processes
                if not (tmp_path / f"ack-{worker}-ready").exists()
            ]
            if not missing:
                break
            if time.monotonic() > deadline:
                pytest.fail(f"workers did not open: {missing[:3]}")
            time.sleep(0.05)
        go_file.write_text("1")

        time.sleep(4)
        for node in NODES:
            victim = processes[f"{node}-0"]
            victim.kill()
        time.sleep(2)
        (tmp_path / "rotate-round-0").write_text("1")

        survivors = {
            worker: process
            for worker, process in processes.items()
            if not worker.endswith("-0")
        }
        results = {}
        for worker, process in survivors.items():
            out, err = process.communicate(timeout=180)
            assert process.returncode == 0, (
                f"{worker} failed ({process.returncode})\n"
                f"stdout:\n{out}\nstderr:\n{err}"
            )
            results[worker] = json.loads(
                [line for line in out.splitlines() if line.strip()][-1]
            )
    finally:
        for process in processes.values():
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)
        bootstrap.close()

    for worker, result in results.items():
        assert not result["errors"], f"{worker}: {result['errors']}"
        assert result["writes"] > 0 and result["reads"] > 0

    # Verify on the mint owner's node.  A non-owner that has no live peer
    # must fetch the fleet key before it may open; after every process is
    # gone there is no peer to answer, by design.  The owner can read its
    # own mint record, so this checks durable records without that race.
    cert, key, _pin = identities["node-a"]
    verifier = Vault.open(
        _config(
            tmp_path, "node-a", endpoint, pins, cert, key, namespace=namespace
        ),
        _schema(),
    )
    try:
        assert verifier.get("sentinel").get_bytes("api_key") == b"survives the crash matrix"
        for worker in results:
            record_id = f"{worker}-0"
            assert (
                verifier.get(record_id).get_bytes("api_key")
                == f"secret-{worker}-{record_id}".encode()
            )
    finally:
        verifier.close()
        drop_namespace(endpoint, namespace)
