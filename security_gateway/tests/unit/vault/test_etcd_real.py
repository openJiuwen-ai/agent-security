"""The vault's etcd authority, against a **real** etcd.

The Go counterpart is ``tests/integration/vault_etcd_test.go``, which starts
an embedded etcd and drives the vault against it.

Everything else in this package's etcd tests runs against a fake, and the
fake is faithful about the compare-and-swap — but a fake is a
reimplementation.  What this file checks is the thing the fake stands in
for: a real etcd, a real lease, a real watch stream and a real
compare-and-swap, with the vault's own etcd half in front of them.

The tests are skipped unless ``CRED_ROUTER_ETCD_ENDPOINT`` names an etcd,
in the ``host:port`` form the client takes.  That is the same gate the
credential manager's sync tests use, and the same variable the etcd client
contract names.

A namespace is minted per test, so a run against a shared etcd does not
have its tests step on each other.
"""

from __future__ import annotations

import os
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from security_gateway.vault import rotate
from security_gateway.vault.clusterkey.clusterkey import ClusterKeyError
from security_gateway.vault.errors import KeyMismatchError
from security_gateway.vault.etcd import EtcdConfig, FencedWriteError
from security_gateway.vault.etcdstore.errors import NotFoundError as StoreNotFoundError
from security_gateway.vault.record import Record, Value
from security_gateway.vault.vault import Config as VaultConfig
from security_gateway.vault.vault import Vault

from .conftest import make_test_schema

#: The endpoint a real etcd is at, in the ``host:port`` form the client
#: takes.  The tests that need a real server are skipped when it is not set.
ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"

pytestmark = pytest.mark.skipif(
    not os.environ.get(ETCD_ENDPOINT_ENV),
    reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
)


def _identity(directory) -> tuple[str, str]:
    """A self-signed client identity for the vault's cluster key."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vault-test")])
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
    cert_file = directory / "client.crt"
    key_file = directory / "client.key"
    cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_file.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return str(cert_file), str(key_file)


def _endpoint() -> str:
    """The endpoint, with the scheme the client does not want removed."""
    value = os.environ[ETCD_ENDPOINT_ENV].strip()
    for prefix in ("http://", "https://"):
        if value.startswith(prefix):
            value = value[len(prefix):]
    return value.rstrip("/")


def _record(record_id: str, secret: str) -> Record:
    """A record of the shape the test schema declares."""
    return Record(
        id=record_id,
        fields={
            "endpoint": Value.new_string("https://api.example.test/v1"),
            "api_key": Value.new_string(secret),
        },
    )


@pytest.fixture
def namespace() -> str:
    """A namespace of this test's own."""
    return "vaulttest-" + uuid.uuid4().hex[:12]


def _etcd_cfg(tmp_path, namespace: str, node_id: str = "vault-test") -> EtcdConfig:
    """An etcd config with this node's identity and the test CA."""
    cert_file, key_file = _identity(tmp_path)
    return EtcdConfig(
        endpoints=(_endpoint(),),
        namespace=namespace,
        node_id=node_id,
        identity_cert_file=cert_file,
        identity_key_file=key_file,
        identity_ca_file=cert_file,
        fetch_timeout=3.0,
    )


@pytest.fixture
def vault(tmp_path, namespace):
    """A vault whose records live in a real etcd."""
    store = Vault.open(
        VaultConfig(
            data_dir=str(tmp_path / "vault"),
            etcd=_etcd_cfg(tmp_path, namespace),
        ),
        make_test_schema(),
    )
    try:
        yield store
    finally:
        store.close()


def _store(namespace: str):
    """A store over the real etcd, for the facts the vault writes itself."""
    import etcd3
    from security_gateway.vault.etcdstore import split_endpoint
    from security_gateway.vault.etcdstore.cluster import generation_key
    from security_gateway.vault.etcdstore.store import Store

    host, port = split_endpoint(_endpoint())
    client = etcd3.Etcd3Client(host=host, port=int(port or 2379), timeout=5.0)
    return Store.from_client(
        client, namespace, generation_key=generation_key(namespace)
    )


def _wait_for(predicate, timeout: float = 15.0) -> bool:
    """Wait until a predicate holds.

    The mirror catches up through a watch, so a fact that lives in the
    authority takes a moment to reach the local copy.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_a_write_reaches_the_authority_and_reads_back(vault):
    """A write goes to the authority, and the local copy has it at once.

    The write applies to the local mirror as well as to the authority, so
    a read right after a write sees it: the watch would deliver it too, but
    not before the caller asks.
    """
    vault.put(_record("cred-1", "sk-secret"))

    entry = vault.authority.store.get_record("cred-1")
    assert entry.data, "the authority holds an empty payload"
    assert entry.schema_version == 1

    record = vault.get("cred-1")
    assert record.get_string("api_key") == "sk-secret"


def test_a_delete_removes_the_record_from_the_authority(vault):
    """A delete goes to the authority, not only to the local copy."""
    vault.put(_record("cred-1", "sk-secret"))
    vault.delete("cred-1")

    with pytest.raises(StoreNotFoundError):
        vault.authority.store.get_record("cred-1")


def test_the_generation_fence_refuses_a_writer_that_is_behind(vault, namespace):
    """A writer the authority has left behind is refused, not silently dropped.

    The fence is the authority's compare-and-swap: the writer says which
    generation it holds, and the authority compares it with its own.  A
    writer that is behind is told so, because "refused" and "written" are
    different answers and only one of them is true.
    """
    vault.put(_record("cred-1", "sk-secret"))

    # The authority's generation moves on — a rotation, or another node.
    vault.authority.advance_generation(2)

    with pytest.raises(FencedWriteError) as caught:
        vault.put(_record("cred-2", "sk-other"))
    assert "generation" in str(caught.value)


def test_a_second_node_without_a_trusted_identity_is_refused(vault, tmp_path, namespace):
    """A peer holding another self-signed identity is refused at handover."""
    vault.put(_record("cred-1", "sk-secret"))
    with pytest.raises((KeyMismatchError, ClusterKeyError, TimeoutError)):
        reader = Vault.open(
            VaultConfig(
                data_dir=str(tmp_path / "reader"),
                etcd=_etcd_cfg(tmp_path, namespace, "reader"),
            ),
            make_test_schema(),
            _allow_duplicate=True,
        )
        try:
            reader.get("cred-1")
        finally:
            reader.close()


def test_a_rotation_in_the_etcd_mode_moves_the_generation(vault):
    """The etcd mode's rotation moves the authority's generation.

    This is the path the local-authority model deliberately left alone:
    in the etcd mode the authority arbitrates the rotation across the
    fleet and moves the generation fence, and the records are re-encrypted
    in the authority rather than in a local database.

    It is also the path that needs a **lease**: the rotation lock is a
    leased key, so a holder that disappears frees it without anybody
    having to notice.
    """
    vault.put(_record("cred-1", "sk-secret"))
    before = vault.authority.generation()

    rotate.rotate_dek(vault, vault.authority.store)

    after = vault.authority.generation()
    assert after != before, "the rotation did not move the authority's generation"

    # The record is still readable: the rotation re-encrypted it in the
    # authority, and the node's own key followed the generation.
    record = vault.get("cred-1")
    assert record.get_string("api_key") == "sk-secret"


def test_the_fleet_rotation_gate_is_seeded_when_the_fleet_forms(vault, namespace):
    """A namespace that has never rotated gets a gate, and it is fresh.

    The gate is the fleet's one answer to "when did the fleet last
    rotate".  Without it the first tick of a fresh fleet rotates the
    fleet before the other nodes have joined, and a node that joins
    afterwards finds the authority one generation ahead of the key it can
    hold — it refuses to start.  The seed is what makes a fresh fleet wait
    a whole period before its first rotation.

    The Go's counterpart is ``tests/integration/vault_fleet_gate_test.go``.
    """
    from security_gateway.vault.etcdstore import last_rotation_at

    store = vault.authority.store
    at = last_rotation_at(store.kv, store.ns)
    assert at is not None, (
        "the fleet's rotation gate was not seeded when the fleet formed"
    )
    assert (datetime.now(timezone.utc) - at) < timedelta(minutes=1), (
        f"the gate was seeded at {at}, not when the fleet formed"
    )


def test_the_fleet_rotation_gate_of_a_fleet_that_has_rotated_is_not_moved(
    tmp_path, namespace
):
    """The seed is for a fleet that has not rotated yet.

    A namespace that already holds a gate keeps it: the fleet rotated at
    that moment, and the seed is not allowed to claim it never did.
    Otherwise every node that opened the store would reset the gate, and
    a fleet that rotates on a schedule would never be due — each node's
    open would push the next rotation a whole period out.

    The Go's counterpart is ``tests/integration/vault_fleet_gate_test.go``.
    """
    from security_gateway.vault.etcdstore import last_rotation_at, set_last_rotation_at

    store = _store(namespace)
    rotated_at = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(hours=2)
    set_last_rotation_at(store.kv, store.ns, rotated_at)

    opened = Vault.open(
        VaultConfig(
            data_dir=str(tmp_path / "vault"),
            etcd=_etcd_cfg(tmp_path, namespace),
        ),
        make_test_schema(),
    )
    try:
        gate = last_rotation_at(store.kv, store.ns)
    finally:
        opened.close()

    assert abs((gate - rotated_at).total_seconds()) < 1.0, (
        f"the gate of a fleet that had rotated was moved: {rotated_at} -> {gate}"
    )


def test_the_rotation_lock_is_exclusive_against_a_real_etcd(vault, namespace):
    """The rotation lock is one holder at a time, and it is really leased.

    The lock is a leased key: revoking the lease deletes it.  That is what
    makes a holder that disappears harmless — nobody has to notice that it
    is gone, and nobody has to clean up after it.
    """
    from security_gateway.vault.etcdstore import (
        acquire_rotation_lock,
        rotation_lock_held,
    )
    from security_gateway.vault.etcdstore.errors import RotationHeldError

    store = vault.authority.store
    leases = store.leases
    assert leases is not None, "the store over a live etcd carries no leases"

    lock = acquire_rotation_lock(store.kv, leases, namespace, "node-a", 30)
    try:
        assert rotation_lock_held(store.kv, namespace)
        with pytest.raises(RotationHeldError):
            acquire_rotation_lock(store.kv, leases, namespace, "node-b", 30)
    finally:
        lock.release()

    # The key is gone, and so is the lock: the lease took the key with it.
    assert not rotation_lock_held(store.kv, namespace)
    second = acquire_rotation_lock(store.kv, leases, namespace, "node-b", 30)
    second.release()


def test_a_presence_marker_dies_with_its_lease(vault, namespace):
    """A node's presence marker is a leased write, and it says so.

    A presence marker written without its lease would mark a dead node
    present for ever, and the rotation barrier would read that as absence
    of a stall — so the lease is the whole point of the write.
    """
    from security_gateway.vault.etcdstore.cluster import Cluster

    store = vault.authority.store
    leases = store.leases
    cluster = Cluster(store.kv, namespace, leases)

    lease_id = cluster.put_presence("node-a", 1, 30)
    assert lease_id, "the presence marker was not leased"

    present = cluster.list_present()
    assert present.get("node-a") == 1, f"the presence marker is not there: {present}"

    cluster.drop_presence(lease_id)
    assert "node-a" not in cluster.list_present(), "the presence marker outlived its lease"
