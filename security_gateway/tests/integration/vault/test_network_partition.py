"""A partition longer than a lease must fence the writer that stayed behind.

The proxy sits between one vault process and etcd.  While it is partitioned
the node's presence lease expires and another node rotates the fleet's DEK.
When the proxy comes back the old process must not be able to write under
its stale generation: it has to learn the new generation and fetch the key
before it can serve again.
"""

from __future__ import annotations

import os
import select
import socket
import threading
import time
import uuid
from contextlib import ExitStack, closing
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
    VaultError,
)
from security_gateway.vault.clusterdek import Fingerprint
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.rotate import rotate_dek

from ._etcd import drop_namespace

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"
NODES = ("node-a", "node-b")

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
        not os.environ.get(ETCD_ENDPOINT_ENV),
        reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
    ),
]


def _endpoint() -> tuple[str, int]:
    value = os.environ[ETCD_ENDPOINT_ENV].strip()
    for prefix in ("http://", "https://"):
        value = value.removeprefix(prefix)
    host, _, port = value.rstrip("/").partition(":")
    return host, int(port or 2379)


class Proxy:
    """A TCP proxy that can drop every connection and refuse new ones."""

    def __init__(self, host: str, port: int) -> None:
        self._upstream = (host, port)
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(16)
        self.port = self._listener.getsockname()[1]
        self._blocked = False
        self._connections: set[socket.socket] = set()
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept, daemon=True)
        self._thread.start()

    @property
    def endpoint(self) -> str:
        return f"127.0.0.1:{self.port}"

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            if self._blocked:
                client.close()
                continue
            upstream = socket.create_connection(self._upstream, timeout=2.0)
            with self._lock:
                self._connections.update((client, upstream))
            threading.Thread(
                target=self._pump, args=(client, upstream), daemon=True
            ).start()

    def _pump(self, left: socket.socket, right: socket.socket) -> None:
        sockets = (left, right)
        try:
            while not self._stop.is_set():
                readable, _, _ = select.select(sockets, (), (), 0.1)
                for source in readable:
                    data = source.recv(65536)
                    if not data:
                        return
                    (right if source is left else left).sendall(data)
        except OSError:
            return
        finally:
            with self._lock:
                self._connections.discard(left)
                self._connections.discard(right)
            for item in sockets:
                try:
                    item.close()
                except OSError:
                    pass

    def partition(self) -> None:
        self._blocked = True
        with self._lock:
            connections = list(self._connections)
        for item in connections:
            try:
                item.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                item.close()
            except OSError:
                pass

    def resume(self) -> None:
        self._blocked = False

    def close(self) -> None:
        self._stop.set()
        self.partition()
        self._listener.close()


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


def _vault(vaults: dict[str, Vault], node: str) -> Vault:
    vault = vaults.get(node)
    if vault is None:
        raise AssertionError(f"vault {node!r} is not open")
    return vault


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="endpoint", type=Type.STRING),
            FieldDef(name="api_key", type=Type.STRING, encrypted=True),
        ],
    )


def _record(record_id: str, secret: str) -> Record:
    return Record(
        id=record_id,
        fields={
            "endpoint": Value.new_string("https://api.example.test/v1"),
            "api_key": Value.new_string(secret),
        },
    )


def _config(
    directory: Path,
    node: str,
    endpoint: str,
    namespace: str,
    pins: tuple[Fingerprint, ...],
    cert: Path,
    key: Path,
) -> Config:
    return Config(
        data_dir=str(directory / node),
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(endpoint,),
            namespace=namespace,
            node_id=node,
            trusted_cert_sha256=pins,
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            identity_ca_file=str(cert),
            dial_timeout=0.5,
            fetch_timeout=10.0,
        ),
    )


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)
@pytest.mark.parametrize("partition_seconds", [16.0, 24.0])
def test_a_partitioned_writer_must_refresh_before_it_writes_again(
    tmp_path, partition_seconds
):
    host, port = _endpoint()
    namespace = "partition-" + uuid.uuid4().hex[:12]
    identities = {node: _identity(tmp_path, node) for node in NODES}
    pins = tuple(identity[2] for identity in identities.values())
    proxy = Proxy(host, port)
    try:
        cert, key, _pin = identities["node-a"]
        a = Vault.open(
            _config(tmp_path, "node-a", proxy.endpoint, namespace, pins, cert, key),
            _schema(),
        )
        try:
            cert, key, _pin = identities["node-b"]
            b = Vault.open(
                _config(tmp_path, "node-b", f"{host}:{port}", namespace, pins, cert, key),
                _schema(),
            )
            try:
                a.put(_record("sentinel", "before"))
                deadline = time.monotonic() + 30
                while True:
                    try:
                        if b.get("sentinel").get_string("api_key") == "before":
                            break
                    except Exception:  # noqa: BLE001, S110 - the key is still arriving
                        pass
                    if time.monotonic() > deadline:
                        raise AssertionError("node-b never saw the sentinel")
                    time.sleep(0.05)

                proxy.partition()
                time.sleep(partition_seconds)

                b.put(_record("after", "new"))
                rotate_dek(b, b.authority.store)

                with pytest.raises((VaultError, TimeoutError, OSError)):
                    a.put(_record("stale", "must-not-land"))
                with pytest.raises(NotFoundError):
                    b.get("stale")

                proxy.resume()
                deadline = time.monotonic() + 30
                while True:
                    try:
                        a.put(_record("stale", "after-refresh"))
                        break
                    except Exception:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(0.2)

                assert a.status().dek_version == b.status().dek_version
                assert a.get("stale").get_string("api_key") == "after-refresh"
            finally:
                b.close()
        finally:
            a.close()
    finally:
        proxy.close()
        drop_namespace(f"{host}:{port}", namespace)


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning"
)
def test_a_majority_of_three_nodes_still_fences_on_recovery(tmp_path):
    """Two of three nodes lose etcd; the survivor rotates and they must catch up.

    This is the client-side majority case: the etcd cluster itself is
    healthy, but most writers cannot reach it.  On recovery they must not
    keep writing under the generation they held while isolated.
    """
    host, port = _endpoint()
    namespace = "partition-majority-" + uuid.uuid4().hex[:12]
    nodes = ("node-a", "node-b", "node-c")
    identities = {node: _identity(tmp_path, node) for node in nodes}
    pins = tuple(identity[2] for identity in identities.values())
    proxies = {"node-a": Proxy(host, port), "node-b": Proxy(host, port)}
    vaults: dict[str, Vault] = {}
    stack = ExitStack()
    try:
        for node in nodes:
            endpoint = (
                proxies[node].endpoint if node in proxies else f"{host}:{port}"
            )
            cert, key, _pin = identities[node]
            vaults[node] = stack.enter_context(
                closing(
                    Vault.open(
                        _config(tmp_path, node, endpoint, namespace, pins, cert, key),
                        _schema(),
                    )
                )
            )

        node_c = _vault(vaults, "node-c")
        _vault(vaults, "node-a").put(_record("sentinel", "before"))
        deadline = time.monotonic() + 30
        while True:
            try:
                if node_c.get("sentinel").get_string("api_key") == "before":
                    break
            except Exception:  # noqa: BLE001, S110 - the key is still arriving
                pass
            if time.monotonic() > deadline:
                raise AssertionError("node-c never saw the sentinel")
            time.sleep(0.05)

        for proxy in proxies.values():
            proxy.partition()
        time.sleep(16)

        node_c.put(_record("after", "new"))
        rotate_dek(node_c, node_c.authority.store)

        for node in proxies:
            with pytest.raises((VaultError, TimeoutError, OSError)):
                _vault(vaults, node).put(_record("stale", "must-not-land"))
        with pytest.raises(NotFoundError):
            node_c.get("stale")

        for proxy in proxies.values():
            proxy.resume()
        deadline = time.monotonic() + 30
        for node in proxies:
            while True:
                try:
                    _vault(vaults, node).put(_record("stale", f"after-{node}"))
                    break
                except Exception:
                    if time.monotonic() > deadline:
                        raise
                    time.sleep(0.2)
            expected = node_c.status().dek_version
            assert _vault(vaults, node).status().dek_version == expected
            assert _vault(vaults, node).get("stale").get_string("api_key") == f"after-{node}"
    finally:
        stack.close()
        for proxy in proxies.values():
            proxy.close()
        drop_namespace(f"{host}:{port}", namespace)
