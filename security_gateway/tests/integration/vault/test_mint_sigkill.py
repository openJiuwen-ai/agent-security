"""SIGKILL a process at each step of the first-mint protocol.

The first mint is only a promise once the process has a durable local key.
The tests kill a real process before the permanent mint, after it, and after
recovering a mint whose owner disappeared. They need a real etcd for the
transaction semantics.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest

from security_gateway.vault.etcdstore.cluster import Cluster
from security_gateway.vault.etcdstore.cluster_keys import mint_key
from security_gateway.vault.etcdstore.store import Store

ETCD_ENDPOINT_ENV = "CRED_ROUTER_ETCD_ENDPOINT"
WORKER = Path(__file__).with_name("_mint_worker.py")

pytestmark = [
    pytest.mark.slow,
    pytest.mark.skipif(
    not os.environ.get(ETCD_ENDPOINT_ENV),
    reason="a real etcd is needed; set CRED_ROUTER_ETCD_ENDPOINT",
)
]


def _endpoint() -> tuple[str, int]:
    value = os.environ[ETCD_ENDPOINT_ENV].strip()
    for prefix in ("http://", "https://"):
        value = value.removeprefix(prefix)
    host, _, port = value.rstrip("/").partition(":")
    return host, int(port or 2379)


@pytest.fixture
def namespace():
    return "mint-kill-" + uuid.uuid4().hex[:12]


@pytest.fixture
def control(namespace):
    import etcd3

    host, port = _endpoint()
    client = etcd3.Etcd3Client(host=host, port=port)
    store = Store.from_client(client, namespace)
    try:
        yield Cluster(store.kv, namespace, store.leases)
    finally:
        client.delete_prefix(f"/security_gateway/{namespace}/")
        client.close()


def _kill_at(
    tmp_path: Path,
    namespace: str,
    mode: str,
    *,
    previous_owner: str = "",
    target: int = 0,
) -> dict:
    ready = tmp_path / f"{mode}-ready"
    env = dict(os.environ)
    env.update(
        {
            "MINT_ENDPOINT": os.environ[ETCD_ENDPOINT_ENV],
            "MINT_NS": namespace,
            "MINT_NODE": "node-a",
            "MINT_MODE": mode,
            "MINT_READY": str(ready),
        }
    )
    if previous_owner:
        env["MINT_PREVIOUS_OWNER"] = previous_owner
        env["MINT_TARGET"] = str(target)

    process = subprocess.Popen(
        [sys.executable, str(WORKER)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 60
        while not ready.exists():
            if process.poll() is not None:
                out, err = process.communicate()
                raise AssertionError(
                    f"the mint worker died before {mode!r}\nstdout:\n{out}\nstderr:\n{err}"
                )
            if time.monotonic() > deadline:
                raise AssertionError(f"the mint worker did not reach {mode!r}")
            time.sleep(0.02)
        payload = json.loads(ready.read_text(encoding="utf-8"))
    finally:
        if process.poll() is None:
            os.kill(process.pid, signal.SIGKILL)
        process.communicate(timeout=30)
    return payload


def test_a_kill_before_the_mint_leaves_the_field_open(tmp_path, namespace, control):
    payload = _kill_at(tmp_path, namespace, "precommit")
    assert payload["node_id"] == "node-a"

    assert control.claim_mint("node-b") is True
    assert control.mint_owner() == "node-b"


def test_a_kill_after_the_mint_keeps_the_owner_and_blocks_a_second_one(
    tmp_path, namespace, control
):
    payload = _kill_at(tmp_path, namespace, "commit")
    assert payload["claimed"] is True

    assert control.generation() == 1
    assert control.mint_owner() == "node-a"
    assert control.claim_mint("node-b") is False

    claimed = control.kv.get(mint_key(namespace))
    assert claimed is not None and claimed.value == b"node-a"


def test_a_kill_after_recover_keeps_the_new_owner_and_generation(
    tmp_path, namespace, control
):
    assert control.claim_mint("node-old") is True
    control.ensure_generation()

    payload = _kill_at(
        tmp_path,
        namespace,
        "recover",
        previous_owner="node-old",
        target=2,
    )
    assert payload["recovered"] is True

    assert control.generation() == 2
    assert control.mint_owner() == "node-a"
    assert control.claim_mint("node-b") is False
