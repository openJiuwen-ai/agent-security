"""A process that reaches one mint step and then waits to be killed.

The parent sends SIGKILL, so no cleanup and no key commit happens after the
ready marker. That is the point: the test is about what the etcd keyspace
says after a process dies at each step of the mint election.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

from security_gateway.vault.etcdstore.cluster import Cluster
from security_gateway.vault.etcdstore.store import Store


def _endpoint() -> tuple[str, int]:
    value = os.environ["MINT_ENDPOINT"].strip()
    for prefix in ("http://", "https://"):
        value = value.removeprefix(prefix)
    host, _, port = value.rstrip("/").partition(":")
    return host, int(port or 2379)


def _ready(payload: dict) -> None:
    Path(os.environ["MINT_READY"]).write_text(json.dumps(payload), encoding="utf-8")


def main() -> int:
    import etcd3

    host, port = _endpoint()
    namespace = os.environ["MINT_NS"]
    node_id = os.environ["MINT_NODE"]
    client = etcd3.Etcd3Client(host=host, port=port)
    try:
        store = Store.from_client(client, namespace)
        cluster = Cluster(store.kv, namespace, store.leases)
        mode = os.environ["MINT_MODE"]
        payload: dict[str, object] = {"node_id": node_id}
        if mode == "commit":
            payload["claimed"] = cluster.claim_mint(node_id)
        elif mode == "recover":
            payload["recovered"] = cluster.recover_mint(
                node_id,
                os.environ["MINT_PREVIOUS_OWNER"],
                int(os.environ["MINT_TARGET"]),
            )
        elif mode != "precommit":
            raise SystemExit(f"unknown MINT_MODE {mode!r}")
        _ready(payload)
        while True:
            time.sleep(60)
    finally:
        client.close()


if __name__ == "__main__":
    sys.exit(main())
