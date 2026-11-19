"""Open a vault and optionally finish a pending rotation, then wait to be killed."""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from security_gateway.vault import Config, FieldDef, Schema, Type, Vault
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.rotate import takeover_pending


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
        ],
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--node", required=True)
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--pin", required=True)
    parser.add_argument("--started", required=True)
    parser.add_argument("--action", choices=("open", "recover"), default="open")
    args = parser.parse_args()

    config = Config(
        data_dir=args.data_dir,
        multi_process=True,
        etcd=EtcdConfig(
            endpoints=(args.endpoint,),
            namespace=args.namespace,
            node_id=args.node,
            trusted_cert_sha256=(args.pin,),
            identity_cert_file=args.cert,
            identity_key_file=args.key,
            fetch_timeout=2.0,
        ),
    )
    Path(args.started).write_text("started", encoding="utf-8")
    vault = Vault.open(config, _schema())
    try:
        if args.action == "recover":
            takeover_pending(vault)
        time.sleep(30)
    finally:
        vault.close()


if __name__ == "__main__":
    main()
