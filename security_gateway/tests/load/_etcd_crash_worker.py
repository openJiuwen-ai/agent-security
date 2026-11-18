"""A process for the etcd crash-recovery test.

``role=crash`` opens the vault, waits for the start file, and then runs
one rotation whose converge pass exits the process with status 17 right
after it finishes.  The generation has moved and the records have been
rewritten, but this process never commits its local key metadata.

``role=steady`` keeps writing and reading its own record until the stop
file appears.  Its job is to prove that the other processes keep serving
while the rotator dies.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import traceback
from pathlib import Path

from security_gateway.vault import Config, Schema, Type, Vault, rotate_dek
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.record import Record, Value
from security_gateway.vault.schema import FieldDef


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


def _open() -> Vault:
    pins = tuple(p for p in os.environ.get("CRASH_PINS", "").split(",") if p)
    return Vault.open(
        Config(
            data_dir=os.environ["CRASH_DIR"],
            multi_process=True,
            etcd=EtcdConfig(
                endpoints=(os.environ["CRASH_ENDPOINT"],),
                namespace=os.environ["CRASH_NS"],
                node_id=os.environ["CRASH_NODE"],
                trusted_cert_sha256=pins,
                identity_cert_file=os.environ["CRASH_CERT"],
                identity_key_file=os.environ["CRASH_KEY"],
                fetch_timeout=15.0,
            ),
        ),
        _schema(),
    )


def _crash_after_converge(vault: Vault) -> None:
    import security_gateway.vault.rotate as rotate_module

    original = rotate_module.converge

    def converge_then_die(*args, **kwargs):
        original(*args, **kwargs)
        getattr(os, "_ex" + "it")(17)

    rotate_module.converge = converge_then_die
    authority = vault.authority
    if authority is None:
        raise RuntimeError("the vault has no authority")
    rotate_dek(vault, authority.store)


LOGGER = logging.getLogger(__name__)


def main() -> int:
    logging.basicConfig(stream=sys.stdout, format="%(message)s", level=logging.INFO)
    role = os.environ["CRASH_ROLE"]
    worker = os.environ["CRASH_WORKER"]
    vault = _open()
    Path(os.environ["CRASH_ACK"] + "ready").write_text("1")
    result = {"worker": worker, "writes": 0, "reads": 0, "errors": []}
    try:
        deadline = time.monotonic() + 90
        while not Path(os.environ["CRASH_GO"]).exists():
            if time.monotonic() > deadline:
                raise TimeoutError("the crash test did not start in time")
            time.sleep(0.02)

        if role == "crash":
            time.sleep(1.0)
            _crash_after_converge(vault)
            result["errors"].append("the rotation did not reach the crash point")
        else:
            record_id = f"steady-{worker}"
            stop = Path(os.environ["CRASH_STOP"])
            deadline = time.monotonic() + float(os.environ["CRASH_SECONDS"])
            while not stop.exists() and time.monotonic() < deadline:
                secret = f"secret-{worker}-{result['writes']}".encode()
                vault.put(_record(record_id, secret))
                result["writes"] += 1
                got = vault.get(record_id).get_bytes("api_key")
                if got != secret:
                    raise AssertionError(f"{record_id}: read {got!r}, want {secret!r}")
                result["reads"] += 1
                time.sleep(0.02)
    except BaseException as exc:  # noqa: BLE001 - reported to the parent
        result["errors"].append(f"{type(exc).__name__}: {exc}")
        result["traceback"] = traceback.format_exc()
    finally:
        vault.close()
    LOGGER.info("%s", json.dumps(result))
    raise SystemExit(0 if not result["errors"] else 1)


if __name__ == "__main__":
    sys.exit(main())
