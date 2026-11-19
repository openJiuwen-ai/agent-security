"""One process of the multi-process vault fleet load test.

The process opens the vault the way the router does, then runs two
loops at once:

* a writer loop that keeps updating its own records and a shared
  "district" record, reading its own record back after every write;
* a rotation loop that asks for one rotation in each fleet-wide round;
  a lock or generation refusal is counted, not retried.

Every process does both, so there is no passive reader tier. The parent
releases all workers together and publishes rotation rounds one at a
time, making the lock contention simultaneous rather than incidental.

The settings arrive in environment variables because the parent process
starts nine of these and the arguments would otherwise be a second
configuration language.
"""

from __future__ import annotations

import json
import logging
import os
import sys
import threading
import time
import traceback
from pathlib import Path

from security_gateway.vault import Config, Schema, Type, Vault, rotate_dek
from security_gateway.vault.etcd import EtcdConfig, FencedWriteError
from security_gateway.vault.errors import (
    ConflictError,
    RotationInProgressError,
    StaleGenerationError,
)
from security_gateway.vault.record import Record, Value
from security_gateway.vault.schema import FieldDef

#: The record every process updates.  It is deliberately shared: the
#: compare-and-swap underneath has to carry concurrent writers, not just
#: one writer per key.
HOTSPOT = "district-1"


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
    pins = tuple(p for p in os.environ.get("FLEET_PINS", "").split(",") if p)
    return Vault.open(
        Config(
            data_dir=os.environ["FLEET_DIR"],
            multi_process=True,
            etcd=EtcdConfig(
                endpoints=(os.environ["FLEET_ENDPOINT"],),
                namespace=os.environ["FLEET_NS"],
                node_id=os.environ["FLEET_NODE"],
                trusted_cert_sha256=pins,
                identity_cert_file=os.environ["FLEET_CERT"],
                identity_key_file=os.environ["FLEET_KEY"],
                fetch_timeout=15.0,
            ),
        ),
        _schema(),
    )


def _rotate_loop(
    vault: Vault,
    result: dict,
    started: threading.Event,
    stop: threading.Event,
) -> None:
    """Rotate once in each round the parent publishes."""
    rounds = int(os.environ["FLEET_ROUNDS"])
    prefix = os.environ["FLEET_ROTATE_PREFIX"]
    ack_prefix = os.environ["FLEET_ACK_PREFIX"]
    try:
        if not started.wait(timeout=90):
            raise TimeoutError("the fleet did not start in time")
        for round_index in range(rounds):
            marker = Path(f"{prefix}{round_index}")
            while not marker.exists():
                if stop.is_set():
                    return
                time.sleep(0.1)
            result["attempts"] += 1
            try:
                authority = vault.authority
                if authority is None:
                    raise RuntimeError("the vault has no authority")
                rotate_dek(vault, authority.store)
            except (RotationInProgressError, StaleGenerationError, FencedWriteError):
                # The fleet lock or the generation fence says another
                # process moved first.  The attempt is what this test is
                # about; the unit test covers the sequential case where
                # every process gets its turn.
                result["retries"] += 1
            else:
                result["rotations"] += 1
            Path(f"{ack_prefix}{round_index}").write_text("1")
    except BaseException as exc:  # noqa: BLE001 - reported to the parent
        result["errors"].append(f"rotation {type(exc).__name__}: {exc}")
        result["rotation_traceback"] = traceback.format_exc()


LOGGER = logging.getLogger(__name__)
RESULT_LOGGER = logging.getLogger(__name__ + ".result")
RESULT_LOGGER.propagate = False
RESULT_LOGGER.setLevel(logging.INFO)
_result_handler = logging.StreamHandler(sys.stdout)
_result_handler.setFormatter(logging.Formatter("%(message)s"))
RESULT_LOGGER.addHandler(_result_handler)


def main() -> int:
    log_file = os.environ.get("FLEET_LOG_FILE")
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        filename=log_file,
        force=True,
    )
    worker = os.environ["FLEET_WORKER"]
    start_file = Path(os.environ["FLEET_GO_FILE"])
    deadline = time.monotonic() + float(os.environ.get("FLEET_OPEN_TIMEOUT", "90"))
    vault = _open()
    Path(os.environ["FLEET_ACK_PREFIX"] + "ready").write_text("1")
    result = {
        "worker": worker,
        "writes": 0,
        "reads": 0,
        "attempts": 0,
        "rotations": 0,
        "retries": 0,
        "conflicts": 0,
        "errors": [],
    }
    started = threading.Event()
    stop = threading.Event()
    rotator = threading.Thread(
        target=_rotate_loop,
        args=(vault, result, started, stop),
        name=f"rotate-{worker}",
    )
    rotator.start()
    try:
        while not start_file.exists():
            if time.monotonic() > deadline:
                raise TimeoutError("the fleet did not start in time")
            time.sleep(0.02)
        started.set()

        ids = [
            f"{worker}-{i}" for i in range(int(os.environ.get("FLEET_RECORDS", "6")))
        ]
        finish = time.monotonic() + float(os.environ["FLEET_SECONDS"])
        while time.monotonic() < finish:
            # The hotspot makes the nine processes contend on one key;
            # the per-worker records give every process private data to
            # read back while the rotations rewrite the whole namespace.
            try:
                vault.put(_record(HOTSPOT, f"hotspot-{worker}".encode()))
                result["writes"] += 1
            except ConflictError:
                # Nine processes updating one key is the point; a lost
                # race is reported, not fatal.
                result["conflicts"] += 1
            for record_id in ids:
                secret = f"secret-{worker}-{record_id}".encode()
                vault.put(_record(record_id, secret))
                result["writes"] += 1
                got = vault.get(record_id).get_bytes("api_key")
                if got != secret:
                    raise AssertionError(f"{record_id}: read {got!r}, want {secret!r}")
                result["reads"] += 1
            try:
                vault.get(HOTSPOT)
                result["reads"] += 1
            except Exception:  # noqa: BLE001 - the first writer may not be there yet
                pass
            time.sleep(0.1)

        # The writes stop first; the rotation rounds are still allowed to
        # finish while the process stays alive to acknowledge them.
        rotator.join(timeout=180.0)
        if rotator.is_alive():
            raise TimeoutError("the rotation rounds did not finish in time")
        if result["attempts"] != int(os.environ["FLEET_ROUNDS"]):
            raise AssertionError(
                f"the process made {result['attempts']} rotation attempts, "
                f"want {os.environ['FLEET_ROUNDS']}"
            )
    except BaseException as exc:  # noqa: BLE001 - reported to the parent
        result["errors"].append(f"{type(exc).__name__}: {exc}")
        result["traceback"] = traceback.format_exc()
    finally:
        stop.set()
        rotator.join(timeout=30.0)
    RESULT_LOGGER.info("%s", json.dumps(result))
    raise SystemExit(0 if not result["errors"] else 1)


if __name__ == "__main__":
    sys.exit(main())
