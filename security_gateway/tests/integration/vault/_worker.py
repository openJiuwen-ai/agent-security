"""A process the cross-process vault tests drive over a shared data directory.

Every scenario crosses a real OS process boundary.  The worker uses only the
public ``security_gateway.vault`` API and writes one JSON object to stdout.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

from security_gateway.vault import (
    Config,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
    rotate_dek,
)


def _schema(version: int = 1, extra_field: bool = False) -> Schema:
    fields = [
        FieldDef(name="endpoint", type=Type.STRING),
        FieldDef(name="api_key", type=Type.STRING, encrypted=True),
        FieldDef(name="created_at", type=Type.INT64),
    ]
    if extra_field:
        fields.append(FieldDef(name="owner", type=Type.STRING))
    return Schema(version=version, fields=fields)


def _open(data_dir: str, version: int = 1, extra_field: bool = False) -> Vault:
    return Vault.open(
        Config(data_dir=data_dir, multi_process=True),
        _schema(version, extra_field),
    )


def _record(record_id: str, secret: str, owner: str | None = None) -> Record:
    rec = Record(id=record_id)
    rec.set("endpoint", Value.new_string("https://api.example.test/v1"))
    rec.set("api_key", Value.new_string(secret))
    rec.set("created_at", Value.new_int64(1_700_000_000))
    if owner is not None:
        rec.set("owner", Value.new_string(owner))
    return rec


def _touch(path: str | None) -> None:
    if path:
        Path(path).write_text("ready", encoding="utf-8")


def _wait(path: str, timeout: float = 30.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if Path(path).exists():
            return
        time.sleep(0.01)
    raise TimeoutError(f"timed out waiting for {path}")


LOGGER = logging.getLogger(__name__)


def _emit(payload: dict) -> None:
    LOGGER.info("%s", json.dumps(payload, sort_keys=True))


def _read(vault: Vault, ids: list[str]) -> dict:
    values: dict[str, str | None] = {}
    errors: dict[str, str] = {}
    for record_id in ids:
        try:
            values[record_id] = vault.get(record_id).get_string("api_key")
        except Exception as exc:  # noqa: BLE001 - the error code is the assertion
            errors[record_id] = getattr(exc, "code", type(exc).__name__)
    return {"values": values, "errors": errors}


def _write(
    vault: Vault,
    prefix: str,
    count: int,
    secret_prefix: str,
    delay: float = 0.0,
    started: str | None = None,
) -> list[str]:
    ids: list[str] = []
    for index in range(count):
        record_id = f"{prefix}-{index:03d}"
        vault.put(_record(record_id, f"{secret_prefix}-{index:03d}"))
        ids.append(record_id)
        if index == 0:
            _touch(started)
        elif delay:
            time.sleep(delay)
    return ids


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(stream=sys.stdout, format="%(message)s", level=logging.INFO)
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["write", "read", "reader", "delete", "list", "rotate"])
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--version", type=int, default=1)
    parser.add_argument("--extra-field", action="store_true")
    parser.add_argument("--prefix", default="record")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--secret-prefix", default="secret")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--ids", default="")
    parser.add_argument("--ready")
    parser.add_argument("--started")
    parser.add_argument("--go")
    args = parser.parse_args(argv)

    vault = _open(args.data_dir, args.version, args.extra_field)
    try:
        if args.role == "write":
            ids = _write(
                vault,
                args.prefix,
                args.count,
                args.secret_prefix,
                args.delay,
                args.started,
            )
            _emit({"ok": True, "ids": ids})
            return 0

        if args.role == "read":
            ids = [item for item in args.ids.split(",") if item]
            _emit(_read(vault, ids))
            return 0

        if args.role == "delete":
            ids = [item for item in args.ids.split(",") if item]
            for record_id in ids:
                vault.delete(record_id)
            _emit({"ok": True})
            return 0

        if args.role == "list":
            entries = vault.list(args.prefix)
            _emit(
                {
                    "ids": [entry.id for entry in entries],
                    "fields": {entry.id: sorted(entry.fields) for entry in entries},
                }
            )
            return 0

        if args.role == "rotate":
            rotate_dek(vault)
            _emit({"ok": True, "dek_version": vault.status().dek_version})
            return 0

        # reader: open the store first, then let the parent rotate/write while
        # this process keeps its original key snapshot.
        _touch(args.ready)
        if not args.go:
            raise SystemExit("reader requires --go")
        _wait(args.go)
        ids = [item for item in args.ids.split(",") if item]
        _emit(_read(vault, ids))
        return 0
    finally:
        vault.close()


if __name__ == "__main__":
    sys.exit(main())
