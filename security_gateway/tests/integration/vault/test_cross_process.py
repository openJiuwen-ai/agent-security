"""Cross-process scenarios on a single-node vault data directory.

These are the end-to-end cases the unit suite approximates with several
``Vault`` objects in one process: a second OS process reads, deletes and
lists; a long-lived reader keeps serving across a rotation; and several
writer processes race a rotation.  The malformed-container cases use the
public API after damaging the row on disk.
"""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from tests.integration.vault.conftest import (
    finish_worker,
    run_worker,
    start_worker,
    wait_for,
)

from security_gateway.vault import (
    Config,
    FieldDef,
    InvalidRecordError,
    KeyMismatchError,
    NotFoundError,
    Record,
    Schema,
    Type,
    Value,
    Vault,
    rotate_dek,
)


def _schema(version: int = 1) -> Schema:
    return Schema(
        version=version,
        fields=[
            FieldDef(name="endpoint", type=Type.STRING),
            FieldDef(name="api_key", type=Type.STRING, encrypted=True),
            FieldDef(name="created_at", type=Type.INT64),
        ],
    )


def _open(data_dir: Path) -> Vault:
    return Vault.open(Config(data_dir=str(data_dir), multi_process=True), _schema())


def _record(record_id: str, secret: str) -> Record:
    rec = Record(id=record_id)
    rec.set("endpoint", Value.new_string("https://api.example.test/v1"))
    rec.set("api_key", Value.new_string(secret))
    rec.set("created_at", Value.new_int64(1_700_000_000))
    return rec


def _raw_record(data_dir: Path, record_id: str) -> bytes:
    db = data_dir / "vault.db"
    with sqlite3.connect(f"file:{db}?mode=ro", uri=True) as conn:
        row = conn.execute(
            "select data from vault_record where id = ?", (record_id,)
        ).fetchone()
    assert row is not None, f"record {record_id} is absent"
    return row[0]


def _write_raw_record(data_dir: Path, record_id: str, data: bytes) -> None:
    with sqlite3.connect(data_dir / "vault.db") as conn:
        conn.execute(
            "update vault_record set data = ? where id = ?", (data, record_id)
        )
        conn.commit()


def test_another_process_reads_deletes_and_lists(data_dir: Path) -> None:
    vault = _open(data_dir)
    try:
        vault.put(_record("user/alice/openai", "sk-alice"))
        vault.put(_record("user/bob/openai", "sk-bob"))
    finally:
        vault.close()

    result = run_worker(
        "read",
        "--data-dir",
        data_dir,
        "--ids",
        "user/alice/openai,user/bob/openai",
    )
    assert result["errors"] == {}
    assert result["values"] == {
        "user/alice/openai": "sk-alice",
        "user/bob/openai": "sk-bob",
    }

    listed = run_worker("list", "--data-dir", data_dir, "--prefix", "user/")
    assert listed["ids"] == ["user/alice/openai", "user/bob/openai"]
    assert listed["fields"]["user/alice/openai"] == ["created_at", "endpoint"]

    run_worker("delete", "--data-dir", data_dir, "--ids", "user/alice/openai")

    result = run_worker(
        "read",
        "--data-dir",
        data_dir,
        "--ids",
        "user/alice/openai,user/bob/openai",
    )
    assert result["errors"] == {"user/alice/openai": "not_found"}
    assert result["values"] == {"user/bob/openai": "sk-bob"}

    vault = _open(data_dir)
    try:
        with pytest.raises(NotFoundError):
            vault.get("user/alice/openai")
    finally:
        vault.close()


def test_a_reader_keeps_serving_across_a_rotation(
    data_dir: Path, control_dir: Path
) -> None:
    vault = _open(data_dir)
    try:
        vault.put(_record("user/old/openai", "sk-old"))
    finally:
        vault.close()

    ready = control_dir / "reader-ready"
    go = control_dir / "reader-go"
    reader = start_worker(
        "reader",
        "--data-dir",
        data_dir,
        "--ids",
        "user/old/openai,user/new/openai",
        "--ready",
        ready,
        "--go",
        go,
    )
    try:
        wait_for(ready)

        vault = _open(data_dir)
        try:
            rotate_dek(vault)
            vault.put(_record("user/new/openai", "sk-new"))
        finally:
            vault.close()

        go.write_text("go", encoding="utf-8")
        result = finish_worker(reader)
    finally:
        if reader.poll() is None:
            reader.kill()
            reader.communicate()

    assert result["errors"] == {}
    assert result["values"] == {
        "user/old/openai": "sk-old",
        "user/new/openai": "sk-new",
    }


def test_three_writers_race_a_rotation(data_dir: Path, control_dir: Path) -> None:
    _open(data_dir).close()

    writers = []
    for index in range(3):
        started = control_dir / f"writer-{index}-started"
        writers.append(
            start_worker(
                "write",
                "--data-dir",
                data_dir,
                "--prefix",
                f"writer{index}",
                "--count",
                20,
                "--delay",
                0.005,
                "--started",
                started,
            )
        )
    try:
        for index in range(3):
            wait_for(control_dir / f"writer-{index}-started")

        vault = _open(data_dir)
        try:
            rotate_dek(vault)
        finally:
            vault.close()

        results = [finish_worker(writer) for writer in writers]
    finally:
        for writer in writers:
            if writer.poll() is None:
                writer.kill()
                writer.communicate()

    ids = [record_id for result in results for record_id in result["ids"]]
    assert len(ids) == 60

    vault = _open(data_dir)
    try:
        status = vault.status()
        assert status.record_count == 60
        assert status.straggler_count == 0
        for result in results:
            for record_id in result["ids"]:
                suffix = record_id.rsplit("-", 1)[-1]
                assert vault.get(record_id).get_string("api_key") == f"secret-{suffix}"
    finally:
        vault.close()


def _damage_container(data_dir: Path, mutate) -> None:
    vault = _open(data_dir)
    try:
        vault.put(_record("user/alice/openai", "sk-alice"))
    finally:
        vault.close()

    blob = _raw_record(data_dir, "user/alice/openai")
    _write_raw_record(data_dir, "user/alice/openai", mutate(blob))

    vault = _open(data_dir)
    try:
        with pytest.raises(InvalidRecordError, match="decode record"):
            vault.get("user/alice/openai")
    finally:
        vault.close()


def test_malformed_container_is_invalid_record(data_dir: Path) -> None:
    _damage_container(data_dir, lambda blob: b"XXXX" + blob[4:])


def test_truncated_container_is_invalid_record(data_dir: Path) -> None:
    _damage_container(data_dir, lambda blob: blob[: len(blob) // 2])


def test_removing_one_key_shard_is_a_key_mismatch(data_dir: Path) -> None:
    vault = _open(data_dir)
    try:
        vault.put(_record("user/alice/openai", "sk-alice"))
    finally:
        vault.close()

    shard = data_dir / "secrets" / "s1.bin.1"
    assert shard.exists()
    os.remove(shard)

    with pytest.raises(KeyMismatchError):
        _open(data_dir)
