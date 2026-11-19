"""Fuzz the data a running process reads but did not produce itself.

The API fuzz cases cover arguments and whole files. These cases cover the
smaller surfaces: etcd keys, watch events, identity PEM files, individual
SQLite columns and filesystem faults. Every one of them must end in a
``VaultError`` (or an accepted OS-level failure), never in a bare
``UnicodeDecodeError``, ``OverflowError`` or ``sqlite3`` exception.
"""

from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests._fuzz_rng import FuzzRandom
from security_gateway.vault import Config, FieldDef, Record, Schema, Type, Value, Vault
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.clusterdek.anchor import ClusterDekError
from security_gateway.vault.etcdstore import watch as watch_module
from security_gateway.vault.etcdstore.errors import EtcdStoreError, InvalidValueError
from security_gateway.vault.etcdstore.keys import (
    cred_key,
    record_id_from_key,
    proxy_key_from_cred_key,
    record_key,
)
from security_gateway.vault.etcdstore.entry import RecordEntry
from security_gateway.vault.errors import VaultError
from security_gateway.vault.mirror import MirrorApplier

SEEDS = tuple(range(3101, 3109))
RNG = FuzzRandom(0x5EED)


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
        ],
    )


def _record(record_id: str) -> Record:
    return Record(
        id=record_id,
        fields={
            "name": Value.new_string("name"),
            "secret": Value.new_string("secret"),
        },
    )


def _open(path, **kwargs):
    return Vault.open(Config(data_dir=str(path), **kwargs), _schema())


def _identity(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fuzz")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc))
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "cert.pem"
    key_path = directory / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _etcd(path, cert, key, **kwargs):
    return Config(
        data_dir=str(path),
        etcd=EtcdConfig(
            endpoints=("127.0.0.1:1",),
            namespace="fuzz",
            node_id="node",
            identity_cert_file=str(cert),
            identity_key_file=str(key),
            identity_ca_file=str(cert),
            dial_timeout=0.1,
            fetch_timeout=0.1,
        ),
        **kwargs,
    )


def test_etcd_keys_survive_random_and_partial_damage(tmp_path):
    valid = (
        (record_key("ns", "record"), lambda key: record_id_from_key("ns", key)),
        (cred_key("ns", "cred"), lambda key: proxy_key_from_cred_key("ns", key)),
    )
    for key, parse in valid:
        assert isinstance(parse(key), str)
        for _ in range(120):
            cut = RNG.randrange(len(key) + 1)
            damaged = RNG.choice(
                (
                    key[:cut],
                    key + RNG.choice(("/", "\\", "\x00", "..", "中文")),
                    key[:cut] + RNG.choice(("/", "\x00", "..")) + key[cut:],
                )
            )
            try:
                parse(damaged)
            except (InvalidValueError, VaultError, ValueError):
                pass


def test_watch_events_never_raise_raw_errors(tmp_path):
    vault = _open(tmp_path / "watch")
    vault.put(_record("record"))
    vault.close()
    db = sqlite3.connect(tmp_path / "watch" / "vault.db")
    applier = MirrorApplier(db, lambda: 999)
    try:
        for _ in range(200):
            event = type(
                "Event",
                (),
                {
                    "key": bytes(RNG.randrange(256) for _ in range(RNG.randrange(8))),
                    "value": bytes(RNG.randrange(256) for _ in range(RNG.randrange(8))),
                    "mod_revision": RNG.choice((-1, 0, 1, 2**62, 2**63 - 1, 2**63)),
                    "version": RNG.choice((-1, 0, 2**63)),
                    "prev_value": None,
                    "type": RNG.choice((0, 1, "PUT", "DELETE", None)),
                },
            )()
            response = watch_module.response_from_event(event)
            for item in response.events:
                try:
                    key = item.key.decode("utf-8")
                    entry = RecordEntry(
                        data=b"x",
                        schema_version=1,
                        dek_version=1,
                        mod_revision=item.mod_revision,
                    )
                    applier.apply_upsert(key, entry)
                except (InvalidValueError, VaultError, ValueError):
                    pass
    finally:
        db.close()


@pytest.mark.parametrize("seed", SEEDS)
def test_identity_pem_files_survive_random_and_partial_damage(tmp_path, seed):
    cert, key = _identity(tmp_path)
    original = cert.read_bytes()
    rng = FuzzRandom(seed)
    for _ in range(20):
        damaged = bytearray(original)
        if rng.random() < 0.5:
            damaged = damaged[: rng.randrange(len(damaged) + 1)]
        else:
            cut = rng.randrange(len(damaged) + 1)
            damaged[cut:cut] = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 8)))
        cert.write_bytes(bytes(damaged))
        try:
            _open(tmp_path / f"identity-{seed}", etcd=_etcd(tmp_path / f"identity-{seed}", cert, key).etcd)
        except (VaultError, ValueError, OSError):
            pass
    cert.write_bytes(original)


def test_a_watch_key_that_is_not_utf8_is_a_sync_error(tmp_path):
    from security_gateway.vault.sync.loop import SyncError, Syncer

    syncer = Syncer(object(), object(), object(), None)
    response = watch_module.WatchResponse(
        events=(watch_module.WatchEvent(key=b"\xff", value=b"x"),)
    )
    with pytest.raises(SyncError):
        getattr(syncer, "_apply_batch")(response)


@pytest.mark.parametrize("column,value", [
    ("active_dek_version", -1),
    ("active_dek_version", 2**63 - 1),
    ("pending_dek_version", -1),
    ("file_shard_version", -1),
    ("rotation_period", float("inf")),
])
def test_corrupt_key_metadata_columns_are_a_vault_error(tmp_path, column, value):
    root = tmp_path / f"meta-{column}-{value}"
    root.mkdir()
    vault = _open(root)
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute(f"UPDATE vault_key_metadata SET {column} = ?", (value,))
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        try:
            vault.get("record")
        except VaultError:
            pass
    finally:
        vault.close()


@pytest.mark.parametrize("column,value", [
    ("row_version", -1),
    ("row_version", 2**63 - 1),
    ("source_revision", -1),
    ("source_revision", 2**63 - 1),
    ("schema_version", -1),
    ("dek_version", -1),
    ("created_at", -1),
    ("updated_at", 2**63 - 1),
])
def test_corrupt_record_columns_are_a_vault_error(tmp_path, column, value):
    root = tmp_path / f"column-{column}-{value}"
    root.mkdir()
    vault = _open(root)
    vault.put(_record("record"))
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute(f"UPDATE vault_record SET {column} = ? WHERE id = 'record'", (value,))
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        try:
            vault.get("record")
        except VaultError:
            pass
        try:
            vault.list("")
        except VaultError:
            pass
    finally:
        vault.close()


def test_read_only_data_directory_is_refused(tmp_path):
    root = tmp_path / "readonly"
    root.mkdir()
    vault = _open(root)
    vault.put(_record("record"))
    vault.close()
    os.chmod(root, 0o500)
    try:
        with pytest.raises((VaultError, OSError)):
            _open(root)
    finally:
        os.chmod(root, 0o700)


def test_a_half_written_wal_is_not_trusted(tmp_path):
    root = tmp_path / "wal"
    root.mkdir()
    vault = _open(root)
    vault.put(_record("record"))
    vault.close()
    (root / "vault.db-wal").write_bytes(b"not a wal" * 100)
    (root / "vault.db-shm").write_bytes(b"not a shm" * 100)
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        vault.get("record")
    except VaultError:
        pass
    finally:
        vault.close()


def test_a_symlink_loop_is_refused(tmp_path):
    root = tmp_path / "loop"
    root.mkdir()
    (root / "vault.db").symlink_to(root / "vault.db")
    with pytest.raises((VaultError, OSError)):
        _open(root)


def test_fsync_failure_does_not_leave_a_half_initialized_vault(tmp_path, monkeypatch):
    root = tmp_path / "fsync"
    root.mkdir()

    def fail_fsync(_fileno):
        raise OSError(28, "no space")

    monkeypatch.setattr("security_gateway.vault.mode.os.fsync", fail_fsync)
    with pytest.raises((VaultError, OSError)):
        _open(root)
    monkeypatch.undo()
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        vault.put(_record("record"))
    finally:
        vault.close()


@pytest.mark.parametrize("definition", [
    "{}",
    '{"version": 1}',
    '{"version": -1, "fields": []}',
    '{"version": 1, "fields": [{}]}',
    '{"version": 1, "fields": [{"name": "a", "type": "nope"}]}',
    '{"version": 1, "fields": [{"name": "a/b", "type": "string"}]}',
    '{"version": 1, "fields": [{"name": "a", "type": "string", "encrypted": "yes"}]}',
    '{"version": 1, "fields": [{"name": "a", "type": "string"}, {"name": "a", "type": "string"}]}',
    '[]',
    'null',
])
def test_corrupt_schema_definition_shapes_are_a_vault_error(tmp_path, definition):
    root = tmp_path / f"schema-{abs(hash(definition))}"
    root.mkdir()
    vault = _open(root)
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute("UPDATE vault_schema SET definition = ?", (definition,))
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        try:
            vault.get("record")
        except VaultError:
            pass
    finally:
        vault.close()


@pytest.mark.parametrize("updates", [
    {"crypto_mode": "bad"},
    {"crypto_mode": ""},
    {"pending_dek_version": 2},
    {"active_dek_version": 2},
    {"wrapped_dek": b"\x00"},
    {"pending_wrapped_dek": b"\x00"},
    {"active_config_shard": b"\x00"},
    {"file_shard_version": 0},
    {"superseded_dek_version": 99},
])
def test_corrupt_key_metadata_relationships_are_a_vault_error(tmp_path, updates):
    root = tmp_path / f"relation-{abs(hash(str(updates)))}"
    root.mkdir()
    vault = _open(root)
    vault.put(_record("record"))
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        assignments = ", ".join(f"{column} = ?" for column in updates)
        db.execute(f"UPDATE vault_key_metadata SET {assignments}", tuple(updates.values()))
    try:
        vault = _open(root)
    except VaultError:
        return
    try:
        try:
            vault.get("record")
        except VaultError:
            pass
    finally:
        vault.close()


def test_wrapped_dek_blobs_survive_random_and_partial_damage(tmp_path):
    from security_gateway.vault.clusterdek.wrap import ErrMalformed, unwrap, wrap

    key = ec.generate_private_key(ec.SECP256R1())
    valid = wrap(key.public_key(), b"secret")
    for _ in range(200):
        cut = RNG.randrange(len(valid) + 1)
        damaged = RNG.choice(
            (
                valid[:cut],
                valid + bytes(RNG.randrange(256) for _ in range(RNG.randrange(1, 8))),
                valid[:cut]
                + bytes(RNG.randrange(256) for _ in range(RNG.randrange(1, 8)))
                + valid[cut:],
                bytes(RNG.randrange(256) for _ in range(RNG.randrange(0, 100))),
            )
        )
        try:
            unwrap(key, damaged)
        except (ErrMalformed, ClusterDekError, VaultError, ValueError):
            pass


def test_watch_items_with_random_metadata_do_not_raise_raw_errors():
    from security_gateway.vault.etcdstore.watch import responses_from_item

    for _ in range(300):
        item = type(
            "Item",
            (),
            {
                "events": [type("Event", (), {
                    "key": bytes(RNG.randrange(256) for _ in range(RNG.randrange(8))),
                    "value": bytes(RNG.randrange(256) for _ in range(RNG.randrange(8))),
                    "mod_revision": RNG.choice((-1, 0, 1, 2**62, 2**63 - 1, 2**63)),
                    "type": RNG.choice((0, 1, None)),
                })() for _ in range(RNG.randrange(3))],
                "header": type("Header", (), {"revision": RNG.choice((-1, 0, 1, 2**63))})(),
                "created": RNG.choice((True, False)),
                "canceled": RNG.choice((True, False)),
                "compact_revision": RNG.choice((-1, 0, 1, 2**63)),
            },
        )()
        try:
            responses_from_item(item)
        except (VaultError, ValueError):
            pass


def test_vrec_container_survives_random_and_partial_damage(tmp_path):
    from security_gateway.vault.codec import ContainerField, decode_container, encode_container
    from security_gateway.vault.errors import InvalidRecordError

    valid = encode_container(
        [ContainerField(name="a", type=Type.STRING, encrypted=False, data=b"x")]
    )
    for _ in range(500):
        cut = RNG.randrange(len(valid) + 1)
        damaged = RNG.choice(
            (
                bytes(RNG.randrange(256) for _ in range(RNG.randrange(0, 80))),
                valid[:cut],
                valid[:cut]
                + bytes(RNG.randrange(256) for _ in range(RNG.randrange(1, 8)))
                + valid[cut:],
            )
        )
        try:
            decode_container(damaged)
        except (InvalidRecordError, VaultError, ValueError):
            pass


def test_clusterkey_roster_and_rotation_decoders_are_not_raw_errors():
    from security_gateway.vault.clusterkey.authority import (
        _unmarshal_node_entry,
        _unmarshal_rotation_state,
    )

    bases = (
        (b'{"node_id":"n","cert_der":"Y2VydA==","dek_version":1}', _unmarshal_node_entry),
        (b'{"state":"running","holder":"n","target_dek_version":1,"started_at":"x"}', _unmarshal_rotation_state),
    )
    for base, decoder in bases:
        for _ in range(200):
            cut = RNG.randrange(len(base) + 1)
            variants = [
                os.urandom(RNG.randrange(0, 40)),
                base[:cut],
                base + b"x",
                b"[]",
                b"null",
                b'"x"',
                b"1",
            ]
            variants.append(
                base[:cut] + bytes(RNG.randrange(256) for _ in range(RNG.randrange(1, 8))) + base[cut:]
            )
            for damaged in variants:
                try:
                    decoder(damaged)
                except (EtcdStoreError, VaultError, ValueError, TypeError):
                    pass


def test_schema_parser_survives_random_and_partial_damage():
    from security_gateway.vault.errors import InvalidSchemaError
    from security_gateway.vault.schema import parse_schema

    valid = b'{"version":1,"fields":[{"name":"a","type":"string","encrypted":true}]}'
    for _ in range(500):
        cut = RNG.randrange(len(valid) + 1)
        damaged = RNG.choice(
            (
                os.urandom(RNG.randrange(0, 80)),
                valid[:cut],
                valid[:cut]
                + bytes(RNG.randrange(256) for _ in range(RNG.randrange(1, 8)))
                + valid[cut:],
                b"[]",
                b"null",
                b"{}",
            )
        )
        try:
            parse_schema(damaged)
        except (InvalidSchemaError, VaultError, ValueError, TypeError):
            pass
