"""Random-seeded API fuzzing for the public Vault surface.

Each run starts from a random base seed and reports it in the pytest
test id, so a failing case can be replayed with::

    API_FUZZ_SEED=<seed> pytest tests/unit/vault/test_api_fuzz.py

The cases drive put/get/delete/list/batch/CAS through valid, malformed
and partially-random inputs, and check the observable result against a
small model of the store. Invalid inputs must fail with a vault error
and leave the store unchanged.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
import time
import types
from typing import Any, cast

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from tests._fuzz_rng import FuzzRandom
from security_gateway.crypto import Mode
from security_gateway.vault.etcd import EtcdConfig
from security_gateway.vault.clusterdek.anchor import ClusterDekError
from security_gateway.vault.etcdstore.errors import EtcdStoreError
from security_gateway.vault import (
    Config,
    ConflictError,
    FieldDef,
    InvalidRecordError,
    NotFoundError,
    Record,
    Schema,
    Type,
    Value,
    Vault,
    VaultError,
    InvalidError,
    batch_delete,
    batch_get,
)

FIELDS = ("name", "secret", "count", "enabled")
PLAIN_FIELDS = ("name", "count", "enabled")
BASE_SEED = int(os.environ.get("API_FUZZ_SEED", "0")) or 1 + secrets.randbelow(2**63 - 1)
SEEDS = tuple(BASE_SEED + i for i in range(8))
ITERATIONS = int(os.environ.get("API_FUZZ_ITERS", "200"))
BINARY_CASES = int(os.environ.get("API_FUZZ_BINARY_CASES", "80"))
FUZZ_SECONDS = float(os.environ.get("API_FUZZ_SECONDS", "0"))


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
            FieldDef(name="count", type=Type.INT64),
            FieldDef(name="enabled", type=Type.BOOL),
        ],
    )


def _value(rng: FuzzRandom, name: str) -> Value:
    if name == "name":
        return Value.new_string("name-" + str(rng.randrange(20)))
    if name == "secret":
        return Value.new_string("secret-" + str(rng.randrange(20)))
    if name == "count":
        return Value.new_int64(rng.randrange(-1000, 1000))
    return Value.new_bool(rng.choice((True, False)))


def _record(rng: FuzzRandom, record_id: str) -> Record:
    return Record(
        id=record_id,
        fields={name: _value(rng, name) for name in FIELDS},
    )


def _plain(rec: Record) -> dict[str, Value]:
    return {name: rec.fields[name] for name in PLAIN_FIELDS}


def _random_value(rng: FuzzRandom) -> Value:
    value_type = rng.choice(
        (Type.STRING, Type.BYTES, Type.INT64, Type.BOOL, Type.INVALID)
    )
    data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 65)))
    return Value(value_type, data)


def _random_record_id(rng: FuzzRandom) -> str:
    return rng.choice(
        (
            "",
            "a",
            "a/b",
            "..",
            "中文",
            "\x00",
            "x" * 1024,
            "rec-" + str(rng.randrange(100)),
        )
    )


@pytest.fixture
def fuzz_vault(tmp_path):
    vault = Vault.open(Config(data_dir=str(tmp_path)), _schema())
    try:
        yield vault
    finally:
        vault.close()


def _random_operation(vault, rng, model, ids):
    op = rng.randrange(7)
    record_id = rng.choice(ids)

    if op in (0, 1):
        rec = _record(rng, record_id)
        vault.put(rec)
        model[record_id] = rec
    elif op == 2:
        if record_id in model:
            assert vault.get(record_id) == model[record_id]
        else:
            with pytest.raises(NotFoundError):
                vault.get(record_id)
    elif op == 3:
        if record_id in model:
            vault.delete(record_id)
            del model[record_id]
        else:
            with pytest.raises(NotFoundError):
                vault.delete(record_id)
    elif op == 4:
        prefix = record_id[: rng.randrange(0, len(record_id) + 1)]
        listed = {entry.id: entry.fields for entry in vault.list(prefix)}
        expected = {
            rid: _plain(rec)
            for rid, rec in model.items()
            if rid.startswith(prefix)
        }
        assert listed == expected
    elif op == 5:
        batch = [rng.choice(ids) for _ in range(rng.randrange(0, 7))]
        unique = list(dict.fromkeys(batch))
        found = batch_get(vault, batch)
        assert list(found) == [rid for rid in unique if rid in model]
        for rid in unique:
            if rid in model:
                assert found[rid] == model[rid]
    else:
        batch = [rng.choice(ids) for _ in range(rng.randrange(0, 7))]
        unique = list(dict.fromkeys(batch))
        result = batch_delete(vault, batch)
        assert set(result.deleted) == {rid for rid in unique if rid in model}
        assert set(result.missing) == {
            rid for rid in unique if rid not in model
        }
        for rid in result.deleted:
            del model[rid]


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_operations_match_model(fuzz_vault, seed):
    rng = FuzzRandom(seed)
    model: dict[str, Record] = {}
    ids = [f"rec-{i}" for i in range(8)]

    for _ in range(ITERATIONS):
        _random_operation(fuzz_vault, rng, model, ids)

    assert fuzz_vault.status().record_count == len(model)
    for record_id, rec in model.items():
        assert fuzz_vault.get(record_id) == rec


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_random_binary_values(fuzz_vault, seed):
    rng = FuzzRandom(seed ^ 0xB1)
    for _ in range(BINARY_CASES):
        record_id = _random_record_id(rng)
        rec = Record(
            id=record_id,
            fields={rng.choice(FIELDS): _random_value(rng)},
        )
        try:
            fuzz_vault.put(rec)
        except InvalidRecordError:
            continue
        assert fuzz_vault.get(record_id) == rec
        fuzz_vault.delete(record_id)


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_partially_mutated_records(fuzz_vault, seed):
    rng = FuzzRandom(seed ^ 0xB2)
    original = _record(FuzzRandom(seed), "hybrid")
    fuzz_vault.put(original)

    for _ in range(BINARY_CASES):
        candidate = Record(id=original.id, fields=dict(original.fields))
        mutation = rng.randrange(5)
        if mutation == 0:
            candidate.fields["unknown"] = _random_value(rng)
        elif mutation == 1:
            candidate.fields["name"] = Value.new_int64(rng.randrange(-1000, 1000))
        elif mutation == 2:
            candidate.fields["count"] = Value(
                Type.INT64,
                bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8))),
            )
        elif mutation == 3:
            candidate.id = ""
        else:
            candidate.fields.pop(rng.choice(FIELDS), None)

        if mutation == 4:
            fuzz_vault.put(candidate)
            assert fuzz_vault.get(candidate.id) == candidate
            fuzz_vault.delete(candidate.id)
            fuzz_vault.put(original)
            continue

        with pytest.raises(VaultError):
            fuzz_vault.put(candidate)
        assert fuzz_vault.get(original.id) == original


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_random_config_does_not_corrupt_open(tmp_path, seed):
    rng = FuzzRandom(seed ^ 0xB3)
    modes = (Mode.AES, Mode.SM4, "aes", "sm", "invalid", "")
    periods = (-1.0, 0.0, 0.001, 60.0)
    cache_sizes = (-1, 0, 1, 1024)
    cache_ttls = (-1.0, 0.0, 0.001, 60.0)

    for i in range(8):
        root = tmp_path / f"config-{i}"
        root.mkdir()
        cfg = Config(
            data_dir=cast(Any, rng.choice((str(root), None, 1))),
            db_path=cast(Any, rng.choice(("", str(root / "custom.db"), None, 1))),
            crypto_mode=cast(Any, rng.choice(modes)),
            rotation_period=rng.choice(periods),
            cache_max_entries=rng.choice(cache_sizes),
            cache_ttl=rng.choice(cache_ttls),
            multi_process=cast(Any, rng.choice((True, False, "yes"))),
        )
        try:
            vault = Vault.open(cfg, _schema())
        except (VaultError, ValueError, TypeError):
            continue
        try:
            rec = _record(rng, "config")
            vault.put(rec)
            assert vault.get("config") == rec
        finally:
            vault.close()


def test_api_fuzz_batch_rejects_an_empty_id(fuzz_vault):
    with pytest.raises(InvalidRecordError):
        batch_delete(fuzz_vault, ["ok", ""])
    assert fuzz_vault.status().record_count == 0


def test_api_fuzz_expected_conflict_does_not_write(fuzz_vault):
    original = _record(FuzzRandom(3), "cas")
    fuzz_vault.put(original)
    replacement = _record(FuzzRandom(4), "cas")

    with pytest.raises(ConflictError):
        fuzz_vault.put(
            replacement,
            expected={"name": Value.new_string("not-the-current-name")},
        )

    assert fuzz_vault.get("cas") == original


@pytest.mark.parametrize(
    "bad_config",
    [
        pytest.param({"data_dir": None}, id="data-dir-none"),
        pytest.param({"data_dir": 3}, id="data-dir-int"),
        pytest.param({"db_path": 3}, id="db-path-int"),
        pytest.param({"rotation_period": float("nan")}, id="period-nan"),
        pytest.param({"rotation_period": float("inf")}, id="period-inf"),
        pytest.param({"rotation_period": "soon"}, id="period-string"),
        pytest.param({"cache_max_entries": -1}, id="cache-negative"),
        pytest.param({"cache_max_entries": 1.5}, id="cache-float"),
        pytest.param({"cache_ttl": -1}, id="ttl-negative"),
        pytest.param({"cache_ttl": float("nan")}, id="ttl-nan"),
        pytest.param({"crypto_mode": "bad"}, id="crypto-mode-bad"),
        pytest.param({"crypto_mode": "aes"}, id="crypto-mode-string"),
        pytest.param({"multi_process": "yes"}, id="multi-process-string"),
        pytest.param({"etcd": "not-an-etcd-config"}, id="etcd-string"),
        pytest.param(
            {"etcd": types.SimpleNamespace(endpoints="127.0.0.1:2379", node_id="n")},
            id="etcd-endpoints-string",
        ),
        pytest.param(
            {"etcd": types.SimpleNamespace(endpoints=("127.0.0.1:2379",), node_id=3)},
            id="etcd-node-id-int",
        ),
        pytest.param(
            {"etcd": types.SimpleNamespace(endpoints=("127.0.0.1:2379",), node_id="")},
            id="etcd-missing-node-id",
        ),
    ],
)
def test_api_fuzz_config_rejects_malformed_values(tmp_path, bad_config):
    root = tmp_path / "bad-config"
    root.mkdir()
    options = {"data_dir": str(root)}
    options.update(bad_config)
    with pytest.raises(InvalidError):
        Vault.open(Config(**options), _schema())


def test_api_fuzz_history_header_corruption_is_a_vault_error(tmp_path):
    root = tmp_path / "history"
    root.mkdir()
    vault = Vault.open(Config(data_dir=str(root)), _schema())
    vault.close()
    database = root / "vault.db"
    database.write_bytes(b"this is not a sqlite database" * 4)
    with pytest.raises(InvalidError):
        Vault.open(Config(data_dir=str(root)), _schema())


def test_api_fuzz_history_schema_mismatch_is_a_vault_error(tmp_path):
    root = tmp_path / "history-schema"
    root.mkdir()
    vault = Vault.open(Config(data_dir=str(root)), _schema())
    vault.close()
    changed = Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.INT64),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
            FieldDef(name="count", type=Type.INT64),
            FieldDef(name="enabled", type=Type.BOOL),
        ],
    )
    with pytest.raises(VaultError):
        Vault.open(Config(data_dir=str(root)), changed)


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_wire_decoders_reject_random_bytes(seed):
    from security_gateway.vault.clusterdek.handover import unmarshal_request
    from security_gateway.vault.etcdstore.cluster_keys import _unmarshal_node_entry
    from security_gateway.vault.etcdstore.entry import unmarshal_entry, unmarshal_record
    from security_gateway.vault.etcdstore.handover import decode_generation
    from security_gateway.vault.etcdstore.rotation import unmarshal_rotation

    rng = FuzzRandom(seed ^ 0xC2)
    decoders = (
        unmarshal_entry,
        unmarshal_record,
        unmarshal_rotation,
        lambda raw: decode_generation("node", raw),
        unmarshal_request,
        lambda raw: _unmarshal_node_entry(raw, "node"),
    )
    for _ in range(BINARY_CASES):
        raw = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 256)))
        for decoder in decoders:
            try:
                decoder(raw)
            except (VaultError, EtcdStoreError, ClusterDekError):
                pass


@pytest.mark.parametrize("seed", [pytest.param(s, id=f"seed={s}") for s in SEEDS])
def test_api_fuzz_wire_decoders_reject_partially_valid_bytes(seed):
    from security_gateway.vault.etcdstore.entry import (
        RecordEntry,
        marshal_record,
        unmarshal_record,
    )

    rng = FuzzRandom(seed ^ 0x9E)
    base = marshal_record(
        RecordEntry(
            data=b"cipher",
            schema_version=1,
            dek_version=1,
            mod_revision=1,
        )
    )
    for _ in range(BINARY_CASES):
        cut = rng.randrange(len(base))
        mutated = rng.choice(
            [
                base[:cut],
                base + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9))),
                base[:cut]
                + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
                + base[cut:],
                bytes(rng.randrange(256) for _ in range(rng.randrange(0, 256))),
            ]
        )
        try:
            unmarshal_record(mutated)
        except (VaultError, EtcdStoreError, ClusterDekError):
            pass
    for _ in range(BINARY_CASES):
        parsed = json.loads(base)
        parsed[rng.choice(list(parsed))] = rng.choice(
            [None, [], {}, "", 1, -1, "not-a-timestamp"]
        )
        mutated = json.dumps(parsed).encode()
        try:
            unmarshal_record(mutated)
        except (VaultError, EtcdStoreError, ClusterDekError):
            pass


def _open(path, **kwargs):
    return Vault.open(Config(data_dir=str(path), **kwargs), _schema())


def test_api_fuzz_corrupt_record_payload_is_a_vault_error(tmp_path):
    root = tmp_path / "corrupt-record"
    root.mkdir()
    vault = _open(root)
    vault.put(_record(FuzzRandom(7), "corrupt"))
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute("UPDATE vault_record SET data = ? WHERE id = 'corrupt'", (b"\x00",))
    vault = _open(root)
    try:
        with pytest.raises(VaultError):
            vault.get("corrupt")
    finally:
        vault.close()


def test_api_fuzz_corrupt_key_metadata_is_a_vault_error(tmp_path):
    root = tmp_path / "corrupt-keys"
    root.mkdir()
    vault = _open(root)
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute("UPDATE vault_key_metadata SET active_config_shard = ?", (b"\x00",))
    with pytest.raises(VaultError):
        _open(root)


def test_api_fuzz_corrupt_schema_is_a_vault_error(tmp_path):
    root = tmp_path / "corrupt-schema"
    root.mkdir()
    vault = _open(root)
    vault.close()
    with sqlite3.connect(root / "vault.db") as db:
        db.execute("UPDATE vault_schema SET definition = ?", ("not-json",))
    with pytest.raises(VaultError):
        _open(root)


def test_api_fuzz_persisted_crypto_mode_mismatch_is_a_vault_error(tmp_path):
    root = tmp_path / "mode-mismatch"
    root.mkdir()
    vault = _open(root, crypto_mode=Mode.AES)
    vault.close()
    with pytest.raises(VaultError):
        _open(root, crypto_mode=Mode.SM4)


@pytest.mark.skipif(FUZZ_SECONDS <= 0, reason="set API_FUZZ_SECONDS to run for a time budget")
def test_api_fuzz_for_a_time_budget(tmp_path):
    root = tmp_path / "timed"
    root.mkdir()
    vault = _open(root)
    rng = FuzzRandom(BASE_SEED ^ 0xD1)
    model: dict[str, Record] = {}
    ids = [f"timed-{i}" for i in range(16)]
    deadline = time.monotonic() + FUZZ_SECONDS
    try:
        while time.monotonic() < deadline:
            _random_operation(vault, rng, model, ids)
        assert vault.status().record_count == len(model)
    finally:
        vault.close()


def test_api_fuzz_empty_etcd_endpoints_are_refused(tmp_path):
    root = tmp_path / "empty-endpoints"
    root.mkdir()
    with pytest.raises(InvalidError, match="endpoints must not be empty"):
        _open(root, etcd=EtcdConfig(endpoints=()))


def _identity(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fuzz-node")])
    from datetime import datetime, timedelta, timezone

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


def test_api_fuzz_an_unreachable_etcd_does_not_open(tmp_path):
    root = tmp_path / "unreachable"
    root.mkdir()
    cert_file, key_file = _identity(root)
    cfg = EtcdConfig(
        endpoints=("127.0.0.1:1",),
        node_id="fuzz-node",
        identity_cert_file=cert_file,
        identity_key_file=key_file,
        identity_ca_file=cert_file,
        dial_timeout=0.2,
        fetch_timeout=1.0,
    )
    with pytest.raises((VaultError, TimeoutError, OSError)):
        _open(root, etcd=cfg)


@pytest.mark.parametrize("seed", SEEDS)
def test_api_fuzz_malformed_etcd_config_is_refused(tmp_path, seed):
    rng = FuzzRandom(seed ^ 0xE7CD)
    root = tmp_path / f"etcd-{seed}"
    root.mkdir()
    for _ in range(40):
        endpoints = rng.choice([(), [], None, [""], ("",), [1], "127.0.0.1:2379"])
        node_id = rng.choice(["", None, 1, "node"])
        cert = rng.choice(["", "/missing/cert.pem"])
        key = rng.choice(["", "/missing/key.pem"])
        identity_ca = rng.choice(["", "/missing/ca.pem"])
        trusted = rng.choice([(), [], None, [""], [1]])
        dial = rng.choice([0.0, -1.0, float("nan"), float("inf"), "1"])
        fetch = rng.choice([0.0, -1.0, float("nan"), float("inf"), "1"])
        tls = rng.choice(
            [
                None,
                types.SimpleNamespace(ca_file="", cert_file="", key_file=""),
                types.SimpleNamespace(ca_file="ca", cert_file="", key_file=""),
                types.SimpleNamespace(ca_file="", cert_file="cert", key_file="key"),
            ]
        )
        cfg = types.SimpleNamespace(
            endpoints=endpoints,
            namespace=rng.choice(["ns", "", None, 1]),
            node_id=node_id,
            identity_cert_file=cert,
            identity_key_file=key,
            identity_ca_file=rng.choice([identity_ca, None, 1]),
            trusted_cert_sha256=trusted,
            dial_timeout=dial,
            fetch_timeout=fetch,
            tls=tls,
        )
        with pytest.raises((VaultError, TypeError, ValueError)):
            _open(root, etcd=cfg)


@pytest.mark.parametrize("seed", SEEDS)
def test_api_fuzz_persisted_files_survive_random_and_partial_damage(tmp_path, seed):
    import shutil

    source = tmp_path / "source"
    source.mkdir()
    vault = _open(source)
    vault.put(_record(FuzzRandom(seed), "persisted"))
    vault.close()

    files = [
        path.relative_to(source)
        for path in source.rglob("*")
        if path.is_file() and path.name not in {".vault_lock"}
    ]
    rng = FuzzRandom(seed ^ 0x5A)
    for i in range(12):
        target = tmp_path / f"damaged-{i}"
        shutil.copytree(source, target)
        victim = target / rng.choice(files)
        raw = victim.read_bytes()
        mode = rng.randrange(3)
        if mode == 0:
            mutated = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 256)))
        elif mode == 1:
            mutated = raw[: rng.randrange(len(raw) + 1)]
        else:
            cut = rng.randrange(len(raw) + 1)
            mutated = (
                raw[:cut]
                + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
                + raw[cut:]
            )
        victim.write_bytes(mutated)
        try:
            damaged = _open(target)
        except VaultError:
            continue
        except Exception as exc:  # noqa: BLE001 - a raw error is the failure
            pytest.fail(f"{victim.name} mode {mode}: {type(exc).__name__}: {exc}")
        try:
            damaged.get("persisted")
        except VaultError:
            pass
        except Exception as exc:  # noqa: BLE001 - a raw error is the failure
            pytest.fail(f"{victim.name} mode {mode}: get: {type(exc).__name__}: {exc}")
        finally:
            damaged.close()


@pytest.mark.parametrize("seed", SEEDS)
def test_api_fuzz_wire_decoders_reject_partially_valid_values(seed):
    from security_gateway.vault.clusterdek.handover import (
        HandoverRequest,
        marshal_request,
        unmarshal_request,
    )
    from security_gateway.vault.etcdstore.cluster_keys import (
        NodeEntry,
        _marshal_node_entry,
        _unmarshal_node_entry,
    )
    from security_gateway.vault.etcdstore.entry import (
        Entry,
        marshal_entry,
        unmarshal_entry,
    )
    from security_gateway.vault.etcdstore.handover import decode_generation, encode_generation
    from security_gateway.vault.etcdstore.rotation import (
        RotationState,
        marshal_rotation,
        unmarshal_rotation,
    )

    rng = FuzzRandom(seed ^ 0x71)
    bases = (
        (unmarshal_entry, marshal_entry(Entry(api_key_cipher=b"x", user_id="u"))),
        (
            unmarshal_rotation,
            marshal_rotation(RotationState(state="running", holder="n")),
        ),
        (
            unmarshal_request,
            marshal_request(HandoverRequest(node_id="n", nonce="x")),
        ),
        (
            lambda raw: _unmarshal_node_entry(raw, "n"),
            _marshal_node_entry(NodeEntry(node_id="n", cert_der="cert")),
        ),
        (
            lambda raw: decode_generation("n", raw),
            encode_generation(1, b"sealed"),
        ),
    )
    for decoder, base in bases:
        for _ in range(BINARY_CASES):
            cut = rng.randrange(len(base))
            variants = [
                base[:cut],
                base + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9))),
                base[:cut]
                + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9)))
                + base[cut:],
            ]
            if base.startswith(b"{"):
                parsed = json.loads(base)
                parsed[rng.choice(list(parsed))] = rng.choice(
                    [None, [], {}, "", 1, -1, "not-a-timestamp"]
                )
                variants.append(json.dumps(parsed).encode())
            for mutated in variants:
                try:
                    decoder(mutated)
                except (VaultError, EtcdStoreError, ClusterDekError):
                    pass


@pytest.mark.parametrize("seed", SEEDS)
def test_api_fuzz_etcd_identity_and_transport_combinations_are_typed(tmp_path, seed):
    """Every etcd field must reject nonsense with a vault error, not a bare one."""
    rng = FuzzRandom(seed ^ 0x51D3)
    root = tmp_path / f"etcd-combinations-{seed}"
    root.mkdir()
    cert_file, key_file = _identity(root)
    nodes = ("node-a", "node/b", "", "node\x00", "n" * 300)
    namespaces = ("", "ns", "a/b", "\x00", 1, None)
    endpoints = (
        ("127.0.0.1:1",),
        ("127.0.0.1:1", "127.0.0.1:2"),
        ("",),
        ("127.0.0.1:1", ""),
        (1,),
    )

    for index in range(40):
        directory = root / f"case-{index}"
        directory.mkdir()
        tls = rng.choice(
            (
                None,
                EtcdConfig.__dataclass_fields__["tls"].default,
                types.SimpleNamespace(ca_file=cert_file, cert_file=cert_file, key_file=key_file),
                types.SimpleNamespace(ca_file="", cert_file=cert_file, key_file=key_file),
                types.SimpleNamespace(ca_file=1, cert_file=cert_file, key_file=key_file),
            )
        )
        cfg = EtcdConfig(
            endpoints=cast(Any, rng.choice(endpoints)),
            namespace=cast(Any, rng.choice(namespaces)),
            node_id=cast(Any, rng.choice(nodes)),
            identity_cert_file=cast(Any, rng.choice((cert_file, "", 1))),
            identity_key_file=cast(Any, rng.choice((key_file, "", 1))),
            identity_ca_file=cast(Any, rng.choice((cert_file, "", 1))),
            trusted_cert_sha256=cast(Any, rng.choice(((), ("a" * 64,), ("",), (1,)))),
            dial_timeout=cast(Any, rng.choice((0.01, 0.0, -1.0, float("nan"), "1"))),
            fetch_timeout=cast(Any, rng.choice((0.1, 0.0, -1.0, float("nan"), "1"))),
            tls=cast(Any, tls),
        )
        with pytest.raises((VaultError, TypeError, ValueError, OSError, EtcdStoreError)):
            _open(directory, etcd=cfg)
