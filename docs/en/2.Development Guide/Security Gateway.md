# Security Gateway

Security Gateway (distribution name `security-gateway`, import name `security_gateway`) is an encrypted field store library. It stores records by id, and the schema decides which fields are encrypted. It is a library, not a standalone service.

---

## 1. What problem it solves

Agents and tools often need to keep API keys, access tokens, private keys, and similar fields. Written directly into a config file or database, they sit in plaintext on disk: backups, logs, and accidental commits can all carry them out.

Security Gateway puts "which fields must be encrypted" into the schema, encrypts on write, and decrypts on read. The data encryption key is never stored in plaintext; it is wrapped by a key encryption key, which is derived with PBKDF2 from the XOR of three shards: a file, SQLite, and a built-in constant. The built-in constant ships with the package and must be treated as public. The security boundary is that an attacker who obtains only the file shard or only the SQLite shard cannot recover the key; that protects against offline data theft, not a local attacker who can read both.

## 2. Core concepts

| Concept | Meaning |
| --- | --- |
| `Record` | One record: an id plus a set of field values |
| `Schema` | The shape of a record: which fields it has, each field's type, and whether it is encrypted |
| `FieldDef` | One field definition in a schema: name, type, and the `encrypted` flag |
| `Value` | A field value: string, bytes, int64, or bool |
| DEK | Data encryption key, used to encrypt field values |
| KEK | Key encryption key, used to wrap the DEK; derived with PBKDF2 from the XOR of three shards: a file, SQLite, and a built-in constant |
| `VREC` | The binary container for a record's fields, stored in `vault_record.data` |
| Rotation | Replacing the DEK and gradually re-encrypting old records under the new key |

The schema is authoritative: whether a field is encrypted depends only on the schema, and the flag in the stored bytes is used only to cross-check on read. A newer schema is accepted only when the change is additive: every existing field keeps its type and encryption state. Renames, removals, type changes, or encryption changes are refused and need an explicit migration. The store keeps earlier schema versions so old records stay readable.

## 3. What happens on read and write

Write:

1. Call `Vault.open(config, schema)` to open the store. The schema is checked at open time: a newer schema must be an additive extension of the stored one, or it is refused.
2. Build a `Record` and fill fields with `Value.new_string()`, `Value.new_bytes()`, and similar constructors.
3. Call `vault.put(record)`. The engine checks the schema, encrypts the fields that require it with the current DEK, encodes the record into a `VREC` container, and writes it to SQLite.

Read:

1. Call `vault.get(record_id)` to load the row by id.
2. Look up the schema version recorded with the row.
3. Decrypt the fields the schema marks as encrypted and return a `Record`.
4. Read values with `record.get_string()`, `record.get_bytes()`, and similar accessors.

Rotation:

1. Call `rotate_dek()` to generate a new DEK and wrap it with the KEK.
2. Rotation switches to the new DEK first, then re-encrypts records still under the old DEK in batches; records not migrated yet fall back to the old DEK on read.
3. Use `start_auto_rotate()` for automatic rotation; an interrupted rotation can continue on the next open or be taken over with `takeover_pending()`.

## 4. Layout

| Directory | Role |
| --- | --- |
| `security_gateway/src/crypto/` | AEAD encryption, key derivation, wire format, and mode constants |
| `security_gateway/src/platform/` | Configuration loading, error codes and HTTP status mapping, memory locking, single-instance lock |
| `security_gateway/src/vault/` | Encrypted field store: schema, record codec, SQLite storage, key management, rotation |

`src` maps directly to the package root, so imports are `security_gateway.vault`, `security_gateway.crypto`, and `security_gateway.platform`.

## 5. Usage example

```python
from security_gateway.vault import (
    Config as VaultConfig,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)

schema = Schema(version=1, fields=[
    FieldDef(name="kind", type=Type.STRING),
    FieldDef(name="secret", type=Type.BYTES, encrypted=True),
])
vault = Vault.open(VaultConfig(data_dir="/var/lib/security-gateway/vault"), schema)

record = Record(id="service/token")
record.set("kind", Value.new_string("api_key"))
record.set("secret", Value.new_bytes(b"..."))
vault.put(record)

entry = vault.get("service/token")
print(entry.get_string("kind"))
print(entry.get_bytes("secret"))
```

## 6. Boundaries and limits

- The package opens no port and provides no UDS server. HTTP APIs, credential routing, and LLM-gateway integration belong to the consuming application.
- Records are accessible by id only. There is no query-by-field API and no secondary index.
- The on-disk format, SQLite DDL, key derivation parameters, and UDS frame format are compatibility contracts; changing one requires a migration on both sides.
- etcd and cluster sync are port skeletons and currently cannot be imported: they reference a `security_gateway.credmgr` subpackage that is not shipped; only the single-machine vault works today.
- Tests currently live under `tests/unit/` and cover crypto, platform, and vault.

## 7. Install and test

```bash
cd security_gateway
pip install -e .
pip install -e ".[dev]"
pytest tests -q
```

Runtime dependencies are only `cryptography` and `PyYAML`. Python 3.11 or newer is required.

## 8. Continue here

The fuller API notes, compatibility rules, and migration cautions are in `security_gateway/README.md`.
