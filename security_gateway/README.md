# security_gateway

English | [简体中文](./README_CN.md)

A Python implementation of the `credential_router` storage layer: an encrypted
field store built on a schema declared in code. It ports the Go service's
`crypto`, `platform`, and `vault` packages; the Go service itself is an external
reference and is not vendored in this repository.

The client and the LLM-gateway integration live in the consuming application;
this package provides the cryptographic primitives, the platform layer, and the
vault.

## Layout

```
src/                  the security_gateway package (package-dir maps src -> security_gateway)
  crypto/             the cryptographic primitives and the on-disk formats
  platform/           the error envelope, configuration and process-level guards
  vault/              the generic encrypted field store (schema, records, keys, rotation)
tests/
  unit/               one directory per package
```

Each package mirrors a Go package one for one. The upstream Go implementation
is a behavioral reference and is not in this repository; each Python module's
docstring records the rules and reasoning it ports, so use the docstrings and
this README as the primary reference.

## What it does

- Records are addressed by an indexed id and carry fields described by a
  `Schema` the host declares in code.
- A field is either stored as-is or encrypted under the store's data encryption
  key (DEK). The schema is authoritative; the stored bytes carry a flag that is
  cross-checked on read.
- The DEK is wrapped by a key encryption key (KEK) derived with PBKDF2 from the
  XOR of three shards: a file, SQLite, and a built-in constant. The built-in
  shard ships with the package and must be treated as public. The security
  boundary is that an attacker who obtains only the file shard or only the
  SQLite shard cannot recover the KEK; that protects against offline data
  theft, not a local privilege escalation that can read both.
- A record's fields are encoded into a `VREC` container and stored in the
  `vault_record.data` column. The schema, key metadata, and sync state live in
  `vault_schema`, `vault_key_metadata`, and `vault_sync_state`.
- DEK rotation, automatic rotation, and takeover of an interrupted rotation are
  supported. A newer schema is accepted only when the change is additive: every
  existing field keeps its type and encryption state. Renames, removals, type
  changes, or encryption changes are refused and need an explicit migration.
  The store keeps the earlier schema versions it has seen so old records stay
  readable.
- Records are keyed by id. The only bulk read is `Vault.list(prefix)`, which
  lists the records whose id starts with the prefix; there is no query-by-field
  API and no secondary index.

## Installing

```sh
pip install -e .
pip install -e '.[dev]'
```

The core package imports nothing beyond `cryptography` and `PyYAML`.

## Testing

```sh
pip install -e '.[dev]'
pytest tests -q
```

The current suite is under `tests/unit/` and covers `crypto`, `platform`, and
`vault`. The Go service's tests remain the reference for behavior that has not
been ported yet.

## Reading and writing records

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
vault = Vault.open(VaultConfig(data_dir="/var/lib/credential-router/vault"), schema)

record = Record(id="some/record/id")
record.set("kind", Value.new_string("api_key"))
record.set("secret", Value.new_bytes(b"..."))
vault.put(record)
secret = vault.get("some/record/id").get_bytes("secret")
```

## Current scope

- The package does not open a port and does not implement a UDS server. HTTP
  APIs, credential routing, and the LLM-gateway integration belong to the
  consuming application.
- etcd and cluster sync are port skeletons and currently cannot be imported:
  they reference a `security_gateway.credmgr` subpackage that is not shipped.
  These modules are not usable yet; only the single-machine vault works today.
- The on-disk VREC container, the wrapped DEK, the key snapshot file, the SQLite
  DDL, and the key derivation parameters are compatibility contracts. Changing
  one requires a migration on both sides.

## Compatibility rules

These are not style preferences. Breaking one breaks a deployment that is
reading data written by the other implementation.

1. **The on-disk formats do not change.** The VREC container, the wrapped
   DEK and the key snapshot file are all fixed by the format. A change needs
   a migration on both sides.
2. **The SQLite DDL does not change.** Same tables, same columns, same
   indexes, same defaults.
3. **The key derivation does not change.** Same three shards, same XOR, same
   salt, same iteration count, same PRF per mode.
4. **The etcd keyspace does not change.** Same prefixes, same value
   encodings, same generation fence.
5. **The UDS frame format does not change.** Same length prefix, same JSON
   shape, same error codes. This package implements neither a UDS listener nor
   the frame codec; the frame format belongs to the external service wrapper and
   the upstream implementation, and nothing here encodes or decodes it.
