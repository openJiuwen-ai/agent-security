# security_gateway

A Python implementation of `credential_router`: a generic encrypted field
store and credential router. It is a port of the Go service in
`../credential_router`, and the two are **interoperable** — they read and
write the same files, so a store created by one is readable by the other
and a deployment can move from one to the other without migrating data.

The client and the LLM-gateway integration live in the consuming
application; this package only provides the cryptographic primitives, the
platform layer and the vault.

## Layout

```
src/                  the security_gateway package (package-dir maps src -> security_gateway)
  crypto/             the cryptographic primitives and the on-disk formats
  platform/           the error envelope, configuration and process-level guards
  vault/              the generic encrypted field store (schema, records, keys, rotation)
tests/
  unit/               one directory per package
  integration/        the whole stack on one machine
  interop/            the checks that only make sense against the Go implementation
```

Each package mirrors a Go package one for one. When you need to know what a
Python module is supposed to do, read the Go file it came from — the Go
code is the specification, and its comments explain the reasoning behind
each rule.

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

The Go service's tests are the specification. Port them rather than
inventing new ones: the Go suite is 114 files and 36k lines, and it encodes
the failure modes that matter.

`tests/interop/` holds the checks that only make sense against the other
implementation: the vault's files and the vault's socket protocol. They
drive the prebuilt Go binary — the Go toolchain is not needed, and the
binary is treated as the reference.

### The end-to-end harness

The sibling `e2e/` harness (outside this repository) runs the whole thing
the way it is deployed: a real litellm, a real postgres, a fake upstream,
and the vault. It takes an implementation switch:

```sh
CRED_ROUTER_IMPL=python /tmp/opencode/litellm-venv/bin/python test_vault_integration.py
CRED_ROUTER_IMPL=go     /tmp/opencode/litellm-venv/bin/python test_vault_integration.py
```

The two runs exercise the same scenarios against the same contract, which
is the point: the harness is what says the Python service is a **drop-in**
for the Go one, not merely a similar one.

## Reading and writing records

```python
from security_gateway.vault.schema import FieldDef, Schema, Type
from security_gateway.vault.vault import Config as VaultConfig
from security_gateway.vault.vault import Vault

schema = Schema(version=1, fields=[
    FieldDef(name="kind", type=Type.STRING),
    FieldDef(name="secret", type=Type.BYTES, encrypted=True),
])
vault = Vault.open(VaultConfig(data_dir="/var/lib/credential-router/vault"), schema)
vault.put(...)
secret = vault.get("some/record/id")
```

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
   shape, same error codes.
