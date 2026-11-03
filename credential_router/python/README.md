# cred_router (Python)

A Python implementation of `cred_router`: a generic secure store and
credential router. It is a port of the Go service in the parent directory
(`..`), and the two are **interoperable** — they read and
write the same files, so a store created by one is readable by the other and
a deployment can move from one to the other without migrating data.

The reason the port exists: `litellm` reads its secrets through
`get_secret`, and today that is a Unix-domain-socket round trip to a
separate Go process. In Python the same call can be an in-process function
call, which removes the socket's latency, its permission model and the
cross-language frame codec from the hot path.

## Layout

```
src/cred_router/
  crypto/     the cryptographic primitives and the on-disk formats
  vault/      the generic encrypted field store (schema, records, keys, rotation)
  vaultsvc/   the service that exposes the vault over a unix socket and TCP
  credmgr/    the credential router: store, keystore, cache, backup, admin
  admin/      the admin API — the only writer of a credential
  proxy/      the LLM upstream proxy
  litellm/    the adapter that lets litellm read secrets in-process
  platform/   the error envelope, the configuration, the single-instance guard
  redact/     the one rule that decides how much of a key a log line may carry
tests/
  unit/        one directory per package
  integration/ the whole stack on one machine
  interop/     the checks that only make sense against the Go implementation
docs/
  ADMIN_API_CONTRACT.md   what the admin API answers, as the Go binary answers it
  ETCD_CLIENT_CONTRACT.md what the etcd client offers, and the CAS rule
```

Each package mirrors a Go package one for one. When you need to know what a
Python module is supposed to do, read the Go file it came from — the Go
code is the specification, and its comments explain the reasoning behind
each rule.

The two files in `docs/` are worth reading before changing the admin API or
the etcd code. Both were written by **running the Go binary** and recording
what it actually answered, because the Go source is easy to misread:
`respondJSON` wraps the body, and several response shapes are assembled in
ways the struct tags do not make obvious. Where a document and a quick
reading of the Go disagree, the document is right.

## The two key material systems

There are **two** independent key material systems in this service, and
they look alike while sharing nothing:

| | `cred_router.credmgr.keystore` | `cred_router.vault` |
|---|---|---|
| holds | the router's credentials | a generic field store |
| S1 | `<secrets_dir>/s1.bin.<N>` | `<data_dir>/secrets/s1.bin.<N>` |
| S2 | `key_metadata.active_config_shard` | `vault_key_metadata.active_config_shard` |
| S3 | compiled in (`keystore.S3Shard`) | compiled in (`vault.s3Shard`) |
| salt | `keystore.kekSalt` | `vault.kekSalt` |
| snapshots | reference counted | not reference counted |

The constants differ. Copying one system's constants into the other yields
a store that opens and then decrypts nothing, whose symptom looks like a
lost key rather than a typo.

## Installing

```sh
pip install -e .            # the core
pip install -e '.[litellm]' # plus the litellm adapter
pip install -e '.[admin]'   # plus the admin API server
pip install -e '.[proxy]'   # plus the proxy's HTTP client
pip install -e '.[etcd]'    # plus the etcd client
```

The core package imports nothing beyond `cryptography` and `PyYAML`.
Importing `cred_router` must never pull in litellm: `cred_router.litellm`
is the only module that may, and it is an optional extra.

## Running

```sh
python -m cred_router -config /etc/credential-router/config.yaml
```

The service listens on **two** addresses, and they are deliberately
different:

| | address | serves |
|---|---|---|
| the proxy | `server.bind_address` | credential traffic |
| the admin | `admin.addr` | `/v1/…`, and nothing else |

The admin API has no authentication of its own. Its safety rests entirely on
not being reachable from wherever the proxy is, so the configuration refuses
an `admin.addr` that binds a wildcard address, and the two are never merged
onto one port.

## Testing

```sh
PYTHONPATH=src python3 -m pytest tests -q
```

The Go service's tests are the specification. Port them rather than
inventing new ones: the Go suite is 114 files and 36k lines, and it encodes
the failure modes that matter.

`tests/interop/` holds the checks that only make sense against the other
implementation: the vault's files, the vault's socket protocol, the
credential database, and the admin API's answers. They drive the prebuilt
Go binary — the Go toolchain is not needed, and the binary is treated as
the reference.

### The end-to-end harness

The sibling `e2e/` harness (outside this repository) runs the whole thing the
way it is deployed: a real litellm, a real postgres, a fake upstream, and the
vault. It takes an implementation switch:

```sh
CRED_ROUTER_IMPL=python /tmp/opencode/litellm-venv/bin/python test_vault_integration.py
CRED_ROUTER_IMPL=go     /tmp/opencode/litellm-venv/bin/python test_vault_integration.py
```

The two runs exercise the same scenarios against the same contract, which
is the point: the harness is what says the Python service is a **drop-in**
for the Go one, not merely a similar one.

## Reading secrets in-process

```python
from cred_router.vault.schema import FieldDef, Schema, Type
from cred_router.vault.vault import Config as VaultConfig
from cred_router.vault.vault import Vault

schema = Schema(version=1, fields=[
    FieldDef(name="kind", type=Type.STRING),
    FieldDef(name="secret", type=Type.BYTES, encrypted=True),
])
vault = Vault.open(VaultConfig(data_dir="/var/lib/credential-router/vault"), schema)
secret = vault.get("litellm/model/gpt-4o")
```

See `src/cred_router/litellm/` for the litellm adapter, which adds the
namespace filtering the proxy needs so that litellm's per-request lookups
never reach the store.

## Compatibility rules

These are not style preferences. Breaking one breaks a deployment that is
reading data written by the other implementation.

1. **The on-disk formats do not change.** The VREC container, the credential
   blob, the wrapped DEK and the key snapshot file are all fixed by the
   format. A change needs a migration on both sides.
2. **The SQLite DDL does not change.** Same tables, same columns, same
   indexes, same defaults.
3. **The key derivation does not change.** Same three shards, same XOR, same
   salt, same iteration count, same PRF per mode.
4. **The etcd keyspace does not change.** Same prefixes, same value
   encodings, same generation fence.
5. **The UDS frame format does not change.** Same length prefix, same JSON
   shape, same error codes.
