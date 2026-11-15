"""The store's own shapes: its settings, its state, and its listings.

The vault module grew past the size one change should touch, so the
parts of it that are not the store's behaviour moved out here. This
module holds the three dataclasses the store takes in and hands back —
the operational settings it was opened with, the state it reports, and
the record a listing carries — together with the constants that name
its files and bound its rotation.

None of it behaves. A dataclass and a constant are what they are, and
the store's behaviour stays in the vault module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from security_gateway.crypto import Mode

from .record import Value

__all__ = [
    "DEFAULT_DATA_DIR_PERM",
    "DEFAULT_DB_NAME",
    "DEFAULT_SECRETS_SUBDIR",
    "ROTATION_BATCH_SIZE",
    "Config",
    "Entry",
    "Status",
]

#: The database file's name inside the data directory.
DEFAULT_DB_NAME = "vault.db"

#: The permissions the data directory and the secrets directory get.
DEFAULT_DATA_DIR_PERM = 0o700

#: The name of the secrets directory inside the data directory.
DEFAULT_SECRETS_SUBDIR = "secrets"

#: How many records one pass of the re-encryption loop takes at a time.
#:
#: The batch is bounded so the database's write lock is not held for the
#: whole store: a rotation of a large vault would otherwise stall every
#: writer for the length of the re-encryption.
ROTATION_BATCH_SIZE = 100


@dataclass
class Config:
    """The store's operational settings.

    Config is per-deployment operational state — where the files live,
    which cipher to use — and the host service supplies it from whatever
    configuration system it already has. The schema is the record's data
    model and lives somewhere else entirely.
    """

    #: The directory the store keeps its database and secrets under. It is
    #: created if it does not exist.
    data_dir: str

    #: The SQLite database file. Defaults to ``<data_dir>/vault.db``.
    db_path: str = ""

    #: The cipher used for the store's data encryption key. Defaults to
    #: AES. The mode is fixed when the store is initialised and cannot be
    #: changed afterwards.
    crypto_mode: Mode = Mode.AES

    #: The automatic DEK rotation period in seconds. Zero disables it.
    #: The value is part of the store's identity: every process opening
    #: the same database has to agree on it.
    rotation_period: float = 0.0

    #: Makes etcd the write authority for the store's records.
    #:
    #: It is ``None`` for a standalone store, and that is the only
    #: difference between the two modes: an etcd-backed store writes
    #: through the authority and its local copy is a mirror that catches
    #: up through a watch.
    #:
    #: The type is :class:`security_gateway.vault.etcd.EtcdConfig`, and it is
    #: left untyped here so that importing this module does not drag the
    #: etcd half in.
    etcd: Any = None

    #: Whether processes on one host share this store. They then share
    #: the data directory and key metadata; a host-local leader only
    #: mints the first key. Off by default.
    multi_process: bool = False

    #: The maximum number of decrypted records kept in the read cache.
    #: Zero disables the cache.
    cache_max_entries: int = 0

    #: How long a cached record stays valid, in seconds. Zero means it
    #: does not expire; it is still evicted by writes, deletes, mirror
    #: changes and LRU pressure.
    cache_ttl: float = 0.0


@dataclass
class Status:
    """The store's current state."""

    #: The version of the schema the store writes with.
    schema_version: int = 0

    #: The hex SHA-256 of that schema's canonical form.
    schema_hash: str = ""

    #: The generation of the current data encryption key.
    dek_version: int = 0

    #: The cipher in use.
    crypto_mode: str = ""

    #: The number of records held.
    record_count: int = 0

    #: The number of records still encrypted under an older key generation.
    #: It is zero in steady state.
    straggler_count: int = 0

    #: The unix time of the last successful DEK rotation, or 0 if none.
    last_rotate_at: int = 0

    #: The configured automatic DEK rotation period in seconds.
    rotation_period: float = 0.0


@dataclass
class Entry:
    """A listed record: its id and the fields the schema does not mark encrypted.

    The encrypted fields are left out on purpose: a listing is a way to
    see what the store holds, not a way to read every secret in it.
    """

    id: str
    fields: dict[str, Value] = field(default_factory=dict)
