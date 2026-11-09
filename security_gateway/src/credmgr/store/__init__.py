"""The SQLite persistence layer of the credential manager.

The Go original is the package ``internal/credmgr/store``; the database
written here is the same one the Go service writes, because one
implementation has to read the other's files.

The store is reached through two pools over one file: ``admin_db`` is the
write path and is kept small because SQLite has exactly one writer,
``proxy_db`` is the proxy's hot read path and is kept wide.  WAL mode is
what lets the two run at the same time.

A caller takes a connection from a pool as a lease; used as a context
manager it returns the connection to its pool on the way out.
"""

from __future__ import annotations

from .credentials import (
    PROXY_KEY_PREFIX,
    Credential,
    CredentialMethods,
    generate_proxy_key,
)
from .credentials_sync import (
    RECONCILE_BATCH_SIZE,
    SourceCredential,
    SourceCredentialMethods,
)
from .errors import (
    ClosedError,
    ConflictError,
    InvalidError,
    KeyMetadataEmptyError,
    NotFoundError,
    PhaseADecryptError,
    SourceIdentityConflictError,
    StoreError,
    SyncStateEmptyError,
    UniquenessConflictError,
    is_uniqueness_constraint_for,
)
from .key_metadata import (
    KEY_METADATA_ID,
    KeyMetadata,
    KeyMetadataMethods,
    set_reencrypt_phase_hook_for_testing,
)
from .store import (
    DEFAULT_ADMIN_MAX_CONNS,
    DEFAULT_PROXY_MAX_CONNS,
    MEMORY_DSN,
    ConnectionPool,
    OpenConfig,
    PooledConnection,
    Store,
    bootstrap_schema,
    transaction,
)
from .sync_state import SYNC_STATE_ID, SyncStateMethods

__all__ = [
    "DEFAULT_ADMIN_MAX_CONNS",
    "DEFAULT_PROXY_MAX_CONNS",
    "KEY_METADATA_ID",
    "MEMORY_DSN",
    "PROXY_KEY_PREFIX",
    "RECONCILE_BATCH_SIZE",
    "SYNC_STATE_ID",
    "ClosedError",
    "ConflictError",
    "ConnectionPool",
    "Credential",
    "CredentialMethods",
    "InvalidError",
    "KeyMetadata",
    "KeyMetadataEmptyError",
    "KeyMetadataMethods",
    "NotFoundError",
    "OpenConfig",
    "PhaseADecryptError",
    "PooledConnection",
    "SourceCredential",
    "SourceCredentialMethods",
    "SourceIdentityConflictError",
    "Store",
    "StoreError",
    "SyncStateEmptyError",
    "SyncStateMethods",
    "UniquenessConflictError",
    "bootstrap_schema",
    "generate_proxy_key",
    "is_uniqueness_constraint_for",
    "set_reencrypt_phase_hook_for_testing",
    "transaction",
]
