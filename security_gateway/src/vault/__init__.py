"""The generic encrypted field store.

Records are addressed by an indexed id. Each carries N fields described
by a schema the host declares in code; a field is either stored as-is or
encrypted under the store's data encryption key.

The package depends on the crypto primitives and on SQLite, and on
nothing else in this repository.

Scope for v1:

  - Records are addressed by id only. There is no query-by-field API,
    and therefore no secondary index.
  - The schema is fixed for the lifetime of a service. A schema that
    does not match the one the store was initialised with is refused at
    open time rather than migrated.
  - Encryption state is authoritative in the schema, not in the stored
    bytes. The stored bytes carry a flag that is cross-checked against
    the schema on read; a disagreement is an error, never a silent
    choice.
"""

from __future__ import annotations

from .codec import (
    CONTAINER_FORMAT,
    CONTAINER_HEADER_SIZE,
    CONTAINER_MAGIC,
    FLAG_ENCRYPTED,
    ContainerField,
    decode_container,
    encode_container,
)
from .errors import (
    ClosedError,
    ConflictError,
    InvalidError,
    InvalidRecordError,
    InvalidSchemaError,
    KeyMismatchError,
    NotFoundError,
    RotationInProgressError,
    SchemaMismatchError,
    StaleGenerationError,
    UndecryptableError,
    UnsupportedError,
    VaultError,
)
from .keys import (
    KEK_SALT,
    KEY_FILE_MODE,
    S3_SHARD,
    SHARD_SIZE,
    AdoptedDEK,
    KeyManager,
    KeyMeta,
    KeySnapshot,
    derive_kek,
    init_keys,
    load_snapshot,
    unpack_generation,
    unpack_snapshot,
    xor_three,
)
from .record import Record, Value
from .rotate import (
    RotationTarget,
    rotate_dek,
    start_auto_rotate,
    takeover_pending,
)
from .schema import (
    MAX_FIELD_NAME_LEN,
    FieldDef,
    Schema,
    Type,
    parse_schema,
)
from .store import (
    KEY_META_DDL,
    MIRROR_SYNC_STATE_ID,
    RECORD_DDL,
    SCHEMA_DDL,
    SYNC_STATE_DDL,
    Database,
    RecordRow,
    SchemaEntry,
    bootstrap_schema,
    count_records,
    count_stragglers,
    delete_record,
    get_record,
    insert_schema_entry,
    list_records,
    open_db,
    prefix_upper_bound,
    put_record,
    read_schema_entries,
    select_stragglers,
    update_record_cipher,
)
from .vault import (
    DEFAULT_DATA_DIR_PERM,
    DEFAULT_DB_NAME,
    DEFAULT_SECRETS_SUBDIR,
    ROTATION_BATCH_SIZE,
    Config,
    Entry,
    Status,
    Vault,
    check_data_dir,
    is_additive,
    set_put_before_write_hook,
)

__all__ = [
    "CONTAINER_FORMAT",
    "CONTAINER_HEADER_SIZE",
    "CONTAINER_MAGIC",
    "DEFAULT_DATA_DIR_PERM",
    "DEFAULT_DB_NAME",
    "DEFAULT_SECRETS_SUBDIR",
    "FLAG_ENCRYPTED",
    "KEY_FILE_MODE",
    "KEY_META_DDL",
    "KEK_SALT",
    "MAX_FIELD_NAME_LEN",
    "MIRROR_SYNC_STATE_ID",
    "RECORD_DDL",
    "ROTATION_BATCH_SIZE",
    "S3_SHARD",
    "SCHEMA_DDL",
    "SHARD_SIZE",
    "SYNC_STATE_DDL",
    "AdoptedDEK",
    "ClosedError",
    "Config",
    "ConflictError",
    "ContainerField",
    "Database",
    "Entry",
    "FieldDef",
    "InvalidError",
    "InvalidRecordError",
    "InvalidSchemaError",
    "KeyManager",
    "KeyMeta",
    "KeyMismatchError",
    "KeySnapshot",
    "NotFoundError",
    "Record",
    "RecordRow",
    "RotationInProgressError",
    "RotationTarget",
    "Schema",
    "SchemaEntry",
    "SchemaMismatchError",
    "StaleGenerationError",
    "Status",
    "Type",
    "UndecryptableError",
    "UnsupportedError",
    "Value",
    "Vault",
    "VaultError",
    "bootstrap_schema",
    "check_data_dir",
    "count_records",
    "count_stragglers",
    "decode_container",
    "delete_record",
    "derive_kek",
    "encode_container",
    "get_record",
    "init_keys",
    "insert_schema_entry",
    "is_additive",
    "list_records",
    "load_snapshot",
    "open_db",
    "parse_schema",
    "prefix_upper_bound",
    "put_record",
    "read_schema_entries",
    "rotate_dek",
    "select_stragglers",
    "set_put_before_write_hook",
    "start_auto_rotate",
    "takeover_pending",
    "unpack_generation",
    "unpack_snapshot",
    "update_record_cipher",
    "xor_three",
]
