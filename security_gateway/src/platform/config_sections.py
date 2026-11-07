"""The configuration schema.

Each section is one block of the YAML file, and each carries the rules
for its own keys.  The whole configuration is assembled from them, and
the loader lives beside them in ``config.py``.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from .errs import Code, ServiceError


DEFAULT_UPSTREAM_TIMEOUT_MS = 30000


DEFAULT_DATA_DIR = "./data"


DEFAULT_BACKUP_DIR = "./backups"


DEFAULT_CRYPTO_MODE = "aes"


DEFAULT_ROTATION_PERIOD = timedelta(hours=720)


DEFAULT_ROTATION_MAX_PHASE_A_LOOPS = 100


DEFAULT_ROTATION_DRAIN_TIMEOUT = timedelta(minutes=5)


DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT = timedelta(seconds=30)


DEFAULT_ROTATION_BARRIER_QUORUM_RATIO = 1.0 / 3.0  # Go 的 1.0/3.0，不是 0.333


DEFAULT_CACHE_MAX_ENTRIES = 10000


DEFAULT_CACHE_TOMBSTONE_TTL = timedelta(hours=1)


DEFAULT_CACHE_ENTRY_TTL = timedelta(minutes=10)


DEFAULT_ADMIN_ADDR = "127.0.0.1:8081"


DEFAULT_ADMIN_USER_ID_MAX_LEN = 256


DEFAULT_ADMIN_REAL_URL_MAX_LEN = 2048


DEFAULT_ADMIN_KEY_TAG_MAX_LEN = 64


DEFAULT_ADMIN_API_KEY_MAX_LEN = 8192


DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN = 16


DEFAULT_SSRF_DIAL_CHECK = False


DEFAULT_SSRF_CACHE_TTL = timedelta(seconds=30)


DEFAULT_SSRF_TIMEOUT = timedelta(seconds=5)


DEFAULT_SERVER_BIND_ADDRESS = "127.0.0.1:8080"


DEFAULT_SERVER_MAX_RESPONSE_BYTES = 10485760


DEFAULT_SERVER_MAX_REQUEST_BYTES = 10485760


DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET = timedelta(seconds=5)


DEFAULT_SERVER_READ_HEADER_TIMEOUT = timedelta(seconds=10)


DEFAULT_SERVER_SHUTDOWN_TIMEOUT = timedelta(seconds=10)


DEFAULT_SERVER_IDLE_CONN_TIMEOUT = timedelta(seconds=90)


DEFAULT_BACKUP_KEEP = 3


DEFAULT_BACKUP_FILENAME_TPL = "backup-{type}-{ts}.db"


DEFAULT_KEY_SNAPSHOT_ENABLED = True


DEFAULT_KEY_SNAPSHOT_FILENAME_TPL = "key-snapshot-{ts}.bin"


DEFAULT_KEY_SNAPSHOT_KEEP = 5


DEFAULT_RECOVERY_MAX_WAIT = timedelta(minutes=5)


DEFAULT_ETCD_NAMESPACE = "credential-router"


DEFAULT_ETCD_OPERATION_TIMEOUT = timedelta(seconds=10)


DEFAULT_ETCD_DIAL_TIMEOUT = timedelta(seconds=20)


DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT = timedelta(minutes=15)


DEFAULT_ETCD_LIST_LIMIT = 0  # 0 means unlimited


DEFAULT_CLUSTER_FETCH_TIMEOUT = timedelta(seconds=30)


class ConfigError(ServiceError):
    """The configuration is not usable."""

    def __init__(self, message: str) -> None:
        super().__init__(Code.BAD_REQUEST, "config", message)


_DURATION_UNITS = {
    "ns": 1,
    "us": 1_000,
    "µs": 1_000,
    "μs": 1_000,
    "ms": 1_000_000,
    "s": 1_000_000_000,
    "m": 60_000_000_000,
    "h": 3_600_000_000_000,
}


_DURATION_PART = re.compile(r"(\d+(?:\.\d*)?|\.\d+)([a-zµμ]+)")


_DURATION_NUMBER = re.compile(r"\d+(?:\.\d*)?|\.\d+")


def parse_duration(value: Any) -> timedelta:
    """Parse a duration the way Go's YAML decoder parses one.

    The grammar is the Go's, and it is narrow:

    * a **string** goes through ``time.ParseDuration``: a signed
      sequence of number-and-unit parts (``"720h"``, ``"1h30m"``,
      ``"30s"``) in which every number carries a unit.  The one number
      that may travel without one is the bare ``"0"``, which Go takes
      as zero;
    * a **number** is a type error.  ``yaml.v3`` will not put an
      ``!!int`` into a ``time.Duration``, so ``period: 30`` means the
      file is rejected — it does not mean thirty seconds, and it does
      not mean thirty nanoseconds;
    * **null** leaves the field alone, which for a fresh configuration
      means zero.

    A bare number is refused, and the message says why: reading one
    file into two configurations is worse than refusing it.
    """
    if isinstance(value, timedelta):
        return value
    if value is None:
        # yaml.v3 leaves a null field alone, and "alone" means the value the
        # field already had — zero for a configuration that was just built.
        return timedelta(0)
    if isinstance(value, bool) or not isinstance(value, str):
        raise ConfigError(
            f"invalid duration: {value!r} is not a duration string; write it "
            "as \"30s\", not as a bare number")

    text = value.strip()
    if not text:
        raise ConfigError("invalid duration: the value is empty")

    sign = 1
    if text[0] in "+-":
        sign = -1 if text[0] == "-" else 1
        text = text[1:]

    if text == "0":
        # The one number Go's ParseDuration accepts without a unit.
        return timedelta(0)

    total_ns = 0.0
    position = 0
    matched = False
    while position < len(text):
        match = _DURATION_PART.match(text, position)
        if match is None:
            if _DURATION_NUMBER.match(text, position):
                raise ConfigError(
                    f"invalid duration: {value!r} is missing a unit")
            raise ConfigError(f"invalid duration: {value!r}")
        number, unit = match.group(1), match.group(2)
        factor = _DURATION_UNITS.get(unit)
        if factor is None:
            raise ConfigError(
                f"invalid duration: unknown unit {unit!r} in {value!r}")
        total_ns += float(number) * factor
        position = match.end()
        matched = True

    if not matched:
        raise ConfigError(f"invalid duration: {value!r}")
    try:
        return timedelta(microseconds=sign * total_ns / 1000.0)
    except OverflowError:
        raise ConfigError(
            f"invalid duration: {value!r} is out of range") from None


def _as_dict(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ConfigError(f"{name} must be a mapping")
    return value


def _get(raw: dict[str, Any], key: str, default: Any) -> Any:
    value = raw.get(key)
    return default if value is None else value


def _as_str(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"{name} must be a string")
    return value


def _as_int(value: Any, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number")
    return int(value)


def _as_float(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{name} must be a number")
    number = float(value)
    if not math.isfinite(number):
        raise ConfigError(f"{name} must be a finite number")
    return number


def _as_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{name} must be true or false")
    return value


def _as_str_list(value: Any, name: str) -> list[str]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list")
    return [_as_str(item, f"{name} entry") for item in value]


def _as_int_list(value: Any, name: str) -> list[int]:
    if not isinstance(value, list):
        raise ConfigError(f"{name} must be a list")
    return [_as_int(item, f"{name} entry") for item in value]


@dataclass
class RotationConfig:
    period: timedelta = DEFAULT_ROTATION_PERIOD
    max_phase_a_loops: int = DEFAULT_ROTATION_MAX_PHASE_A_LOOPS
    drain_timeout: timedelta = DEFAULT_ROTATION_DRAIN_TIMEOUT
    complete_drain_timeout: timedelta = DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT
    barrier_quorum_ratio: float = DEFAULT_ROTATION_BARRIER_QUORUM_RATIO

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RotationConfig":
        raw = _as_dict(raw, "rotation")
        return cls(
            period=parse_duration(
                _get(raw, "period", DEFAULT_ROTATION_PERIOD)),
            max_phase_a_loops=_as_int(
                _get(raw, "max_phase_a_loops",
                      DEFAULT_ROTATION_MAX_PHASE_A_LOOPS),
                "rotation.max_phase_a_loops"),
            drain_timeout=parse_duration(
                _get(raw, "drain_timeout", DEFAULT_ROTATION_DRAIN_TIMEOUT)),
            complete_drain_timeout=parse_duration(
                _get(raw, "complete_drain_timeout",
                     DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT)),
            barrier_quorum_ratio=_as_float(
                _get(raw, "barrier_quorum_ratio",
                     DEFAULT_ROTATION_BARRIER_QUORUM_RATIO),
                "rotation.barrier_quorum_ratio"),
        )


@dataclass
class CacheConfig:
    max_entries: int = DEFAULT_CACHE_MAX_ENTRIES
    tombstone_ttl: timedelta = DEFAULT_CACHE_TOMBSTONE_TTL
    entry_ttl: timedelta = DEFAULT_CACHE_ENTRY_TTL

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "CacheConfig":
        raw = _as_dict(raw, "cache")
        return cls(
            max_entries=_as_int(
                _get(raw, "max_entries", DEFAULT_CACHE_MAX_ENTRIES),
                "cache.max_entries"),
            tombstone_ttl=parse_duration(
                _get(raw, "tombstone_ttl", DEFAULT_CACHE_TOMBSTONE_TTL)),
            entry_ttl=parse_duration(
                _get(raw, "entry_ttl", DEFAULT_CACHE_ENTRY_TTL)),
        )


@dataclass
class ValidationConfig:
    user_id_max_len: int = DEFAULT_ADMIN_USER_ID_MAX_LEN
    real_url_max_len: int = DEFAULT_ADMIN_REAL_URL_MAX_LEN
    key_tag_max_len: int = DEFAULT_ADMIN_KEY_TAG_MAX_LEN
    api_key_max_len: int = DEFAULT_ADMIN_API_KEY_MAX_LEN
    auth_type_max_len: int = DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ValidationConfig":
        raw = _as_dict(raw, "admin.validation")
        return cls(
            user_id_max_len=_as_int(
                _get(raw, "user_id_max_len", DEFAULT_ADMIN_USER_ID_MAX_LEN),
                "admin.validation.user_id_max_len"),
            real_url_max_len=_as_int(
                _get(raw, "real_url_max_len", DEFAULT_ADMIN_REAL_URL_MAX_LEN),
                "admin.validation.real_url_max_len"),
            key_tag_max_len=_as_int(
                _get(raw, "key_tag_max_len", DEFAULT_ADMIN_KEY_TAG_MAX_LEN),
                "admin.validation.key_tag_max_len"),
            api_key_max_len=_as_int(
                _get(raw, "api_key_max_len", DEFAULT_ADMIN_API_KEY_MAX_LEN),
                "admin.validation.api_key_max_len"),
            auth_type_max_len=_as_int(
                _get(raw, "auth_type_max_len", DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN),
                "admin.validation.auth_type_max_len"),
        )


@dataclass
class AuthRule:
    """How one auth_type puts the real key into a request."""

    header: str = ""
    prefix: str = ""
    query_params: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AuthRule":
        raw = _as_dict(raw, "auth rule")
        return cls(
            header=_as_str(_get(raw, "header", ""), "auth_types.header"),
            prefix=_as_str(_get(raw, "prefix", ""), "auth_types.prefix"),
            query_params=_as_str_list(
                _get(raw, "query_params", []), "auth_types.query_params"),
        )


@dataclass
class AdminConfig:
    addr: str = DEFAULT_ADMIN_ADDR
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    auth_types: dict[str, AuthRule] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "AdminConfig":
        raw = _as_dict(raw, "admin")
        rules_raw = _as_dict(_get(raw, "auth_types", {}), "admin.auth_types")
        rules = {
            name: AuthRule.from_dict(value)
            for name, value in rules_raw.items()
        }
        return cls(
            addr=_as_str(_get(raw, "addr", DEFAULT_ADMIN_ADDR), "admin.addr"),
            validation=ValidationConfig.from_dict(
                _get(raw, "validation", {})),
            auth_types=rules,
        )


@dataclass
class SSRFConfig:
    dial_check: bool = DEFAULT_SSRF_DIAL_CHECK
    allowed_hosts: list[str] = field(default_factory=list)
    cache_ttl: timedelta = DEFAULT_SSRF_CACHE_TTL
    timeout: timedelta = DEFAULT_SSRF_TIMEOUT

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "SSRFConfig":
        raw = _as_dict(raw, "ssrf")
        return cls(
            dial_check=_as_bool(
                _get(raw, "dial_check", DEFAULT_SSRF_DIAL_CHECK),
                "ssrf.dial_check"),
            allowed_hosts=_as_str_list(
                _get(raw, "allowed_hosts", []), "ssrf.allowed_hosts"),
            cache_ttl=parse_duration(
                _get(raw, "cache_ttl", DEFAULT_SSRF_CACHE_TTL)),
            timeout=parse_duration(
                _get(raw, "timeout", DEFAULT_SSRF_TIMEOUT)),
        )


@dataclass
class ServerConfig:
    bind_address: str = DEFAULT_SERVER_BIND_ADDRESS
    external_address: str = ""
    max_response_bytes: int = DEFAULT_SERVER_MAX_RESPONSE_BYTES
    max_request_bytes: int = DEFAULT_SERVER_MAX_REQUEST_BYTES
    shutdown_zero_budget: timedelta = DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET
    read_header_timeout: timedelta = DEFAULT_SERVER_READ_HEADER_TIMEOUT
    shutdown_timeout: timedelta = DEFAULT_SERVER_SHUTDOWN_TIMEOUT
    idle_conn_timeout: timedelta = DEFAULT_SERVER_IDLE_CONN_TIMEOUT
    log_file: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ServerConfig":
        raw = _as_dict(raw, "server")
        return cls(
            bind_address=_as_str(
                _get(raw, "bind_address", DEFAULT_SERVER_BIND_ADDRESS),
                "server.bind_address"),
            external_address=_as_str(
                _get(raw, "external_address", ""), "server.external_address"),
            max_response_bytes=_as_int(
                _get(raw, "max_response_bytes",
                     DEFAULT_SERVER_MAX_RESPONSE_BYTES),
                "server.max_response_bytes"),
            max_request_bytes=_as_int(
                _get(raw, "max_request_bytes",
                     DEFAULT_SERVER_MAX_REQUEST_BYTES),
                "server.max_request_bytes"),
            shutdown_zero_budget=parse_duration(
                _get(raw, "shutdown_zero_budget",
                     DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET)),
            read_header_timeout=parse_duration(
                _get(raw, "read_header_timeout",
                     DEFAULT_SERVER_READ_HEADER_TIMEOUT)),
            shutdown_timeout=parse_duration(
                _get(raw, "shutdown_timeout", DEFAULT_SERVER_SHUTDOWN_TIMEOUT)),
            idle_conn_timeout=parse_duration(
                _get(raw, "idle_conn_timeout",
                     DEFAULT_SERVER_IDLE_CONN_TIMEOUT)),
            log_file=_as_str(_get(raw, "log_file", ""), "server.log_file"),
        )


@dataclass
class KeySnapshotConfig:
    enabled: bool = DEFAULT_KEY_SNAPSHOT_ENABLED
    filename_template: str = DEFAULT_KEY_SNAPSHOT_FILENAME_TPL
    keep: int = DEFAULT_KEY_SNAPSHOT_KEEP

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "KeySnapshotConfig":
        raw = _as_dict(raw, "backup.key_snapshot")
        return cls(
            enabled=_as_bool(
                _get(raw, "enabled", DEFAULT_KEY_SNAPSHOT_ENABLED),
                "backup.key_snapshot.enabled"),
            filename_template=_as_str(
                _get(raw, "filename_template", DEFAULT_KEY_SNAPSHOT_FILENAME_TPL),
                "backup.key_snapshot.filename_template"),
            keep=_as_int(
                _get(raw, "keep", DEFAULT_KEY_SNAPSHOT_KEEP),
                "backup.key_snapshot.keep"),
        )


@dataclass
class BackupConfig:
    keep: int = DEFAULT_BACKUP_KEEP
    filename_template: str = DEFAULT_BACKUP_FILENAME_TPL
    key_snapshot: KeySnapshotConfig = field(default_factory=KeySnapshotConfig)

    @classmethod
    def from_dict(cls, raw: dict[str[str, Any], Any]) -> "BackupConfig":
        raw = _as_dict(raw, "backup")
        return cls(
            keep=_as_int(_get(raw, "keep", DEFAULT_BACKUP_KEEP),
                         "backup.keep"),
            filename_template=_as_str(
                _get(raw, "filename_template", DEFAULT_BACKUP_FILENAME_TPL),
                "backup.filename_template"),
            key_snapshot=KeySnapshotConfig.from_dict(
                _get(raw, "key_snapshot", {})),
        )


@dataclass
class RecoveryConfig:
    max_wait: timedelta = DEFAULT_RECOVERY_MAX_WAIT

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "RecoveryConfig":
        raw = _as_dict(raw, "recovery")
        return cls(
            max_wait=parse_duration(
                _get(raw, "max_wait", DEFAULT_RECOVERY_MAX_WAIT)),
        )


@dataclass
class EtcdTLSConfig:
    ca_file: str = ""
    cert_file: str = ""
    key_file: str = ""

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EtcdTLSConfig":
        raw = _as_dict(raw, "etcd.tls")
        return cls(
            ca_file=_as_str(_get(raw, "ca_file", ""), "etcd.tls.ca_file"),
            cert_file=_as_str(_get(raw, "cert_file", ""),
                              "etcd.tls.cert_file"),
            key_file=_as_str(_get(raw, "key_file", ""), "etcd.tls.key_file"),
        )

    def any_set(self) -> bool:
        return bool(self.ca_file or self.cert_file or self.key_file)

    def all_set(self) -> bool:
        return bool(self.ca_file and self.cert_file and self.key_file)


@dataclass
class EtcdConfig:
    endpoints: list[str] = field(default_factory=list)
    namespace: str = DEFAULT_ETCD_NAMESPACE
    operation_timeout: timedelta = DEFAULT_ETCD_OPERATION_TIMEOUT
    dial_timeout: timedelta = DEFAULT_ETCD_DIAL_TIMEOUT
    watch_liveness_timeout: timedelta = DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT
    list_limit: int = DEFAULT_ETCD_LIST_LIMIT
    tls: EtcdTLSConfig = field(default_factory=EtcdTLSConfig)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "EtcdConfig":
        raw = _as_dict(raw, "etcd")
        return cls(
            endpoints=_as_str_list(
                _get(raw, "endpoints", []), "etcd.endpoints"),
            namespace=_as_str(
                _get(raw, "namespace", DEFAULT_ETCD_NAMESPACE),
                "etcd.namespace"),
            operation_timeout=parse_duration(
                _get(raw, "operation_timeout", DEFAULT_ETCD_OPERATION_TIMEOUT)),
            dial_timeout=parse_duration(
                _get(raw, "dial_timeout", DEFAULT_ETCD_DIAL_TIMEOUT)),
            watch_liveness_timeout=parse_duration(
                _get(raw, "watch_liveness_timeout",
                     DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT)),
            list_limit=_as_int(
                _get(raw, "list_limit", DEFAULT_ETCD_LIST_LIMIT),
                "etcd.list_limit"),
            tls=EtcdTLSConfig.from_dict(_get(raw, "tls", {})),
        )

    def enabled(self) -> bool:
        """The etcd backend is on when endpoints were given."""
        return bool(self.endpoints)


@dataclass
class ClusterConfig:
    node_id: str = ""
    fetch_timeout: timedelta = timedelta(seconds=30)
    trusted_cert_sha256: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "ClusterConfig":
        raw = _as_dict(raw, "cluster")
        return cls(
            node_id=_as_str(_get(raw, "node_id", ""), "cluster.node_id"),
            fetch_timeout=parse_duration(
                _get(raw, "fetch_timeout", DEFAULT_CLUSTER_FETCH_TIMEOUT)),
            trusted_cert_sha256=_as_str_list(
                _get(raw, "trusted_cert_sha256", []),
                "cluster.trusted_cert_sha256"),
        )

    def enabled(self) -> bool:
        """The cluster is on when the node has an identity."""
        return bool(self.node_id)


@dataclass
class VaultUIDScopeConfig:
    uid: int = 0
    prefixes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultUIDScopeConfig":
        raw = _as_dict(raw, "vault.rpc.uid_scopes")
        return cls(
            uid=_as_int(_get(raw, "uid", 0), "vault.rpc.uid_scopes.uid"),
            prefixes=_as_str_list(
                _get(raw, "prefixes", []), "vault.rpc.uid_scopes.prefixes"),
        )


@dataclass
class VaultClientConfig:
    """One TCP client of the vault.

    Each has a secret of its own and, if it is given prefixes, a scope
    of its own: one shared secret would open the store to every client.
    """

    #: Who the client is. It appears in the log.
    name: str = ""

    #: The file the client's secret is read from.
    token_file: str = ""

    #: The beginnings of the record ids this client may touch. Empty means
    #: it may touch everything.
    prefixes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultClientConfig":
        raw = _as_dict(raw, "vault.rpc.clients")
        return cls(
            name=_as_str(_get(raw, "name", ""), "vault.rpc.clients.name"),
            token_file=_as_str(_get(raw, "token_file", ""),
                               "vault.rpc.clients.token_file"),
            prefixes=_as_str_list(
                _get(raw, "prefixes", []), "vault.rpc.clients.prefixes"),
        )


@dataclass
class VaultRPCConfig:
    unix_path: str = ""
    tcp_addr: str = ""
    token_file: str = ""
    allowed_uids: list[int] = field(default_factory=list)
    uid_scopes: list[VaultUIDScopeConfig] = field(default_factory=list)
    allow_unsafe_socket_dir: bool = False
    socket_mode: str = ""
    socket_group: str = ""
    clients: list[VaultClientConfig] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultRPCConfig":
        raw = _as_dict(raw, "vault.rpc")
        scopes_raw = _get(raw, "uid_scopes", [])
        if not isinstance(scopes_raw, list):
            raise ConfigError("vault.rpc.uid_scopes must be a list")
        clients_raw = _get(raw, "clients", [])
        if not isinstance(clients_raw, list):
            raise ConfigError("vault.rpc.clients must be a list")
        return cls(
            unix_path=_as_str(_get(raw, "unix_path", ""),
                              "vault.rpc.unix_path"),
            tcp_addr=_as_str(_get(raw, "tcp_addr", ""), "vault.rpc.tcp_addr"),
            token_file=_as_str(_get(raw, "token_file", ""),
                               "vault.rpc.token_file"),
            allowed_uids=_as_int_list(
                _get(raw, "allowed_uids", []), "vault.rpc.allowed_uids"),
            uid_scopes=[
                VaultUIDScopeConfig.from_dict(item) for item in scopes_raw
            ],
            allow_unsafe_socket_dir=_as_bool(
                _get(raw, "allow_unsafe_socket_dir", False),
                "vault.rpc.allow_unsafe_socket_dir"),
            socket_mode=_as_str(_get(raw, "socket_mode", ""),
                                "vault.rpc.socket_mode"),
            socket_group=_as_str(_get(raw, "socket_group", ""),
                                 "vault.rpc.socket_group"),
            clients=[VaultClientConfig.from_dict(item) for item in clients_raw],
        )


@dataclass
class VaultFieldConfig:
    name: str = ""
    type: str = ""
    encrypted: bool = False

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultFieldConfig":
        raw = _as_dict(raw, "vault.schema.fields")
        return cls(
            name=_as_str(_get(raw, "name", ""), "vault.schema.fields.name"),
            type=_as_str(_get(raw, "type", ""), "vault.schema.fields.type"),
            encrypted=_as_bool(_get(raw, "encrypted", False),
                               "vault.schema.fields.encrypted"),
        )


@dataclass
class VaultSchemaConfig:
    version: int = 0
    fields: list[VaultFieldConfig] = field(default_factory=list)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultSchemaConfig":
        raw = _as_dict(raw, "vault.schema")
        fields_raw = _get(raw, "fields", [])
        if not isinstance(fields_raw, list):
            raise ConfigError("vault.schema.fields must be a list")
        return cls(
            version=_as_int(_get(raw, "version", 0), "vault.schema.version"),
            fields=[VaultFieldConfig.from_dict(item) for item in fields_raw],
        )


@dataclass
class VaultRotationConfig:
    #: How often the store's DEK is rotated, in seconds. Zero means the
    #: rotation is not scheduled: the capability exists, and whoever wants
    #: it attaches it.
    period: float = 0.0

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultRotationConfig":
        raw = _as_dict(raw, "vault.rotation")
        return cls(
            # The default is the zero *duration*, the way the Go's
            # DefaultVaultRotationPeriod is the zero time.Duration: a bare
            # zero here would be a number, and a number is not a duration.
            period=parse_duration(
                _get(raw, "period", timedelta(0))).total_seconds(),
        )


@dataclass
class VaultConfig:
    data_dir: str = ""
    rpc: VaultRPCConfig = field(default_factory=VaultRPCConfig)
    schema: VaultSchemaConfig = field(default_factory=VaultSchemaConfig)
    rotation: VaultRotationConfig = field(default_factory=VaultRotationConfig)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "VaultConfig":
        raw = _as_dict(raw, "vault")
        return cls(
            data_dir=_as_str(_get(raw, "data_dir", ""), "vault.data_dir"),
            rpc=VaultRPCConfig.from_dict(_get(raw, "rpc", {})),
            schema=VaultSchemaConfig.from_dict(_get(raw, "schema", {})),
            rotation=VaultRotationConfig.from_dict(_get(raw, "rotation", {})),
        )

    def enabled(self) -> bool:
        """The vault is on when it was given a data directory."""
        return bool(self.data_dir)
