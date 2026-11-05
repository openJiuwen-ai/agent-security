"""Loading and validating the service's configuration.

The YAML keys, the defaults and the validation rules are shared with the
Go service: a file the Go binary accepts must be accepted here, and one
it refuses must be refused here for the same reason.

Durations are written the Go way — ``720h``, ``5m``, ``30s``, ``1h30m``.
A bare number is not a duration: Go's YAML decoder refuses to put an
integer into a duration field, and so does this.
"""

from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import yaml

from .errs import Code, ServiceError

__all__ = [
    "AdminConfig",
    "AuthRule",
    "BackupConfig",
    "CacheConfig",
    "ClusterConfig",
    "Config",
    "ConfigError",
    "DEFAULT_ADMIN_ADDR",
    "DEFAULT_ADMIN_API_KEY_MAX_LEN",
    "DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN",
    "DEFAULT_ADMIN_KEY_TAG_MAX_LEN",
    "DEFAULT_ADMIN_REAL_URL_MAX_LEN",
    "DEFAULT_ADMIN_USER_ID_MAX_LEN",
    "DEFAULT_BACKUP_DIR",
    "DEFAULT_BACKUP_FILENAME_TPL",
    "DEFAULT_BACKUP_KEEP",
    "DEFAULT_CACHE_ENTRY_TTL",
    "DEFAULT_CACHE_MAX_ENTRIES",
    "DEFAULT_CACHE_TOMBSTONE_TTL",
    "DEFAULT_CLUSTER_FETCH_TIMEOUT",
    "DEFAULT_CRYPTO_MODE",
    "DEFAULT_DATA_DIR",
    "DEFAULT_ETCD_DIAL_TIMEOUT",
    "DEFAULT_ETCD_LIST_LIMIT",
    "DEFAULT_ETCD_NAMESPACE",
    "DEFAULT_ETCD_OPERATION_TIMEOUT",
    "DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT",
    "DEFAULT_KEY_SNAPSHOT_ENABLED",
    "DEFAULT_KEY_SNAPSHOT_FILENAME_TPL",
    "DEFAULT_KEY_SNAPSHOT_KEEP",
    "DEFAULT_RECOVERY_MAX_WAIT",
    "DEFAULT_ROTATION_BARRIER_QUORUM_RATIO",
    "DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT",
    "DEFAULT_ROTATION_DRAIN_TIMEOUT",
    "DEFAULT_ROTATION_MAX_PHASE_A_LOOPS",
    "DEFAULT_ROTATION_PERIOD",
    "DEFAULT_SERVER_BIND_ADDRESS",
    "DEFAULT_SERVER_IDLE_CONN_TIMEOUT",
    "DEFAULT_SERVER_MAX_REQUEST_BYTES",
    "DEFAULT_SERVER_MAX_RESPONSE_BYTES",
    "DEFAULT_SERVER_READ_HEADER_TIMEOUT",
    "DEFAULT_SERVER_SHUTDOWN_TIMEOUT",
    "DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET",
    "DEFAULT_SSRF_CACHE_TTL",
    "DEFAULT_SSRF_DIAL_CHECK",
    "DEFAULT_SSRF_TIMEOUT",
    "DEFAULT_UPSTREAM_TIMEOUT_MS",
    "EtcdConfig",
    "EtcdTLSConfig",
    "KeySnapshotConfig",
    "RecoveryConfig",
    "RotationConfig",
    "SSRFConfig",
    "ServerConfig",
    "ValidationConfig",
    "VaultClientConfig",
    "VaultConfig",
    "VaultFieldConfig",
    "VaultRPCConfig",
    "VaultRotationConfig",
    "VaultSchemaConfig",
    "VaultUIDScopeConfig",
    "format_duration",
    "load",
    "load_for_store",
    "parse_duration",
    "Code",
    "ServiceError",
]



from .config_sections import (
    DEFAULT_UPSTREAM_TIMEOUT_MS,
    DEFAULT_DATA_DIR,
    DEFAULT_BACKUP_DIR,
    DEFAULT_CRYPTO_MODE,
    DEFAULT_ROTATION_PERIOD,
    DEFAULT_ROTATION_MAX_PHASE_A_LOOPS,
    DEFAULT_ROTATION_DRAIN_TIMEOUT,
    DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT,
    DEFAULT_ROTATION_BARRIER_QUORUM_RATIO,
    DEFAULT_CACHE_MAX_ENTRIES,
    DEFAULT_CACHE_TOMBSTONE_TTL,
    DEFAULT_CACHE_ENTRY_TTL,
    DEFAULT_ADMIN_ADDR,
    DEFAULT_ADMIN_USER_ID_MAX_LEN,
    DEFAULT_ADMIN_REAL_URL_MAX_LEN,
    DEFAULT_ADMIN_KEY_TAG_MAX_LEN,
    DEFAULT_ADMIN_API_KEY_MAX_LEN,
    DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN,
    DEFAULT_SSRF_DIAL_CHECK,
    DEFAULT_SSRF_CACHE_TTL,
    DEFAULT_SSRF_TIMEOUT,
    DEFAULT_SERVER_BIND_ADDRESS,
    DEFAULT_SERVER_MAX_RESPONSE_BYTES,
    DEFAULT_SERVER_MAX_REQUEST_BYTES,
    DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET,
    DEFAULT_SERVER_READ_HEADER_TIMEOUT,
    DEFAULT_SERVER_SHUTDOWN_TIMEOUT,
    DEFAULT_SERVER_IDLE_CONN_TIMEOUT,
    DEFAULT_BACKUP_KEEP,
    DEFAULT_BACKUP_FILENAME_TPL,
    DEFAULT_KEY_SNAPSHOT_ENABLED,
    DEFAULT_KEY_SNAPSHOT_FILENAME_TPL,
    DEFAULT_KEY_SNAPSHOT_KEEP,
    DEFAULT_RECOVERY_MAX_WAIT,
    DEFAULT_ETCD_NAMESPACE,
    DEFAULT_ETCD_OPERATION_TIMEOUT,
    DEFAULT_ETCD_DIAL_TIMEOUT,
    DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT,
    DEFAULT_ETCD_LIST_LIMIT,
    DEFAULT_CLUSTER_FETCH_TIMEOUT,
    ConfigError,
    parse_duration,
    _as_dict,
    _get,
    _as_str,
    _as_int,
    RotationConfig,
    CacheConfig,
    ValidationConfig,
    AuthRule,
    AdminConfig,
    SSRFConfig,
    ServerConfig,
    KeySnapshotConfig,
    BackupConfig,
    RecoveryConfig,
    EtcdTLSConfig,
    EtcdConfig,
    ClusterConfig,
    VaultUIDScopeConfig,
    VaultClientConfig,
    VaultRPCConfig,
    VaultFieldConfig,
    VaultSchemaConfig,
    VaultRotationConfig,
    VaultConfig,
)


def _format_frac(value: int, digits: int) -> str:
    """A whole part and a fraction with no trailing zeros."""
    whole, rest = divmod(value, 10 ** digits)
    if rest == 0:
        return str(whole)
    return f"{whole}.{rest:0{digits}d}".rstrip("0")


def format_duration(value: timedelta) -> str:
    """Render a duration the way Go's ``time.Duration.String`` does."""
    total_ns = (
        (value.days * 86_400 + value.seconds) * 1_000_000_000
        + value.microseconds * 1_000
    )
    if total_ns == 0:
        return "0s"
    sign = "-" if total_ns < 0 else ""
    total_ns = abs(total_ns)
    if total_ns < 1_000_000_000:
        if total_ns < 1_000_000:
            return f"{sign}{_format_frac(total_ns, 3)}µs"
        return f"{sign}{_format_frac(total_ns, 6)}ms"
    whole_seconds, nanos = divmod(total_ns, 1_000_000_000)
    seconds = str(whole_seconds % 60)
    if nanos:
        seconds += f".{nanos:09d}".rstrip("0")
    minutes = whole_seconds // 60
    if minutes == 0:
        return f"{sign}{seconds}s"
    if minutes < 60:
        return f"{sign}{minutes}m{seconds}s"
    hours, minute = divmod(minutes, 60)
    return f"{sign}{hours}h{minute}m{seconds}s"


# --- the whole configuration ------------------------------------------------
@dataclass
class Config:
    upstream_timeout_ms: int = DEFAULT_UPSTREAM_TIMEOUT_MS
    data_dir: str = DEFAULT_DATA_DIR
    backup_dir: str = DEFAULT_BACKUP_DIR
    crypto_mode: str = DEFAULT_CRYPTO_MODE

    rotation: RotationConfig = field(default_factory=RotationConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    admin: AdminConfig = field(default_factory=AdminConfig)
    ssrf: SSRFConfig = field(default_factory=SSRFConfig)
    server: ServerConfig = field(default_factory=ServerConfig)
    backup: BackupConfig = field(default_factory=BackupConfig)
    recovery: RecoveryConfig = field(default_factory=RecoveryConfig)
    etcd: EtcdConfig = field(default_factory=EtcdConfig)
    cluster: ClusterConfig = field(default_factory=ClusterConfig)
    vault: VaultConfig = field(default_factory=VaultConfig)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Config":
        raw = _as_dict(raw, "the configuration")
        return cls(
            upstream_timeout_ms=_as_int(
                _get(raw, "upstream_timeout_ms", DEFAULT_UPSTREAM_TIMEOUT_MS),
                "upstream_timeout_ms"),
            data_dir=_as_str(_get(raw, "data_dir", DEFAULT_DATA_DIR),
                             "data_dir"),
            backup_dir=_as_str(_get(raw, "backup_dir", DEFAULT_BACKUP_DIR),
                               "backup_dir"),
            crypto_mode=_as_str(_get(raw, "crypto_mode", DEFAULT_CRYPTO_MODE),
                                "crypto_mode"),
            rotation=RotationConfig.from_dict(_get(raw, "rotation", {})),
            cache=CacheConfig.from_dict(_get(raw, "cache", {})),
            admin=AdminConfig.from_dict(_get(raw, "admin", {})),
            ssrf=SSRFConfig.from_dict(_get(raw, "ssrf", {})),
            server=ServerConfig.from_dict(_get(raw, "server", {})),
            backup=BackupConfig.from_dict(_get(raw, "backup", {})),
            recovery=RecoveryConfig.from_dict(_get(raw, "recovery", {})),
            etcd=EtcdConfig.from_dict(_get(raw, "etcd", {})),
            cluster=ClusterConfig.from_dict(_get(raw, "cluster", {})),
            vault=VaultConfig.from_dict(_get(raw, "vault", {})),
        )

    # --- paths --------------------------------------------------------------

    def db_path(self) -> str:
        """The path of the router's credential database."""
        return os.path.join(self.data_dir, "credentials.db")

    def secrets_dir(self) -> str:
        """The directory holding the router's key shards."""
        return os.path.join(self.data_dir, "secrets")

    def vault_db_path(self) -> str:
        """The path of the vault's database."""
        return os.path.join(self.vault.data_dir, "vault.db")

    def vault_secrets_dir(self) -> str:
        """The directory holding the vault's key shards."""
        return os.path.join(self.vault.data_dir, "secrets")

    def upstream_timeout(self) -> timedelta:
        """The upstream timeout as a duration."""
        return timedelta(milliseconds=self.upstream_timeout_ms)

    # --- validation ---------------------------------------------------------

    def validate(self, *, serving: bool = True) -> None:
        """Refuse a configuration that would fail later in a worse way."""
        # "sm4" is the spelling the documentation uses; "sm" is the one
        # the crypto package speaks.  Both are accepted here and the load
        # path normalizes them to "sm", so that the value that reaches the
        # cipher is one the cipher understands.  The Go accepts the same
        # two spellings and normalizes them the same way.
        if self.crypto_mode.strip().lower() not in ("aes", "sm", "sm4"):
            raise ConfigError(
                "crypto_mode must be aes or sm, got "
                f"{self.crypto_mode!r}")

        if self.rotation.barrier_quorum_ratio <= 0 or \
                self.rotation.barrier_quorum_ratio > 1:
            raise ConfigError(
                "rotation.barrier_quorum_ratio must be greater than zero "
                "and at most one")
        if self.rotation.max_phase_a_loops <= 0:
            raise ConfigError("rotation.max_phase_a_loops must be positive")

        if self.cache.max_entries <= 0:
            raise ConfigError("cache.max_entries must be positive")

        self._validate_admin_addr()
        self._validate_server()
        self._validate_etcd()
        self._validate_cluster()
        self._validate_vault(serving=serving)

    def _validate_cluster(self) -> None:
        """Check the three things that would otherwise fail late."""
        node_id = self.cluster.node_id
        if not node_id:
            return
        if "/" in node_id or " " in node_id or node_id in (".", ".."):
            raise ConfigError(
                f"cluster.node_id {node_id!r} must not contain '/' or spaces; "
                "it forms an etcd key")
        if not self.etcd.enabled():
            raise ConfigError(
                "cluster.node_id is set but etcd.endpoints is empty; the peer "
                "roster lives in etcd")
        if not self.etcd.tls.cert_file.strip() or \
                not self.etcd.tls.key_file.strip():
            raise ConfigError(
                "cluster.node_id is set but etcd.tls.cert_file or "
                "etcd.tls.key_file is empty; the wrapping key is this node's "
                "own etcd client certificate, so there would be nothing to "
                "wrap with")

    def _validate_admin_addr(self) -> None:
        """The admin API has no authentication of its own."""
        addr = self.admin.addr.strip()
        if not addr:
            raise ConfigError("admin.addr is empty")
        host, _, _ = addr.rpartition(":")
        if not host:
            raise ConfigError(f"admin.addr {addr!r} is not host:port")
        if host in ("0.0.0.0", "::", "[::]"):
            raise ConfigError(
                f"admin.addr {addr!r} binds every interface; the admin API "
                "has no authentication, so it must not be reachable from "
                "the network")
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            # A hostname is fine as long as it is not obviously public.
            return
        if address.is_unspecified:
            raise ConfigError(
                f"admin.addr {addr!r} binds every interface; the admin API "
                "has no authentication, so it must not be reachable from "
                "the network")

    def _validate_server(self) -> None:
        bind = self.server.bind_address.strip()
        if not bind:
            raise ConfigError("server.bind_address is empty")
        host, _, _ = bind.rpartition(":")
        candidate = host.strip("[]")
        try:
            wildcard = not candidate or \
                ipaddress.ip_address(candidate).is_unspecified
        except ValueError:
            wildcard = host in ("", "0", "0.0.0.0", "::", "[::]")
        if wildcard and not self.server.external_address.strip():
            raise ConfigError(
                "server.external_address is required when "
                "server.bind_address is a wildcard address")
        external = self.server.external_address.strip()
        if external:
            if not external.startswith("http://") and \
                    not external.startswith("https://"):
                raise ConfigError(
                    "server.external_address must be an http or https URL")
        if self.server.max_response_bytes <= 0:
            raise ConfigError("server.max_response_bytes must be positive")
        if self.server.max_request_bytes <= 0:
            raise ConfigError("server.max_request_bytes must be positive")

    def _validate_etcd(self) -> None:
        if not self.etcd.enabled():
            return
        namespace = self.etcd.namespace
        if "/" in namespace or any(ch.isspace() for ch in namespace):
            raise ConfigError(
                "etcd.namespace must not contain a slash or whitespace")
        tls = self.etcd.tls
        if tls.any_set() and not tls.all_set():
            raise ConfigError(
                "etcd.tls needs all three of ca_file, cert_file and "
                "key_file; a partial set is refused rather than silently "
                "downgraded")
        if self.etcd.list_limit < 0:
            raise ConfigError("etcd.list_limit must not be negative")
        for index, endpoint in enumerate(self.etcd.endpoints):
            parsed = urlparse(endpoint)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ConfigError(
                    f"etcd.endpoints[{index}] {endpoint!r} must be an "
                    "http(s) URL")
        for name, value in (
            ("etcd.operation_timeout", self.etcd.operation_timeout),
            ("etcd.dial_timeout", self.etcd.dial_timeout),
            ("etcd.watch_liveness_timeout", self.etcd.watch_liveness_timeout),
        ):
            if value <= timedelta(0):
                raise ConfigError(f"{name} must be positive")

    def _validate_vault(self, *, serving: bool = True) -> None:
        vault = self.vault
        # Checked before the store is known to be on: a negative interval
        # is a typo, and the moment to catch it is while it is still
        # harmless, not once somebody turns the store on.  The Go checks
        # the same knob in the same place — the sibling ``rotation.period``
        # is validated unconditionally there too.
        if vault.rotation.period < 0:
            # Zero is the documented "not scheduled"; a negative period is
            # not another way of saying the same thing.
            raise ConfigError("vault.rotation.period must not be negative")
        if not vault.enabled():
            return
        if serving and not vault.rpc.unix_path.strip() and \
                not vault.rpc.tcp_addr.strip():
            raise ConfigError(
                "vault.data_dir is set but neither vault.rpc.unix_path nor "
                "vault.rpc.tcp_addr is; the store would be on with nothing "
                "answering it")
        if vault.rpc.unix_path.strip() and \
                not os.path.isabs(vault.rpc.unix_path.strip()):
            raise ConfigError(
                "vault.rpc.unix_path must be an absolute path: the socket is "
                "shared across processes and a relative path would resolve "
                "against each process's working directory")
        if vault.rpc.tcp_addr.strip():
            # A client that brings a secret of its own has no use for the
            # shared one, and the other way round: the two are ways of
            # saying the same thing, and saying both leaves it unclear
            # which one is in force.
            if vault.rpc.clients and vault.rpc.token_file.strip():
                raise ConfigError(
                    "vault.rpc.tcp_addr is set with both token_file and "
                    "clients; a client has a secret of its own, so the "
                    "shared one has no place")
            if not vault.rpc.clients and not vault.rpc.token_file.strip():
                raise ConfigError(
                    "vault.rpc.tcp_addr is set but vault.rpc.token_file is "
                    "empty; the tcp listener has no way to authenticate a client")
        if vault.rpc.socket_mode:
            try:
                mode = int(vault.rpc.socket_mode, 8)
            except ValueError:
                raise ConfigError(
                    f"vault.rpc.socket_mode {vault.rpc.socket_mode!r} is not "
                    "an octal mode") from None
            # The Go checks the low nine bits only: setuid, setgid and
            # sticky are not permission bits there, so a mode that carries
            # them is refused.
            if mode & ~0o777:
                raise ConfigError(
                    f"vault.rpc.socket_mode {vault.rpc.socket_mode!r} has "
                    "bits outside the permission bits")
        seen_clients: set[str] = set()
        for client in vault.rpc.clients:
            name = client.name.strip()
            if not name:
                raise ConfigError("vault.rpc.clients has a client with no name")
            if name in seen_clients:
                raise ConfigError(
                    f"vault.rpc.clients has two clients named {name!r}")
            seen_clients.add(name)
            if not client.token_file.strip():
                raise ConfigError(
                    f"vault.rpc.clients has a client {name!r} with no "
                    "token_file")
        seen_uids: set[int] = set()
        for scope in vault.rpc.uid_scopes:
            if scope.uid < 0:
                raise ConfigError("vault.rpc.uid_scopes.uid must not be negative")
            if scope.uid in seen_uids:
                raise ConfigError(
                    f"vault.rpc.uid_scopes has two entries for uid "
                    f"{scope.uid}")
            seen_uids.add(scope.uid)
            if not scope.prefixes:
                raise ConfigError(
                    f"vault.rpc.uid_scopes has a scope for uid {scope.uid} "
                    "with no prefixes; it would deny that user every record")
            for prefix in scope.prefixes:
                if not prefix.strip():
                    raise ConfigError(
                        "vault.rpc.uid_scopes has an empty prefix for uid "
                        f"{scope.uid}")
        self._validate_vault_schema(vault)

    @staticmethod
    def _validate_vault_schema(vault: "VaultConfig") -> None:
        """Check the record declaration.

        A store that is on with no declaration has no shape to enforce
        and no way to say which fields are encrypted, so it is refused
        at startup rather than left to fail on the first write.
        """
        schema = vault.schema
        if schema.version <= 0:
            raise ConfigError("vault.schema.version must be positive")
        if not schema.fields:
            raise ConfigError(
                "vault.schema.fields is empty; the store would hold records "
                "with no fields")
        seen: set[str] = set()
        for field_config in schema.fields:
            name = field_config.name.strip()
            if not name:
                raise ConfigError(
                    "vault.schema.fields has a field with no name")
            if name in seen:
                raise ConfigError(
                    f"vault.schema.fields declares {name!r} twice")
            seen.add(name)
            if field_config.type.strip() not in ("string", "bytes", "int64",
                                                 "bool"):
                raise ConfigError(
                    f"vault.schema.fields[{name!r}] has type "
                    f"{field_config.type!r}; it must be one of string, bytes, "
                    "int64, bool")


# --- loading ----------------------------------------------------------------


def load(path: str | os.PathLike[str]) -> Config:
    """Load and validate a configuration file."""
    return _load(path, serving=True)


def load_for_store(path: str | os.PathLike[str]) -> Config:
    """Load a configuration that only describes the store."""
    return _load(path, serving=False)


def _load(path: str | os.PathLike[str], *, serving: bool) -> Config:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = yaml.safe_load(f)
    except OSError as exc:
        raise ConfigError(f"read the configuration {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise ConfigError(f"parse the configuration {path}: {exc}") from exc
    if raw is None:
        raw = {}
    config = Config.from_dict(raw)
    _apply_load_defaults(config)
    if serving:
        _apply_vault_defaults(config)
    config.validate(serving=serving)
    return config


def _apply_load_defaults(config: Config) -> None:
    """Replace the values the Go's ``Load()`` replaces.

    The vault's own rotation period is the one value left alone: there,
    zero means "not scheduled" rather than "unset", so substituting a
    default would hand every deployment that never asked for a rotation
    one.
    """
    if config.upstream_timeout_ms <= 0:
        config.upstream_timeout_ms = DEFAULT_UPSTREAM_TIMEOUT_MS
    if not config.server.bind_address:
        config.server.bind_address = DEFAULT_SERVER_BIND_ADDRESS
    if not config.data_dir:
        config.data_dir = DEFAULT_DATA_DIR
    if not config.backup_dir:
        config.backup_dir = DEFAULT_BACKUP_DIR
    if not config.crypto_mode:
        config.crypto_mode = DEFAULT_CRYPTO_MODE
    # The cipher speaks "sm"; the documentation says "sm4".  The value that
    # leaves this function is the one the cipher is handed, so it is
    # normalized here rather than at every place that reads it.
    config.crypto_mode = config.crypto_mode.strip().lower()
    if config.crypto_mode == "sm4":
        config.crypto_mode = "sm"

    if config.rotation.period <= timedelta(0):
        config.rotation.period = DEFAULT_ROTATION_PERIOD
    if config.rotation.max_phase_a_loops <= 0:
        config.rotation.max_phase_a_loops = DEFAULT_ROTATION_MAX_PHASE_A_LOOPS
    if config.rotation.drain_timeout <= timedelta(0):
        config.rotation.drain_timeout = DEFAULT_ROTATION_DRAIN_TIMEOUT
    if config.rotation.complete_drain_timeout <= timedelta(0):
        config.rotation.complete_drain_timeout = \
            DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT
    if config.rotation.barrier_quorum_ratio <= 0:
        config.rotation.barrier_quorum_ratio = \
            DEFAULT_ROTATION_BARRIER_QUORUM_RATIO

    if config.cache.max_entries <= 0:
        config.cache.max_entries = DEFAULT_CACHE_MAX_ENTRIES
    if config.cache.tombstone_ttl <= timedelta(0):
        config.cache.tombstone_ttl = DEFAULT_CACHE_TOMBSTONE_TTL
    if config.cache.entry_ttl <= timedelta(0):
        config.cache.entry_ttl = DEFAULT_CACHE_ENTRY_TTL

    if not config.admin.addr:
        config.admin.addr = DEFAULT_ADMIN_ADDR
    if config.admin.validation.user_id_max_len <= 0:
        config.admin.validation.user_id_max_len = \
            DEFAULT_ADMIN_USER_ID_MAX_LEN
    if config.admin.validation.real_url_max_len <= 0:
        config.admin.validation.real_url_max_len = \
            DEFAULT_ADMIN_REAL_URL_MAX_LEN
    if config.admin.validation.key_tag_max_len <= 0:
        config.admin.validation.key_tag_max_len = \
            DEFAULT_ADMIN_KEY_TAG_MAX_LEN
    if config.admin.validation.api_key_max_len <= 0:
        config.admin.validation.api_key_max_len = \
            DEFAULT_ADMIN_API_KEY_MAX_LEN
    if config.admin.validation.auth_type_max_len <= 0:
        config.admin.validation.auth_type_max_len = \
            DEFAULT_ADMIN_AUTH_TYPE_MAX_LEN

    if config.server.max_response_bytes <= 0:
        config.server.max_response_bytes = DEFAULT_SERVER_MAX_RESPONSE_BYTES
    if config.server.max_request_bytes <= 0:
        config.server.max_request_bytes = DEFAULT_SERVER_MAX_REQUEST_BYTES
    if config.server.shutdown_zero_budget <= timedelta(0):
        config.server.shutdown_zero_budget = \
            DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET
    if config.server.read_header_timeout <= timedelta(0):
        config.server.read_header_timeout = \
            DEFAULT_SERVER_READ_HEADER_TIMEOUT
    if config.server.shutdown_timeout <= timedelta(0):
        config.server.shutdown_timeout = DEFAULT_SERVER_SHUTDOWN_TIMEOUT
    if config.server.idle_conn_timeout <= timedelta(0):
        config.server.idle_conn_timeout = DEFAULT_SERVER_IDLE_CONN_TIMEOUT

    if config.ssrf.cache_ttl <= timedelta(0):
        config.ssrf.cache_ttl = DEFAULT_SSRF_CACHE_TTL
    if config.ssrf.timeout <= timedelta(0):
        config.ssrf.timeout = DEFAULT_SSRF_TIMEOUT

    if config.backup.keep <= 0:
        config.backup.keep = DEFAULT_BACKUP_KEEP
    if not config.backup.filename_template:
        config.backup.filename_template = DEFAULT_BACKUP_FILENAME_TPL
    if not config.backup.key_snapshot.filename_template:
        config.backup.key_snapshot.filename_template = \
            DEFAULT_KEY_SNAPSHOT_FILENAME_TPL
    if config.backup.key_snapshot.keep <= 0:
        config.backup.key_snapshot.keep = DEFAULT_KEY_SNAPSHOT_KEEP

    if config.recovery.max_wait <= timedelta(0):
        config.recovery.max_wait = DEFAULT_RECOVERY_MAX_WAIT

    # Applied even when the section is off, so that an operator who later
    # adds endpoints does not inherit zero timeouts — the Go says the same.
    if not config.etcd.namespace:
        config.etcd.namespace = DEFAULT_ETCD_NAMESPACE
    if config.etcd.operation_timeout <= timedelta(0):
        config.etcd.operation_timeout = DEFAULT_ETCD_OPERATION_TIMEOUT
    if config.etcd.dial_timeout <= timedelta(0):
        config.etcd.dial_timeout = DEFAULT_ETCD_DIAL_TIMEOUT
    if config.etcd.watch_liveness_timeout <= timedelta(0):
        config.etcd.watch_liveness_timeout = \
            DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT
    # list_limit keeps its zero: it is a guard rail to opt into, not
    # something to have silently imposed at the 100k design target.

    if config.cluster.fetch_timeout <= timedelta(0):
        config.cluster.fetch_timeout = DEFAULT_CLUSTER_FETCH_TIMEOUT


def _apply_vault_defaults(config: Config) -> None:
    """Give an enabled store the local listener it did not name.

    Only the serving path gets it. The store-only configuration
    describes a store with **no** channel, and handing it a socket it
    will never open would be a lie about what the process is doing.
    """
    vault = config.vault
    if not vault.enabled():
        return
    if vault.rpc.unix_path.strip() or vault.rpc.tcp_addr.strip():
        return
    vault.rpc.unix_path = os.path.join(vault.data_dir, "vault.sock")
