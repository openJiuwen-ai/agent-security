"""The configuration surface.

The Go counterpart is ``internal/platform/config.go``. A configuration file
that the Go binary accepts must be accepted here, and one it refuses must
be refused here for the same reason.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from security_gateway.platform.config import (
    Config,
    ConfigError,
    format_duration,
    load,
    load_for_store,
    parse_duration,
)

# --- durations --------------------------------------------------------------


@pytest.mark.parametrize(
    "text,nanoseconds",
    [
        ("720h", 720 * 3600 * 1_000_000_000),
        ("5m", 5 * 60 * 1_000_000_000),
        ("30s", 30 * 1_000_000_000),
        ("1h30m", 90 * 60 * 1_000_000_000),
        ("500ms", 500 * 1_000_000),
        ("100us", 100 * 1_000),
        ("42ns", 42),
    ],
)
def test_a_go_duration_string_is_parsed(text, nanoseconds):
    assert parse_duration(text) == timedelta(microseconds=nanoseconds / 1000)


def test_a_bare_number_is_refused():
    """A number is not a duration.

    The Go's YAML decoder puts a ``time.Duration`` into a duration field
    only from a string; an ``!!int`` there is a type error and the file is
    rejected.  Reading ``30`` as thirty nanoseconds would be worse than
    refusing it, because it looks like it worked.
    """
    with pytest.raises(ConfigError):
        parse_duration(1_000_000_000)
    with pytest.raises(ConfigError):
        parse_duration(30)
    with pytest.raises(ConfigError):
        parse_duration(1.5)


def test_the_bare_zero_is_the_one_number_go_accepts():
    """Go's ``ParseDuration`` special-cases a bare ``"0"``."""
    assert parse_duration("0") == timedelta(0)
    assert parse_duration("+0") == timedelta(0)
    assert parse_duration("-0") == timedelta(0)


def test_a_null_duration_is_zero():
    """yaml.v3 leaves a null field alone, which for a fresh field is zero."""
    assert parse_duration(None) == timedelta(0)


def test_a_negative_duration_is_allowed():
    assert parse_duration("-5m") == timedelta(minutes=-5)


def test_a_duration_renders_the_go_way():
    assert format_duration(timedelta(hours=720)) == "720h0m0s"
    assert format_duration(timedelta(seconds=30)) == "30s"
    assert format_duration(timedelta(0)) == "0s"


@pytest.mark.parametrize("bad", ["", "5", "5x", "h", "5 h", "00", "1.2.3s"])
def test_a_broken_duration_is_refused(bad):
    with pytest.raises(ConfigError):
        parse_duration(bad)


def test_a_number_without_a_unit_says_so():
    """A missing unit is a different mistake from an unknown one."""
    with pytest.raises(ConfigError) as refused:
        parse_duration("30")
    assert "missing a unit" in str(refused.value)

    with pytest.raises(ConfigError) as refused:
        parse_duration("30x")
    assert "unknown unit" in str(refused.value)


# --- the defaults -----------------------------------------------------------


def test_the_defaults_match_the_go_service():
    config = Config()
    assert config.upstream_timeout_ms == 30000
    assert config.data_dir == "./data"
    assert config.backup_dir == "./backups"
    assert config.crypto_mode == "aes"
    assert config.rotation.period == timedelta(hours=720)
    assert config.rotation.max_phase_a_loops == 100
    assert config.rotation.drain_timeout == timedelta(minutes=5)
    assert config.rotation.complete_drain_timeout == timedelta(seconds=30)
    # The Go's default is 1.0/3.0, not the 0.333 the documentation
    # rounds it to.
    assert config.rotation.barrier_quorum_ratio == 1.0 / 3.0
    assert config.cache.max_entries == 10000
    assert config.cache.tombstone_ttl == timedelta(hours=1)
    assert config.cache.entry_ttl == timedelta(minutes=10)
    assert config.ssrf.dial_check is False
    assert config.ssrf.cache_ttl == timedelta(seconds=30)
    assert config.ssrf.timeout == timedelta(seconds=5)
    assert config.server.max_response_bytes == 10485760
    assert config.server.max_request_bytes == 10485760
    assert config.server.shutdown_zero_budget == timedelta(seconds=5)
    assert config.server.read_header_timeout == timedelta(seconds=10)
    assert config.server.shutdown_timeout == timedelta(seconds=10)
    assert config.server.idle_conn_timeout == timedelta(seconds=90)
    assert config.backup.keep == 3
    assert config.backup.filename_template == "backup-{type}-{ts}.db"
    assert config.backup.key_snapshot.enabled is True
    assert config.backup.key_snapshot.filename_template == "key-snapshot-{ts}.bin"
    assert config.backup.key_snapshot.keep == 5
    assert config.recovery.max_wait == timedelta(minutes=5)
    assert config.etcd.list_limit == 0


def test_the_defaults_are_a_usable_configuration():
    Config().validate()


# --- what turns each feature on --------------------------------------------


def test_etcd_is_on_when_endpoints_are_given():
    assert not Config().etcd.enabled()
    assert Config.from_dict({"etcd": {"endpoints": ["http://x:2379"]}}).etcd.enabled()


def test_etcd_defaults_to_the_security_gateway_namespace():
    assert Config().etcd.namespace == "security_gateway"


def test_etcd_without_a_node_id_is_refused():
    config = Config.from_dict({"etcd": {"endpoints": ["http://x:2379"]}})
    with pytest.raises(ConfigError, match="node_id"):
        config.validate()


def test_the_cluster_is_on_when_the_node_has_an_identity():
    assert not Config().cluster.enabled()
    assert Config.from_dict({"cluster": {"node_id": "n1"}}).cluster.enabled()


def test_the_vault_is_on_when_it_has_a_data_directory():
    assert not Config().vault.enabled()
    raw = {"vault": {"data_dir": "/srv/vault", "rpc": {"unix_path": "/run/vault.sock"}}}
    assert Config.from_dict(raw).vault.enabled()


def test_the_vault_can_share_its_store_between_host_processes():
    assert not Config().vault.multi_process
    raw = {
        "vault": {
            "data_dir": "/srv/vault",
            "rpc": {"unix_path": "/run/vault.sock"},
            "multi_process": True,
        }
    }
    assert Config.from_dict(raw).vault.multi_process


# --- the paths --------------------------------------------------------------


def test_the_paths_are_derived_from_the_data_directories():
    config = Config.from_dict(
        {
            "data_dir": "/srv/data",
            "vault": {
                "data_dir": "/srv/vault",
                "rpc": {"unix_path": "/run/vault.sock"},
            },
        }
    )
    assert config.db_path() == "/srv/data/credentials.db"
    assert config.secrets_dir() == "/srv/data/secrets"
    assert config.vault_db_path() == "/srv/vault/vault.db"
    assert config.vault_secrets_dir() == "/srv/vault/secrets"


# --- the refusals -----------------------------------------------------------


def test_an_unknown_crypto_mode_is_refused():
    with pytest.raises(ConfigError):
        Config.from_dict({"crypto_mode": "rot13"}).validate()


def test_the_admin_api_may_not_bind_every_interface():
    """The admin API has no authentication, so it must not be reachable."""
    with pytest.raises(ConfigError):
        Config.from_dict({"admin": {"addr": "0.0.0.0:8080"}}).validate()
    with pytest.raises(ConfigError):
        Config.from_dict({"admin": {"addr": "[::]:8080"}}).validate()


def test_the_admin_api_may_bind_a_private_address():
    Config.from_dict({"admin": {"addr": "127.0.0.1:8080"}}).validate()
    Config.from_dict({"admin": {"addr": ".".join(["10", "0", "0", "5"]) + ":8080"}}).validate()


def test_an_external_address_is_required_when_the_bind_is_a_wildcard():
    with pytest.raises(ConfigError):
        Config.from_dict({"server": {"bind_address": "0.0.0.0:8080"}}).validate()
    Config.from_dict(
        {
            "server": {
                "bind_address": "0.0.0.0:8080",
                "external_address": "https://router.example",
            },
        }
    ).validate()


def test_the_external_address_must_be_an_http_url():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "server": {
                    "bind_address": "0.0.0.0:8080",
                    "external_address": "ftp://router.example",
                },
            }
        ).validate()


def test_the_etcd_namespace_may_not_contain_a_slash_or_whitespace():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "etcd": {"endpoints": ["http://x:2379"], "namespace": "a/b"},
            }
        ).validate()
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "etcd": {"endpoints": ["http://x:2379"], "namespace": "a b"},
            }
        ).validate()


def test_a_partial_etcd_tls_set_is_refused():
    """A partial set is refused rather than silently downgraded."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "etcd": {"endpoints": ["http://x:2379"], "tls": {"ca_file": "/ca.pem"}},
            }
        ).validate()
    Config.from_dict(
        {
            "etcd": {
                "endpoints": ["http://x:2379"],
                "tls": {
                    "ca_file": "/ca.pem",
                    "cert_file": "/c.pem",
                    "key_file": "/k.pem",
                },
            },
            "cluster": {"node_id": "node-a", "identity_ca_file": "/id-ca.pem"},
        }
    ).validate()


def test_a_vault_with_a_data_directory_needs_a_listener():
    with pytest.raises(ConfigError):
        Config.from_dict({"vault": {"data_dir": "/srv/vault"}}).validate()


def test_a_client_that_opens_the_store_itself_needs_no_listener():
    """The store with nobody to answer it is a server's mistake, not a client's.

    A process that opens the store in its own memory *is* the answer, so it
    must not be made to declare a listener it will never open — and the
    credential-router service must not open a socket nobody asked for.
    """
    config = Config.from_dict(
        {"vault": {"data_dir": "/srv/vault", "schema": _a_schema()}}
    )
    config.validate(serving=False)
    assert config.vault.data_dir == "/srv/vault"


def test_a_client_still_refuses_a_broken_vault():
    """Only the listener is waived; the other rules are not."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {"data_dir": "/srv/vault", "rpc": {"unix_path": "vault.sock"}},
            }
        ).validate(serving=False)


def test_the_vault_socket_path_must_be_absolute():
    """The socket is shared across processes; a relative path would not be."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {"data_dir": "/srv/vault", "rpc": {"unix_path": "vault.sock"}},
            }
        ).validate()


def test_a_tcp_vault_needs_a_token_or_clients():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {"tcp_addr": "127.0.0.1:19000"},
                },
            }
        ).validate()


def test_the_clients_are_enough_without_a_shared_token():
    """Each client brings a secret of its own; the shared one is not needed."""
    Config.from_dict(
        {
            "vault": {
                "data_dir": "/srv/vault",
                "schema": _a_schema(),
                "rpc": {
                    "tcp_addr": "127.0.0.1:19000",
                    "clients": [
                        {"name": "backend", "token_file": "/etc/backend.token"}
                    ],
                },
            },
        }
    ).validate()


def test_the_shared_token_and_the_clients_are_mutually_exclusive():
    """The two are ways of saying the same thing; saying both says nothing."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {
                        "tcp_addr": "127.0.0.1:19000",
                        "token_file": "/etc/shared.token",
                        "clients": [
                            {"name": "backend", "token_file": "/etc/backend.token"}
                        ],
                    },
                },
            }
        ).validate()


def test_the_clients_are_read():
    config = Config.from_dict(
        {
            "vault": {
                "data_dir": "/srv/vault",
                "rpc": {
                    "tcp_addr": "127.0.0.1:19000",
                    "clients": [
                        {
                            "name": "backend",
                            "token_file": "/etc/backend.token",
                            "prefixes": ["litellm/"],
                        },
                        {"name": "litellm", "token_file": "/etc/litellm.token"},
                    ],
                },
            },
        }
    )
    clients = config.vault.rpc.clients
    assert len(clients) == 2
    assert clients[0].name == "backend"
    assert clients[0].token_file == "/etc/backend.token"
    assert clients[0].prefixes == ["litellm/"]
    assert clients[1].name == "litellm"
    assert clients[1].prefixes == []


def test_a_client_without_a_name_is_refused():
    """The name is what a refused request is reported against."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {
                        "tcp_addr": "127.0.0.1:19000",
                        "clients": [{"name": "  ", "token_file": "/etc/backend.token"}],
                    },
                },
            }
        ).validate()


def test_two_clients_with_the_same_name_are_refused():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {
                        "tcp_addr": "127.0.0.1:19000",
                        "clients": [
                            {"name": "backend", "token_file": "/etc/backend.token"},
                            {"name": "backend", "token_file": "/etc/other.token"},
                        ],
                    },
                },
            }
        ).validate()


def test_a_client_without_a_token_file_is_refused():
    """A client with no secret of its own would fall back to the shared one."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {
                        "tcp_addr": "127.0.0.1:19000",
                        "clients": [{"name": "backend"}],
                    },
                },
            }
        ).validate()


def test_two_scopes_for_the_same_uid_are_refused():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {
                        "unix_path": "/run/vault.sock",
                        "uid_scopes": [
                            {"uid": 1000, "prefixes": ["a/"]},
                            {"uid": 1000, "prefixes": ["b/"]},
                        ],
                    },
                },
            }
        ).validate()


def test_the_socket_mode_must_be_octal_and_within_the_permission_bits():
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {"unix_path": "/run/vault.sock", "socket_mode": "not-octal"},
                },
            }
        ).validate()
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {"unix_path": "/run/vault.sock", "socket_mode": "10000"},
                },
            }
        ).validate()


# --- the auth rules ---------------------------------------------------------


def test_the_auth_rules_are_read():
    config = Config.from_dict(
        {
            "admin": {
                "auth_types": {
                    "my_type": {
                        "header": "X-Key",
                        "prefix": "Bearer ",
                        "query_params": ["k"],
                    }
                }
            },
        }
    )
    rule = config.admin.auth_types["my_type"]
    assert rule.header == "X-Key"
    assert rule.prefix == "Bearer "
    assert rule.query_params == ["k"]


# --- the vault's rotation schedule -------------------------------------------


def test_the_vault_rotation_period_defaults_to_zero():
    """Zero means the rotation is not scheduled.

    The capability exists, and whoever wants it attaches it — so a
    deployment that says nothing gets the behaviour it has today.
    """
    assert Config().vault.rotation.period == 0.0


def test_the_vault_rotation_period_is_read():
    """The period is a duration, like the other knobs."""
    config = Config.from_dict(
        {
            "vault": {
                "data_dir": "/srv/vault",
                "rpc": {"unix_path": "/run/vault.sock"},
                "rotation": {"period": "720h"},
            },
        }
    )
    assert config.vault.rotation.period == 720 * 3600


def test_a_negative_vault_rotation_period_is_refused():
    """Zero is "not scheduled"; a negative period is not another way of
    saying the same thing."""
    with pytest.raises(ConfigError):
        Config.from_dict(
            {
                "vault": {
                    "data_dir": "/srv/vault",
                    "rpc": {"unix_path": "/run/vault.sock"},
                    "rotation": {"period": "-5m"},
                },
            }
        ).validate()


def test_a_negative_vault_rotation_period_is_refused_even_when_the_store_is_off():
    """A negative interval is a typo, and the store being off does not make
    it a valid one.

    The check runs whether the store is on or off, the way the Go's does:
    the sibling ``rotation.period`` is validated unconditionally there, and
    catching the typo while the store is off is the better time to catch
    it.
    """
    with pytest.raises(ConfigError) as refused:
        Config.from_dict(
            {
                "vault": {"rotation": {"period": "-5m"}},
            }
        ).validate()
    assert "vault.rotation.period" in str(refused.value)


# --- the socket an enabled store gets ---------------------------------------


def _a_schema() -> dict:
    """A record declaration the Go would accept as well.

    A store that is on needs a declaration: the Go refuses one without a
    schema, so a fixture that turns the store on has to say what the
    records look like.
    """
    return {
        "version": 1,
        "fields": [{"name": "secret", "type": "bytes", "encrypted": True}],
    }


def _write_a_config(tmp_path, vault: dict) -> Path:
    """A configuration file with the given vault section."""
    import yaml

    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "data_dir": str(tmp_path / "data"),
                "backup_dir": str(tmp_path / "backups"),
                "vault": vault,
            }
        ),
        encoding="utf-8",
    )
    return path


def test_an_enabled_store_with_no_listener_gets_the_local_socket(tmp_path):
    """The Go's ``Load()`` gives an enabled store the socket it did not name.

    A store that is on with nothing answering it can only be a mistake,
    so it gets the socket inside its own directory.  The Go does the same,
    and the two must not drift: a configuration the Go starts on is a
    configuration this side starts on too.
    """
    path = _write_a_config(
        tmp_path, {"data_dir": str(tmp_path / "vault"), "schema": _a_schema()}
    )

    config = load(str(path))

    assert config.vault.rpc.unix_path == str(tmp_path / "vault" / "vault.sock")


def test_the_store_only_configuration_names_no_channel(tmp_path):
    """The store-only path describes a store with no channel.

    It must not be handed a socket path it will never open: this process
    is the answer, and there is no socket.
    """
    path = _write_a_config(
        tmp_path, {"data_dir": str(tmp_path / "vault"), "schema": _a_schema()}
    )

    config = load_for_store(str(path))

    assert config.vault.rpc.unix_path == ""


def test_a_named_tcp_listener_is_not_joined_by_a_unix_socket(tmp_path):
    """The local socket is a default, not something added to a choice."""
    path = _write_a_config(
        tmp_path,
        {
            "data_dir": str(tmp_path / "vault"),
            "schema": _a_schema(),
            "rpc": {"tcp_addr": "127.0.0.1:19000", "token_file": "/etc/vault.token"},
        },
    )

    config = load(str(path))

    assert config.vault.rpc.unix_path == ""
    assert config.vault.rpc.tcp_addr == "127.0.0.1:19000"


# --- the crypto mode's two spellings ---------------------------------------


def test_the_crypto_mode_is_normalized_to_what_the_cipher_speaks(tmp_path):
    """The cipher says "sm"; the documentation says "sm4".

    Both are accepted, and the value that leaves the loader is the one the
    cipher understands — otherwise a configuration written from the
    documentation passes the check and is then refused by the cipher.
    """
    import yaml

    def a_config_with(mode: str):
        path = tmp_path / f"{mode}.yaml"
        path.write_text(yaml.safe_dump({"crypto_mode": mode}), encoding="utf-8")
        return load(str(path))

    assert a_config_with("sm").crypto_mode == "sm"
    assert a_config_with("sm4").crypto_mode == "sm"
    assert a_config_with("SM4").crypto_mode == "sm"
    assert a_config_with("aes").crypto_mode == "aes"
    assert a_config_with("AES").crypto_mode == "aes"


# --- the multi-node backend's three conditions -------------------------------


def test_an_etcd_endpoint_must_be_a_url():
    """The Go asks for an http(s) URL, and so does this side.

    The Go's own client would take a bare ``host:port``, but the
    deployment scripts all write the URL form, and the rule is the same on
    both sides.
    """
    with pytest.raises(ConfigError) as refused:
        Config.from_dict({"etcd": {"endpoints": ["127.0.0.1:2379"]}}).validate()
    assert "http(s) URL" in str(refused.value)


def test_a_node_without_a_roster_is_refused():
    with pytest.raises(ConfigError) as refused:
        Config.from_dict({"cluster": {"node_id": "node-a"}}).validate()
    assert "etcd.endpoints is empty" in str(refused.value)


def test_a_node_without_a_certificate_has_nothing_to_wrap_with():
    """The wrapping key is the node's own etcd client certificate."""
    with pytest.raises(ConfigError) as refused:
        Config.from_dict(
            {
                "etcd": {"endpoints": ["http://127.0.0.1:2379"]},
                "cluster": {"node_id": "node-a"},
            }
        ).validate()
    assert "etcd.tls.cert_file" in str(refused.value)


def test_a_complete_node_is_accepted():
    config = Config.from_dict(
        {
            "etcd": {
                "endpoints": ["http://127.0.0.1:2379"],
                "tls": {
                    "ca_file": "/etc/etcd/ca.pem",
                    "cert_file": "/etc/etcd/node.pem",
                    "key_file": "/etc/etcd/node.key",
                },
            },
            "cluster": {"node_id": "node-a", "identity_ca_file": "/id-ca.pem"},
        }
    )
    config.validate()


def test_a_node_id_may_not_break_the_key_layout():
    with pytest.raises(ConfigError) as refused:
        Config.from_dict(
            {
                "etcd": {"endpoints": ["http://127.0.0.1:2379"]},
                "cluster": {"node_id": "node/a"},
            }
        ).validate()
    assert "cluster.node_id" in str(refused.value)


def test_cluster_needs_an_identity_ca_or_pins():
    with pytest.raises(ConfigError, match="identity_ca_file"):
        Config.from_dict(
            {
                "etcd": {
                    "endpoints": ["http://127.0.0.1:2379"],
                    "tls": {
                        "ca_file": "/ca.pem",
                        "cert_file": "/c.pem",
                        "key_file": "/k.pem",
                    },
                },
                "cluster": {"node_id": "node-a"},
            }
        ).validate()
