"""The second layer of defaults.

A configuration file is read in two steps.  The first gives every key the
file does not mention its default; the second replaces a key the file
*did* mention — when it is empty or non-positive — with that same
default.  The second step is the one that is easy to miss: a file that
says ``cache: {max_entries: 0}`` is not asking for an empty cache, it is
asking for the default one.

The Go's ``Load()`` does this, so this side does it too — otherwise one
file becomes two configurations.  The cross-language check lives in
``tests/interop/test_config_parity.py`` and needs the Go repository; these
are the local guard that stands on its own.
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from security_gateway.platform.config import (
    DEFAULT_ADMIN_ADDR,
    DEFAULT_CACHE_ENTRY_TTL,
    DEFAULT_CACHE_MAX_ENTRIES,
    DEFAULT_CACHE_TOMBSTONE_TTL,
    DEFAULT_CLUSTER_FETCH_TIMEOUT,
    DEFAULT_CRYPTO_MODE,
    DEFAULT_DATA_DIR,
    DEFAULT_ETCD_DIAL_TIMEOUT,
    DEFAULT_ETCD_NAMESPACE,
    DEFAULT_ETCD_OPERATION_TIMEOUT,
    DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT,
    DEFAULT_RECOVERY_MAX_WAIT,
    DEFAULT_ROTATION_BARRIER_QUORUM_RATIO,
    DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT,
    DEFAULT_ROTATION_DRAIN_TIMEOUT,
    DEFAULT_ROTATION_MAX_PHASE_A_LOOPS,
    DEFAULT_ROTATION_PERIOD,
    DEFAULT_SERVER_BIND_ADDRESS,
    DEFAULT_SERVER_IDLE_CONN_TIMEOUT,
    DEFAULT_SERVER_MAX_REQUEST_BYTES,
    DEFAULT_SERVER_MAX_RESPONSE_BYTES,
    DEFAULT_SERVER_READ_HEADER_TIMEOUT,
    DEFAULT_SERVER_SHUTDOWN_TIMEOUT,
    DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET,
    DEFAULT_SSRF_CACHE_TTL,
    DEFAULT_SSRF_TIMEOUT,
    DEFAULT_UPSTREAM_TIMEOUT_MS,
    load,
)

_ZEROES = """
upstream_timeout_ms: 0
data_dir: ""
backup_dir: ""
crypto_mode: ""

rotation:
  period: "0s"
  max_phase_a_loops: 0
  drain_timeout: "0s"
  complete_drain_timeout: "0s"
  barrier_quorum_ratio: 0.0

cache:
  max_entries: 0
  tombstone_ttl: "0s"
  entry_ttl: "0s"

admin:
  addr: ""
  validation:
    user_id_max_len: 0
    real_url_max_len: 0
    key_tag_max_len: 0
    api_key_max_len: 0
    auth_type_max_len: 0

ssrf:
  cache_ttl: "0s"
  timeout: "0s"

server:
  bind_address: ""
  max_response_bytes: 0
  max_request_bytes: 0
  shutdown_zero_budget: "0s"
  read_header_timeout: "0s"
  shutdown_timeout: "0s"
  idle_conn_timeout: "0s"

backup:
  keep: 0
  filename_template: ""
  key_snapshot:
    enabled: false
    filename_template: ""
    keep: 0

recovery:
  max_wait: "0s"

etcd:
  namespace: ""
  operation_timeout: "0s"
  dial_timeout: "0s"
  watch_liveness_timeout: "0s"
  list_limit: 0

cluster:
  fetch_timeout: "0s"
"""


@pytest.fixture()
def a_config(tmp_path: Path):
    """A configuration file in which every knob is written as zero."""
    path = tmp_path / "config.yaml"
    path.write_text(_ZEROES, encoding="utf-8")
    return load(str(path))


def test_the_zeroes_become_the_defaults(a_config):
    assert a_config.upstream_timeout_ms == DEFAULT_UPSTREAM_TIMEOUT_MS
    assert a_config.data_dir == DEFAULT_DATA_DIR
    assert a_config.backup_dir == "./backups"
    assert a_config.crypto_mode == DEFAULT_CRYPTO_MODE


def test_the_rotation_knobs_become_the_defaults(a_config):
    assert a_config.rotation.period == DEFAULT_ROTATION_PERIOD
    assert a_config.rotation.max_phase_a_loops == DEFAULT_ROTATION_MAX_PHASE_A_LOOPS
    assert a_config.rotation.drain_timeout == DEFAULT_ROTATION_DRAIN_TIMEOUT
    assert (
        a_config.rotation.complete_drain_timeout
        == DEFAULT_ROTATION_COMPLETE_DRAIN_TIMEOUT
    )
    assert (
        a_config.rotation.barrier_quorum_ratio == DEFAULT_ROTATION_BARRIER_QUORUM_RATIO
    )


def test_the_cache_knobs_become_the_defaults(a_config):
    assert a_config.cache.max_entries == DEFAULT_CACHE_MAX_ENTRIES
    assert a_config.cache.tombstone_ttl == DEFAULT_CACHE_TOMBSTONE_TTL
    assert a_config.cache.entry_ttl == DEFAULT_CACHE_ENTRY_TTL


def test_the_admin_knobs_become_the_defaults(a_config):
    assert a_config.admin.addr == DEFAULT_ADMIN_ADDR
    assert a_config.admin.validation.user_id_max_len == 256
    assert a_config.admin.validation.real_url_max_len == 2048
    assert a_config.admin.validation.key_tag_max_len == 64
    assert a_config.admin.validation.api_key_max_len == 8192
    assert a_config.admin.validation.auth_type_max_len == 16


def test_the_server_knobs_become_the_defaults(a_config):
    assert a_config.server.bind_address == DEFAULT_SERVER_BIND_ADDRESS
    assert a_config.server.max_response_bytes == DEFAULT_SERVER_MAX_RESPONSE_BYTES
    assert a_config.server.max_request_bytes == DEFAULT_SERVER_MAX_REQUEST_BYTES
    assert a_config.server.shutdown_zero_budget == DEFAULT_SERVER_SHUTDOWN_ZERO_BUDGET
    assert a_config.server.read_header_timeout == DEFAULT_SERVER_READ_HEADER_TIMEOUT
    assert a_config.server.shutdown_timeout == DEFAULT_SERVER_SHUTDOWN_TIMEOUT
    assert a_config.server.idle_conn_timeout == DEFAULT_SERVER_IDLE_CONN_TIMEOUT


def test_the_ssrf_knobs_become_the_defaults(a_config):
    assert a_config.ssrf.cache_ttl == DEFAULT_SSRF_CACHE_TTL
    assert a_config.ssrf.timeout == DEFAULT_SSRF_TIMEOUT


def test_the_backup_and_recovery_knobs_become_the_defaults(a_config):
    assert a_config.backup.keep == 3
    assert a_config.backup.filename_template == "backup-{type}-{ts}.db"
    assert a_config.backup.key_snapshot.filename_template == "key-snapshot-{ts}.bin"
    assert a_config.backup.key_snapshot.keep == 5
    assert a_config.recovery.max_wait == DEFAULT_RECOVERY_MAX_WAIT


def test_the_etcd_and_cluster_knobs_become_the_defaults(a_config):
    assert a_config.etcd.namespace == DEFAULT_ETCD_NAMESPACE
    assert a_config.etcd.operation_timeout == DEFAULT_ETCD_OPERATION_TIMEOUT
    assert a_config.etcd.dial_timeout == DEFAULT_ETCD_DIAL_TIMEOUT
    assert a_config.etcd.watch_liveness_timeout == DEFAULT_ETCD_WATCH_LIVENESS_TIMEOUT
    assert a_config.cluster.fetch_timeout == DEFAULT_CLUSTER_FETCH_TIMEOUT


def test_the_values_that_mean_something_keep_their_meaning(a_config):
    """A zero that means "none" is not a zero that means "unset"."""
    # The list limit is a rail the operator opts into.
    assert a_config.etcd.list_limit == 0
    # The dial check is off by default, and off is a decision.
    assert a_config.ssrf.dial_check is False
    # The snapshot was turned off on purpose.
    assert a_config.backup.key_snapshot.enabled is False
    # Nothing was said about where the log goes.
    assert a_config.server.log_file == ""


def test_the_vault_rotation_period_is_not_replaced(tmp_path: Path):
    """There, zero means "not scheduled" rather than "unset".

    Substituting a default would hand every deployment that never asked
    for a rotation one.
    """
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "vault": {"rotation": {"period": "0s"}},
            }
        ),
        encoding="utf-8",
    )

    config = load(str(path))

    assert config.vault.rotation.period == 0.0


def test_a_negative_vault_rotation_period_is_still_refused(tmp_path: Path):
    """Replacing the non-positive values must not swallow the refusal."""
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "vault": {"rotation": {"period": "-5m"}},
            }
        ),
        encoding="utf-8",
    )

    from security_gateway.platform.config import ConfigError

    with pytest.raises(ConfigError) as refused:
        load(str(path))
    assert "vault.rotation.period" in str(refused.value)


def test_a_negative_keystore_rotation_period_becomes_the_default(tmp_path: Path):
    """The Go replaces it, so this side replaces it too."""
    path = tmp_path / "config.yaml"
    path.write_text(
        yaml.safe_dump(
            {
                "rotation": {"period": "-5m"},
            }
        ),
        encoding="utf-8",
    )

    config = load(str(path))

    assert config.rotation.period == DEFAULT_ROTATION_PERIOD
    assert config.rotation.period == timedelta(hours=720)
