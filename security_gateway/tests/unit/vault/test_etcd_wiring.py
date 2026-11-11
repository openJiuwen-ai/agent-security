"""How the vault is wired to an etcd authority.

The Go's ``pkg/vault`` can put etcd in front of its records: the write
goes to the authority, and the local copy is a mirror that catches up
through a watch.  A standalone store writes to its own database and reads
it back.

Two things are checked here, and neither needs an etcd:

* the **mapping** of the operator's configuration onto the vault's own —
  the namespace in particular, because the vault's records and the
  router's credentials share one etcd and must not share one keyspace;
* the **write path** — with an authority, a write goes to the authority
  and to it only, because writing to both would leave the two
  disagreeing for as long as the watch takes.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from security_gateway.vault import Config as VaultConfig
from security_gateway.vault import Schema, Vault
from security_gateway.vault.cluster import vault_etcd_config, vault_namespace
from security_gateway.vault.record import Record, Value
from security_gateway.vault.schema import FieldDef, Type


def make_schema() -> Schema:
    """A schema with one encrypted field and one plain one."""
    return Schema(
        version=1,
        fields=[
            FieldDef(name="kind", type=Type.STRING),
            FieldDef(name="secret", type=Type.BYTES, encrypted=True),
        ],
    )


class FakeAuthority:
    """Stands in for the etcd authority."""

    def __init__(self) -> None:
        self.written: list[tuple] = []
        self.deleted: list[str] = []
        self.closed = False

    def write_record(self, db, id, data, schema_version, dek_version) -> None:
        self.written.append((id, data, schema_version, dek_version))

    def delete_record(self, db, id) -> None:
        self.deleted.append(id)

    def close(self) -> None:
        self.closed = True


class FakeTls:
    ca_file = ""
    cert_file = ""
    key_file = ""


class FakeEtcd:
    endpoints = ["http://127.0.0.1:2379"]
    namespace = "credential-router"

    #: The platform holds a duration here, not a number.  The fake used
    #: to hold a float, and that is exactly how the mapping's
    #: ``float()`` on a ``timedelta`` stayed hidden: the fake answered a
    #: question the real configuration never answered.
    dial_timeout = timedelta(seconds=5)
    tls = FakeTls()


class FakeCluster:
    node_id = "node-a"
    trusted_cert_sha256 = ["aa:bb"]
    fetch_timeout = 30.0


class FakePlatformConfig:
    """The operator's configuration, as far as the mapping reads it."""

    etcd = FakeEtcd()
    cluster = FakeCluster()


# -- the mapping -----------------------------------------------------------


def test_the_vault_gets_its_own_namespace():
    """The two keyspaces must not collide.

    The router's credentials and the vault's records live in one etcd.
    The vault's handover and the router's handover would fight over the
    same roster, the same mint record and the same sealed answers — and
    two fleets claiming one keyspace is a failure that only shows up in a
    cluster deployment.
    """
    assert vault_namespace("credential-router") == "credential-router-vault"
    assert vault_namespace("") == "-vault"


def test_the_mapping_carries_the_operator_settings():
    """The vault's configuration is the operator's, with its own namespace."""
    cfg = vault_etcd_config(FakePlatformConfig())

    assert cfg.namespace == "credential-router-vault"
    assert tuple(cfg.endpoints) == ("http://127.0.0.1:2379",)
    assert cfg.node_id == "node-a"
    assert tuple(cfg.trusted_cert_sha256) == ("aa:bb",)
    assert cfg.fetch_timeout == 30.0


# -- the write path --------------------------------------------------------


def test_a_write_goes_to_the_authority_and_to_it_only(tmp_path):
    """With an authority the local database is not written.

    The local copy is a mirror that catches up through a watch, and
    writing to both would leave the two disagreeing for as long as the
    watch takes.
    """
    authority = FakeAuthority()
    vault = Vault.open(VaultConfig(data_dir=str(tmp_path)), make_schema())
    vault.authority = authority
    try:
        record = Record(id="cred-1")
        record.set("kind", Value.new_string("litellm.master_key"))
        record.set("secret", Value.new_bytes(b"sk-real"))
        vault.put(record)

        assert len(authority.written) == 1
        written_id, data, schema_version, dek_version = authority.written[0]
        assert written_id == "cred-1"
        assert schema_version == 1
        assert dek_version >= 1
        # The payload is the encrypted container, not the plaintext.
        assert b"sk-real" not in data

        # The local database did not get it: the watch brings it here.
        from security_gateway.vault.store import get_record

        assert get_record(vault.db, "cred-1") is None
    finally:
        vault.close()


def test_a_delete_goes_to_the_authority(tmp_path):
    """A delete is the authority's to perform."""
    authority = FakeAuthority()
    vault = Vault.open(VaultConfig(data_dir=str(tmp_path)), make_schema())
    vault.authority = authority
    try:
        vault.delete("cred-1")
        assert authority.deleted == ["cred-1"]
    finally:
        vault.close()


def test_closing_the_store_closes_the_authority(tmp_path):
    """The authority holds a connection; it goes with the store."""
    authority = FakeAuthority()
    vault = Vault.open(VaultConfig(data_dir=str(tmp_path)), make_schema())
    vault.authority = authority

    vault.close()
    assert authority.closed is True


def test_a_standalone_store_writes_to_its_own_database(tmp_path):
    """Without an authority nothing changes: the local database is it."""
    vault = Vault.open(VaultConfig(data_dir=str(tmp_path)), make_schema())
    try:
        assert vault.authority is None

        record = Record(id="cred-1")
        record.set("kind", Value.new_string("litellm.master_key"))
        record.set("secret", Value.new_bytes(b"sk-real"))
        vault.put(record)

        from security_gateway.vault.store import get_record

        row = get_record(vault.db, "cred-1")
        assert row is not None
        assert vault.get("cred-1").get_string("kind") == "litellm.master_key"
    finally:
        vault.close()


# -- the start-up path ---------------------------------------------------


def test_the_mapping_survives_a_duration_held_as_a_duration():
    """The platform holds a duration; the vault holds seconds.

    A ``timedelta`` is not a number, and ``float()`` on one is a
    TypeError — at start-up, for every deployment that configured an
    etcd endpoint.  The fake used to hold a float, so the unit tests
    asked a question the real configuration never answered.
    """
    cfg = vault_etcd_config(FakePlatformConfig())

    assert cfg.dial_timeout == 5.0


def test_the_mapping_leaves_the_tls_out_when_there_is_none():
    """No TLS material means no TLS, not empty paths.

    An empty path handed to the etcd client is a ``FileNotFoundError``
    on ``""`` — the client tries to read the file the name names.  The
    Go only sets TLS when it is configured, and this is the same
    arrangement.
    """
    cfg = vault_etcd_config(FakePlatformConfig())

    assert cfg.tls is None


def test_the_mapping_carries_the_tls_when_there_is_some():
    """The material reaches the vault, and it answers what the dialer asks.

    The runtime builds the cluster's own TLS configuration and the
    vault's dialer reads it as its own, so the two are used
    interchangeably: the one the cluster builds has to answer the same
    questions the vault's own does.
    """

    class WithTls(FakePlatformConfig):
        class etcd(FakeEtcd):
            class tls(FakeTls):
                ca_file = "ca.pem"
                cert_file = "cert.pem"
                key_file = "key.pem"

    cfg = vault_etcd_config(WithTls())

    assert cfg.tls is not None
    assert cfg.tls.ca_file == "ca.pem"
    assert cfg.tls.cert_file == "cert.pem"
    assert cfg.tls.key_file == "key.pem"
    assert cfg.tls.all_set() is True
    assert cfg.tls.partially_set() is False


def test_the_endpoint_splitter_understands_both_spellings():
    """An endpoint is either a host and a port, or a URL naming them.

    The configuration file demands the URL form and the client's own
    form is the short one; the dialer has to understand both, because
    splitting the URL on its first colon turns the host into
    ``"http"`` and the port into ``"//127.0.0.1:32379"``.
    """
    from security_gateway.vault.etcdstore import split_endpoint

    assert split_endpoint("127.0.0.1:32379") == ("127.0.0.1", 32379)
    assert split_endpoint("http://127.0.0.1:32379") == ("127.0.0.1", 32379)
    assert split_endpoint("https://127.0.0.1:32379") == ("127.0.0.1", 32379)
    assert split_endpoint("http://127.0.0.1:32379/") == ("127.0.0.1", 32379)
    assert split_endpoint("127.0.0.1") == ("127.0.0.1", 2379)

    with pytest.raises(ValueError):
        split_endpoint("127.0.0.1:not-a-port")
