"""The names the etcd client is called under.

This is a small file about a small thing, and the small thing broke the
whole TLS path.

``etcd3.Etcd3Client`` spells its client certificate ``cert_cert`` and
takes ``ca_cert`` and ``cert_key`` beside it.  Both call sites used to
pass ``cert`` instead — the name the configuration uses — and the client
answers that with a ``TypeError`` at construction.  So every deployment
that configured ``etcd.tls`` failed to start, and with it the entire
multi-node cluster path: in that mode the node's identity *is* its etcd
client certificate, so TLS is not optional.

Nothing caught it, because the fake key-value seam never builds a client
and the real-etcd tests never enabled TLS.  The rules here are therefore
narrow and mechanical:

* the names are built in **one** place, and
* that place is checked against the client's own signature.

The check against the signature is the part that matters: it is the only
one that fails when the client changes, and it fails with the name it
does not take.
"""

from __future__ import annotations

import sys
import types

import pytest

from security_gateway.vault.etcdstore import tls_client_kwargs

#: The names the client takes its TLS material under.
EXPECTED = {"ca_cert", "cert_cert", "cert_key"}


class _StubTransaction:
    """One comparison, as the client's own builders build them."""

    def __init__(self, key: str) -> None:
        self.key = key

    def __eq__(self, other: object) -> object:
        return ("compare", self.key, other)


class _StubTransactions:
    """The comparison and operation builders the translation layer uses."""

    Create = _StubTransaction
    Mod = _StubTransaction
    Version = _StubTransaction

    @staticmethod
    def Value(key: str) -> _StubTransaction:
        return _StubTransaction(key)

    @staticmethod
    def Put(key: str, value: bytes, lease: int | None = None) -> tuple:
        return ("put", key, value, lease)

    @staticmethod
    def Get(key: str) -> tuple:
        return ("get", key)

    @staticmethod
    def Delete(key: str) -> tuple:
        return ("delete", key)


class _StubClient:
    """A client that records what it was called with.

    It takes **only** the names the real client takes, and refuses
    anything else the way the real client does.  That is what makes this
    stub worth having: a call site that invents a name fails here rather
    than at the customer's deployment.
    """

    def __init__(
        self,
        host=None,
        port=None,
        ca_cert=None,
        cert_key=None,
        cert_cert=None,
        timeout=None,
        **extra,
    ) -> None:
        if extra:
            raise TypeError(f"the etcd client does not take {sorted(extra)}")
        self.called = {
            "host": host,
            "port": port,
            "ca_cert": ca_cert,
            "cert_key": cert_key,
            "cert_cert": cert_cert,
            "timeout": timeout,
        }

    def transaction(self, compare=None, success=None, failure=None):
        return True, []

    def get(self, key, *args, **kwargs):
        return None, None


def _stub_etcd3() -> types.ModuleType:
    """A stand-in for the ``etcd3`` extra."""
    module = types.ModuleType("etcd3")
    module.Etcd3Client = _StubClient
    module.transactions = _StubTransactions
    return module


def test_the_tls_material_is_named_the_way_the_client_names_it():
    """The helper hands over three names, and they are the client's."""
    kwargs = tls_client_kwargs("ca.pem", "cert.pem", "key.pem")

    assert set(kwargs) == EXPECTED
    assert kwargs["ca_cert"] == "ca.pem"
    assert kwargs["cert_cert"] == "cert.pem"
    assert kwargs["cert_key"] == "key.pem"


def test_the_client_takes_the_names_we_hand_it():
    """The real client accepts what the helper builds.

    A ``TypeError`` here is the failure this file exists for: the client
    does not take the name we invented.  Any other failure is the
    connection, which this test does not care about.
    """
    etcd3 = pytest.importorskip("etcd3", reason="the etcd extra is not installed")

    kwargs = tls_client_kwargs("ca.pem", "cert.pem", "key.pem")
    try:
        etcd3.Etcd3Client(host="127.0.0.1", port=1, **kwargs)
    except TypeError as exc:
        pytest.fail(f"the etcd client does not take {sorted(kwargs)}: {exc}")
    except Exception:
        # The names were accepted; the connection is what failed.
        pass


def test_the_vault_hands_the_client_names_it_takes(monkeypatch):
    """The vault's own dialer passes the client's names."""
    from security_gateway.vault import etcd as vault_etcd

    monkeypatch.setitem(sys.modules, "etcd3", _stub_etcd3())

    tls = vault_etcd.EtcdTLSConfig(
        ca_file="ca.pem", cert_file="cert.pem", key_file="key.pem"
    )
    authority = vault_etcd.dial_etcd(
        vault_etcd.EtcdConfig(
            endpoints=("127.0.0.1:2379",), namespace="kwargcheck", tls=tls
        )
    )
    try:
        called = authority._client._client_at(0).called
        assert called["ca_cert"] == "ca.pem"
        assert called["cert_cert"] == "cert.pem"
        assert called["cert_key"] == "key.pem"
    finally:
        authority.close()
