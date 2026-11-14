"""The multi-endpoint client moves to the next address when one fails."""

from __future__ import annotations

import sys
import types

from security_gateway.vault.etcdstore import build_failover_client


class _FlakyClient:
    """A client whose first address fails after a configurable number of calls."""

    calls = 0
    fail_after = 0
    fail_host = ""
    by_host: dict[str, "_FlakyClient"] = {}

    def __init__(self, host=None, port=None, timeout=None, **kwargs):
        self.host = host
        self.port = port
        self.attempts = 0
        self.closed = False
        _FlakyClient.by_host[str(host)] = self

    def get(self, key):
        self.attempts += 1
        if self.fail_host == self.host:
            raise ConnectionError(f"{self.host} is down")
        if self.fail_after and self.attempts > self.fail_after:
            raise ConnectionError(f"{self.host} is down")
        return (b"value", None)

    def close(self):
        self.closed = True


def _etcd3_stub() -> types.ModuleType:
    module = types.ModuleType("etcd3")
    module.Etcd3Client = _FlakyClient
    return module


def _fresh(monkeypatch):
    _FlakyClient.by_host.clear()
    _FlakyClient.fail_after = 0
    monkeypatch.setitem(sys.modules, "etcd3", _etcd3_stub())


def test_a_dead_first_endpoint_is_skipped(monkeypatch):
    _fresh(monkeypatch)
    _FlakyClient.fail_host = "dead"
    client = build_failover_client(("http://dead:2379", "http://live:2379"))
    try:
        assert client.get("k") == (b"value", None)
        assert getattr(client, "_client_at")(0).attempts == 1
        assert getattr(client, "_client_at")(1).attempts == 1
    finally:
        client.close()


def test_a_failure_after_startup_moves_the_next_call(monkeypatch):
    _fresh(monkeypatch)
    client = build_failover_client(("http://a:2379", "http://b:2379"))
    try:
        assert client.get("k") == (b"value", None)
        _FlakyClient.by_host["a"].fail_after = 1
        assert client.get("k") == (b"value", None)
        assert _FlakyClient.by_host["a"].attempts == 2
        assert _FlakyClient.by_host["b"].attempts == 1
    finally:
        client.close()


def test_close_closes_every_client(monkeypatch):
    _fresh(monkeypatch)
    client = build_failover_client(("http://a:2379", "http://b:2379"))
    client.get("k")
    client.close()
    assert _FlakyClient.by_host["a"].closed is True
