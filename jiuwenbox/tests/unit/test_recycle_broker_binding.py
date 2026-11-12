# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Soft-delete credentials belong to the current runner and live broker."""
import socket
import struct
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.supervisor import win_recycle_broker as recycle
from jiuwenbox.supervisor import win_softdelete as soft


@pytest.fixture(autouse=True)
def isolated_broker(monkeypatch):
    monkeypatch.setattr(recycle, "_broker", None)
    monkeypatch.setattr(recycle, "_permit_ports", [], raising=False)


@pytest.mark.parametrize("supplied", [True, False])
def test_exec_uses_runner_broker_credentials(monkeypatch, supplied):
    monkeypatch.setenv(soft.ENV_RECYCLE_PORT, "32123")
    monkeypatch.setenv(soft.ENV_RECYCLE_TOKEN, "current-test-token")
    env = {soft.ENV_RECYCLE_PORT: "12321", soft.ENV_RECYCLE_TOKEN: "stale-test-token"} if supplied else {}
    soft.merge_soft_delete_env(env)
    assert env.get(soft.ENV_RECYCLE_PORT) == "32123"
    assert env.get(soft.ENV_RECYCLE_TOKEN) == "current-test-token"


def test_exec_cannot_supply_broker_credentials_missing_from_runner(monkeypatch):
    monkeypatch.delenv(soft.ENV_RECYCLE_PORT, raising=False)
    monkeypatch.delenv(soft.ENV_RECYCLE_TOKEN, raising=False)
    env = {soft.ENV_RECYCLE_PORT: "12321", soft.ENV_RECYCLE_TOKEN: "stale-test-token"}
    soft.merge_soft_delete_env(env)
    assert soft.ENV_RECYCLE_PORT not in env
    assert soft.ENV_RECYCLE_TOKEN not in env


def test_failed_registration_is_not_repopulated_from_server_environment(monkeypatch):
    monkeypatch.setenv(soft.ENV_ENABLED, "1")
    monkeypatch.setenv(soft.ENV_RECYCLE_PORT, "12321")
    monkeypatch.setenv(soft.ENV_RECYCLE_TOKEN, "old-server-test-token")
    monkeypatch.setattr(recycle, "get_broker", lambda: None)
    env = {}
    soft.merge_soft_delete_spawn_env(env)
    assert recycle.prepare_runner_recycle(env, []) is None
    # The server-to-runner merge must never restore an old credential.
    merge = getattr(soft, "_merge_soft_delete_runner_env", soft.merge_soft_delete_spawn_env)
    merge(env)
    assert env.get(soft.ENV_RECYCLE_PORT) == "0"
    assert soft.ENV_RECYCLE_TOKEN not in env


def test_dead_accept_thread_is_not_running(monkeypatch):
    broker = recycle.RecycleBroker()
    monkeypatch.setattr(broker, "_sock", Mock())
    monkeypatch.setattr(broker, "_thread", SimpleNamespace(is_alive=lambda: False))
    assert not broker.running


def test_disabled_soft_delete_discards_supplied_credentials(monkeypatch):
    monkeypatch.delenv(soft.ENV_ENABLED, raising=False)
    env = {soft.ENV_RECYCLE_PORT: "12321", soft.ENV_RECYCLE_TOKEN: "stale-test-token"}
    assert recycle.prepare_runner_recycle(env, []) is None
    assert env == {}


def test_dead_broker_recovers_only_on_recorded_permitted_ports(tmp_path, monkeypatch):
    monkeypatch.setenv(soft.ENV_ENABLED, "1")
    monkeypatch.setattr(recycle, "_permit_ports", [32124, 32123])
    start = Mock()
    broker = SimpleNamespace(running=True, port=32124, register=Mock(return_value="current-test-token"), start=start)
    monkeypatch.setattr(recycle, "RecycleBroker", lambda: broker)
    env = {}
    assert recycle.prepare_runner_recycle(env, [str(tmp_path)]) == "current-test-token"
    start.assert_called_once_with([32124, 32123])
    assert env == {soft.ENV_RECYCLE_PORT: "32124", soft.ENV_RECYCLE_TOKEN: "current-test-token"}


def test_recovery_failure_preserves_existing_deletion_fallback(monkeypatch):
    monkeypatch.setenv(soft.ENV_ENABLED, "1")
    monkeypatch.setattr(recycle, "_permit_ports", [32124])
    start = Mock(side_effect=OSError("occupied"))
    monkeypatch.setattr(recycle, "RecycleBroker", lambda: SimpleNamespace(start=start))
    env = {soft.ENV_RECYCLE_TOKEN: "stale-test-token"}
    assert recycle.prepare_runner_recycle(env, []) is None
    assert env == {soft.ENV_RECYCLE_PORT: "0"}
    start.assert_called_once_with([32124])


def test_explicit_stop_does_not_restart_broker_during_preparation(tmp_path, monkeypatch):
    monkeypatch.setenv(soft.ENV_ENABLED, "1")
    monkeypatch.setattr(recycle, "_permit_ports", [32124])
    restart = Mock(side_effect=AssertionError("must not restart after stop"))
    monkeypatch.setattr(recycle, "RecycleBroker", restart)
    recycle.stop_broker()
    env = {}
    assert recycle.prepare_runner_recycle(env, [str(tmp_path)]) is None
    assert env == {soft.ENV_RECYCLE_PORT: "0"}
    restart.assert_not_called()


def test_preparation_without_permitted_ports_never_constructs_broker(tmp_path, monkeypatch):
    monkeypatch.setenv(soft.ENV_ENABLED, "1")
    restart = Mock(side_effect=AssertionError("must not select an ephemeral port"))
    monkeypatch.setattr(recycle, "RecycleBroker", restart)
    env = {}
    assert recycle.prepare_runner_recycle(env, [str(tmp_path)]) is None
    assert env == {soft.ENV_RECYCLE_PORT: "0"}
    restart.assert_not_called()


def test_accept_failure_releases_listener(monkeypatch):
    broker = recycle.RecycleBroker()
    closed = threading.Event()
    listener = Mock()
    listener.getsockname.return_value = ("127.0.0.1", 32123)
    listener.accept.side_effect = OSError("accept failed")
    listener.close.side_effect = closed.set
    monkeypatch.setattr(recycle.socket, "socket", lambda *_: listener)
    try:
        broker.start([32123])
        assert closed.wait(3)
        assert not broker.running
        listener.close.assert_called_once()
    finally:
        broker.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="Winsock exclusive bind")
def test_windows_broker_uses_exclusive_binding(monkeypatch):
    listener = Mock()
    listener.getsockname.return_value = ("127.0.0.1", 32123)
    monkeypatch.setattr(recycle.socket, "socket", lambda *_: listener)
    thread = Mock()
    thread.is_alive.return_value = True
    monkeypatch.setattr(recycle.threading, "Thread", lambda **_: thread)
    broker = recycle.RecycleBroker()
    try:
        assert broker.start([32123]) == 32123
        listener.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
    finally:
        broker.stop()


@pytest.mark.skipif(sys.platform != "win32", reason="Windows recycle path checks")
def test_live_broker_serves_a_frame_and_rejects_unknown_credentials(tmp_path):
    target = tmp_path / "victim"
    target.write_text("preserved", encoding="utf-8")
    recycler = Mock(return_value=True)
    broker = recycle.RecycleBroker(recycler=recycler)
    try:
        port = broker.start()
        token = broker.register([str(tmp_path)])
        # Exercise the actual accept thread and wire framing without deleting a file.
        for credential, expected in ((token, b"ok"), ("unknown-test-token", b"no")):
            with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                encoded_token = credential.encode("utf-8")
                encoded_path = str(target).encode("utf-8")
                payload = (struct.pack(">I", len(encoded_token)) + encoded_token
                           + struct.pack(">I", len(encoded_path)) + encoded_path)
                client.sendall(struct.pack(">I", len(payload)) + payload)
                size = struct.unpack(">I", client.recv(4))[0]
                assert client.recv(size) == expected
        recycler.assert_called_once()
        assert target.read_text(encoding="utf-8") == "preserved"
    finally:
        broker.stop()
