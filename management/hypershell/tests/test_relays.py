"""Unit tests for the P3 per-user relay supervisor (pure, cross-platform)."""

from __future__ import annotations

from hypershell.web.relays import RelaySupervisor, terminate_relay_process


class FakeHandle:
    def __init__(self):
        self.returncode = None
        self.terminated = False
        self.killed = False

    def poll(self):
        return self.returncode

    def terminate(self):
        self.terminated = True
        self.returncode = -15

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout=None):
        return self.returncode


def make(phases):
    spawned = []

    def spawn(user_id, port):
        handle = FakeHandle()
        spawned.append({"user": user_id, "port": port, "handle": handle})
        return handle

    def status(user_id):
        return {"phase": phases.get(user_id, "STOPPED")}

    def port_for(user_id):
        return 9000 + list(phases).index(user_id)

    supervisor = RelaySupervisor(
        users=lambda: list(phases), port_for=port_for, status=status, spawn=spawn, interval=3600
    )
    return supervisor, spawned


def test_ensure_running_spawns_once_and_is_idempotent():
    supervisor, spawned = make({"u1": "RUNNING"})
    first = supervisor.ensure("u1", running=True)
    assert first == {"user": "u1", "relay": "started", "port": 9000}
    second = supervisor.ensure("u1", running=True)
    assert second["relay"] == "running"
    assert len(spawned) == 1
    assert supervisor.is_running("u1") is True


def test_ensure_not_running_terminates_and_removes():
    supervisor, spawned = make({"u1": "RUNNING"})
    supervisor.ensure("u1", running=True)
    handle = spawned[0]["handle"]
    result = supervisor.ensure("u1", running=False)
    assert result["relay"] == "stopped"
    assert handle.terminated is True
    assert supervisor.is_running("u1") is False


def test_reconcile_matches_phases_and_drops_unconfigured():
    supervisor, spawned = make({"u1": "RUNNING", "u2": "STOPPED"})
    supervisor.ensure("u1", running=True)
    # u1 live, u2 needs nothing
    out = supervisor.reconcile()
    assert out["u1"]["relay"] == "running"
    assert out["u2"]["relay"] == "absent"
    assert len(spawned) == 1


def test_reconcile_stops_relay_when_instance_stopped():
    phases = {"u1": "RUNNING"}
    supervisor, spawned = make(phases)
    supervisor.ensure("u1", running=True)
    handle = spawned[0]["handle"]

    phases["u1"] = "STOPPED"
    out = supervisor.reconcile()
    assert out["u1"]["relay"] == "stopped"
    assert handle.terminated is True


def test_spawn_failure_is_reported_not_raised():
    def bad_spawn(user_id, port):
        raise OSError("cannot spawn")

    supervisor = RelaySupervisor(
        users=lambda: ["u1"], port_for=lambda u: 9000, status=lambda u: {"phase": "RUNNING"}, spawn=bad_spawn
    )
    result = supervisor.ensure("u1", running=True)
    assert result["relay"] == "error"
    assert "cannot spawn" in result["error"]
    assert supervisor.is_running("u1") is False


def test_start_does_initial_reconcile_and_shutdown_terminates_all():
    supervisor, spawned = make({"u1": "RUNNING", "u2": "RUNNING"})
    supervisor.start()
    try:
        assert len(spawned) == 2
        assert supervisor.is_running("u1") and supervisor.is_running("u2")
    finally:
        supervisor.shutdown()
    assert all(item["handle"].terminated for item in spawned)


def test_port_for_uses_declared_index():
    supervisor, _ = make({"u1": "STOPPED", "u2": "STOPPED"})
    assert supervisor.port_for("u1") == 9000
    assert supervisor.port_for("u2") == 9001


def test_terminate_relay_process_is_safe_on_dead_handle():
    handle = FakeHandle()
    handle.returncode = 0
    terminate_relay_process(handle)  # already exited: no exception
    assert handle.terminated is False
