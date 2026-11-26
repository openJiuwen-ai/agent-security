"""Per-user web relay lifecycle managed by the control plane (P3).

A web relay must be its own process: it holds a long-lived *session lease* and
blocks while serving bytes. Running it inside the gateway process would make the
gateway the lease holder, so an administrator "terminate" would kill the gateway
itself. The supervisor therefore spawns one relay process per RUNNING user on a
deterministic port, stops it when the instance is not RUNNING, and reconciles
periodically so a relay that died (or an instance stopped/started outside the
admin UI) is healed automatically.

The class is deliberately free of Linux-specific calls and takes its spawn /
terminate / status behaviour as callables, so it is unit-testable on any host.
"""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import threading


def spawn_relay_process(user_id, port, *, python, host, frontend_port, gate_url, login_url, log_dir):
    """Start ``python -m hypershell web`` for one user; return a Popen handle."""
    log_path = Path(log_dir) / f"hypershell-relay-{user_id}.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    handle = open(log_path, "ab")
    command = [
        python,
        "-B",
        "-m",
        "hypershell",
        "web",
        "--user",
        user_id,
        "--listen-host",
        host,
        "--listen-port",
        str(port),
        "--frontend-port",
        str(frontend_port),
    ]
    if gate_url:
        command += ["--gate-url", gate_url]
    if login_url:
        command += ["--login-url", login_url]
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    try:
        return subprocess.Popen(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=handle,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finally:
        handle.close()


def terminate_relay_process(handle, *, timeout=8.0):
    """Terminate a relay, escalating to SIGKILL if it does not exit."""
    if handle is None:
        return
    if handle.poll() is not None:
        return
    try:
        handle.terminate()
    except ProcessLookupError:
        return
    try:
        handle.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            handle.kill()
        except ProcessLookupError:
            pass
        try:
            handle.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


class RelaySupervisor:
    def __init__(self, *, users, port_for, status, spawn, terminate=None, interval=15.0, log=None):
        self._users = users  # callable -> iterable[str]
        self._port_for = port_for  # callable(user_id) -> int
        self._status = status  # callable(user_id) -> dict with "phase"
        self._spawn = spawn  # callable(user_id, port) -> handle
        self._terminate = terminate or terminate_relay_process
        self._interval = max(1.0, float(interval))
        self._log = log or (lambda message: None)
        self._procs = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread = None

    def _user_list(self):
        try:
            return list(self._users())
        except Exception:
            return []

    def port_for(self, user_id):
        return self._port_for(user_id)

    def is_running(self, user_id):
        with self._lock:
            handle = self._procs.get(user_id)
            return handle is not None and handle.poll() is None

    def ensure(self, user_id, *, running=None, phase=None):
        """Start or stop one user's relay; idempotent."""
        if running is None:
            running = phase == "RUNNING"
        with self._lock:
            handle = self._procs.get(user_id)
            if running:
                if handle is not None and handle.poll() is None:
                    return {"user": user_id, "relay": "running", "port": self._port_for(user_id)}
                if handle is not None:
                    self._procs.pop(user_id, None)
                try:
                    port = self._port_for(user_id)
                    self._procs[user_id] = self._spawn(user_id, port)
                    self._log(f"relay started for {user_id} on port {port}")
                    return {"user": user_id, "relay": "started", "port": port}
                except Exception as exc:  # noqa: BLE001 - reported, not fatal
                    self._log(f"relay start failed for {user_id}: {exc}")
                    return {"user": user_id, "relay": "error", "error": str(exc)}
            if handle is not None:
                self._terminate(handle)
                self._procs.pop(user_id, None)
                self._log(f"relay stopped for {user_id}")
                return {"user": user_id, "relay": "stopped"}
            return {"user": user_id, "relay": "absent"}

    def reconcile(self):
        """Bring every user's relay in line with the instance phase."""
        result = {}
        for user_id in self._user_list():
            try:
                phase = (self._status(user_id) or {}).get("phase")
            except Exception as exc:  # noqa: BLE001
                result[user_id] = {"user": user_id, "relay": "status-error", "error": str(exc)}
                continue
            result[user_id] = self.ensure(user_id, phase=phase)
        active = set(self._user_list())
        with self._lock:
            for user_id in [u for u in self._procs if u not in active]:
                self._terminate(self._procs.pop(user_id))
                result[user_id] = {"user": user_id, "relay": "stopped"}
        return result

    def _loop(self):
        while not self._stop.wait(self._interval):
            try:
                self.reconcile()
            except Exception as exc:  # noqa: BLE001
                self._log(f"relay reconcile error: {exc}")

    def start(self):
        with self._lock:
            if self._thread is not None:
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="relay-supervisor", daemon=True)
            self._thread.start()
        try:
            self.reconcile()
        except Exception as exc:  # noqa: BLE001
            self._log(f"relay initial reconcile error: {exc}")

    def shutdown(self):
        self._stop.set()
        thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout=5)
        with self._lock:
            for user_id in list(self._procs):
                self._terminate(self._procs.pop(user_id))
