"""Exercise the real Linux PTY/socket broker, with no simulated terminal frames."""

from __future__ import annotations

import base64
import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

from hypershell.runner.terminal_broker import BROKER_SOURCE, build_broker_command

LINUX = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="real PTY broker requires Linux")
LOOPBACK = str(IPv4Address(socket.INADDR_LOOPBACK))


def _spec(directory=PurePosixPath("/home/agent/tmp"), command=None, **overrides):
    result = {
        "token": secrets.token_hex(32),
        "command": command or ["/usr/bin/python3", "-c", "pass"],
        "ready_path": str(directory / (".hs-terminal-" + uuid4().hex + ".json")),
        "rows": 24,
        "columns": 80,
        "timeout_seconds": 8,
        "idle_timeout_seconds": 4,
    }
    result.update(overrides)
    return result


def _frame(value):
    payload = json.dumps(value, separators=(",", ":")).encode()
    return struct.pack("!I", len(payload)) + payload


def _exact(connection, size):
    data = bytearray()
    while len(data) < size:
        chunk = connection.recv(size - len(data))
        assert chunk, "broker closed the connection before completing its frame"
        data.extend(chunk)
    return bytes(data)


def _receive(connection):
    size = struct.unpack("!I", _exact(connection, 4))[0]
    assert 1 <= size <= 65536
    return json.loads(_exact(connection, size))


def _output_until(connection, marker):
    output = bytearray()
    while marker not in output:
        frame = _receive(connection)
        assert frame["type"] == "output"
        output.extend(base64.b64decode(frame["data"], validate=True))
        assert len(output) <= 1048576
    return bytes(output)


def _exit(connection):
    output = bytearray()
    while True:
        frame = _receive(connection)
        if frame["type"] == "exit":
            assert type(frame["code"]) is int and 0 <= frame["code"] <= 255
            return frame["code"], bytes(output)
        assert frame["type"] == "output"
        output.extend(base64.b64decode(frame["data"], validate=True))
        assert len(output) <= 1048576


@pytest.fixture
def broker_factory(tmp_path):
    brokers = []

    def start(source, **overrides):
        spec = _spec(tmp_path, [sys.executable, "-I", "-c", source], **overrides)
        command = build_broker_command(sys.executable, spec)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=tmp_path,
            env={**os.environ, "HOME": str(tmp_path), "TERM": "untrusted-term"},
        )
        broker = SimpleNamespace(process=process, spec=spec, path=Path(spec["ready_path"]))
        brokers.append(broker)
        process.stdin.write((spec["token"] + "\n").encode())
        process.stdin.close()
        process.stdin = None
        limit = time.monotonic() + 5
        while time.monotonic() < limit:
            if broker.path.exists():
                try:
                    ready = json.loads(broker.path.read_text())
                    break
                except ValueError:
                    pass  # The exclusive file may still be receiving its first write.
            if process.poll() is not None:
                raise AssertionError("broker startup failed: " + process.stderr.read().decode())
            time.sleep(0.01)
        else:
            pytest.fail("broker readiness timed out")
        broker.ready = ready
        assert ready == {
            "version": 1,
            "port": ready["port"],
            "token_digest": hashlib.sha256(spec["token"].encode()).hexdigest(),
        }
        assert type(ready["port"]) is int and 1 <= ready["port"] <= 65535
        assert broker.path.stat().st_mode & 0o777 == 0o600
        assert spec["token"] not in broker.path.read_text()
        return broker

    yield start
    for broker in brokers:
        if broker.process.poll() is None:
            broker.process.terminate()
        try:
            broker.process.communicate(timeout=8)
        except subprocess.TimeoutExpired:
            broker.process.kill()
            broker.process.communicate(timeout=3)


def _connect(broker):
    connection = socket.create_connection((LOOPBACK, broker.ready["port"]), timeout=4)
    connection.sendall(_frame({"type": "hello", "token": broker.spec["token"]}))
    assert _receive(connection) == {"type": "ready"}
    return connection


def _gone(pid):
    limit = time.monotonic() + 3
    while time.monotonic() < limit:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    pytest.fail("terminal child was not reaped")


def test_builder_isolated_argv_never_contains_token():
    spec = _spec()
    command = build_broker_command("/opt/runtime/bin/python", spec)
    assert command[:4] == ["/opt/runtime/bin/python", "-I", "-S", "-c"]
    assert command[command.index("-c") + 1] == BROKER_SOURCE
    assert spec["token"] not in " ".join(command)
    assert "token" not in json.loads(command[-1])
    assert json.loads(command[-1])["command"] == spec["command"]


@pytest.mark.parametrize(
    "overrides",
    [
        {"token": "short"},
        {"token": "z" * 64},
        {"command": ["relative"]},
        {"command": ["/bin/echo", "bad\x00argument"]},
        {"rows": True},
        {"columns": 1001},
        {"ready_path": "/tmp/user-file"},
        {"timeout_seconds": float("inf")},
        {"idle_timeout_seconds": 0},
        {"extra": "unsupported"},
    ],
)
def test_builder_rejects_invalid_or_unbounded_specs(overrides):
    with pytest.raises((TypeError, ValueError)):
        build_broker_command("/usr/bin/python3", _spec(**overrides))


def test_builder_refuses_a_token_embedded_in_child_command():
    spec = _spec()
    spec["command"] = ["/bin/echo", spec["token"]]
    with pytest.raises(ValueError, match="token"):
        build_broker_command("/usr/bin/python3", spec)


@LINUX
def test_real_terminal_input_resize_environment_and_final_output(broker_factory, tmp_path):
    source = (
        "import fcntl,json,os,struct,sys,termios\n"
        "size=lambda: list(struct.unpack('HHHH',fcntl.ioctl(0,termios.TIOCGWINSZ,b'\\0'*8))[:2])\n"
        "print('INITIAL:'+json.dumps({'size':size(),'home':os.environ['HOME'],'cwd':os.getcwd(),"
        "'term':os.environ['TERM']}),flush=True)\n"
        "line=sys.stdin.readline().strip()\n"
        "print('RECEIVED:'+line,flush=True)\n"
        "print('RESIZED:'+json.dumps(size()),flush=True)\n"
        "os.write(1,b'FINAL-BYTES')\n"
    )
    broker = broker_factory(source)
    with _connect(broker) as connection:
        initial = _output_until(connection, b"INITIAL:")
        # A PTY may split an output line across frames.
        while b"\n" not in initial:
            initial += _output_until(connection, b"\n")
        metadata = json.loads(initial.split(b"INITIAL:", 1)[1].splitlines()[0])
        assert metadata == {"size": [24, 80], "home": str(tmp_path), "cwd": str(tmp_path), "term": "xterm-256color"}
        connection.sendall(_frame({"type": "resize", "rows": 37, "columns": 101}))
        connection.sendall(_frame({"type": "input", "data": base64.b64encode(b"hello terminal\n").decode()}))
        code, output = _exit(connection)
    assert code == 0 and b"RECEIVED:hello terminal" in output
    assert b"RESIZED:[37, 101]" in output and output.endswith(b"FINAL-BYTES")
    assert broker.process.wait(timeout=4) == 0
    assert not broker.path.exists()


@LINUX
def test_fragmented_handshake_and_wrong_token_do_not_launch_a_child(broker_factory, tmp_path):
    marker = tmp_path / "child-started"
    broker = broker_factory(
        "from pathlib import Path\nPath('child-started').write_text('yes')\nprint('launched',flush=True)"
    )
    with socket.create_connection((LOOPBACK, broker.ready["port"]), timeout=2) as bad:
        bad.sendall(_frame({"type": "hello", "token": "0" * 64}))
        assert bad.recv(1) == b""
    assert broker.process.poll() is None and not marker.exists()
    with socket.create_connection((LOOPBACK, broker.ready["port"]), timeout=3) as connection:
        hello = _frame({"type": "hello", "token": broker.spec["token"]})
        connection.sendall(hello[:2])
        connection.settimeout(0.05)
        with pytest.raises(socket.timeout):
            connection.recv(1)
        connection.settimeout(3)
        for part in (hello[2:5], hello[5:17], hello[17:]):
            connection.sendall(part)
        assert _receive(connection) == {"type": "ready"}
        code, output = _exit(connection)
    assert code == 0 and b"launched" in output and marker.read_text() == "yes"
    assert broker.process.wait(timeout=4) == 0


@LINUX
def test_normal_nonzero_exit_keeps_last_pty_output(broker_factory):
    broker = broker_factory("import os\nos.write(1,b'last-output-before-exit')\nos._exit(7)")
    with _connect(broker) as connection:
        code, output = _exit(connection)
    assert code == 7 and output == b"last-output-before-exit"
    assert broker.process.wait(timeout=4) == 7 and not broker.path.exists()


@LINUX
@pytest.mark.parametrize(
    "malformed",
    [
        struct.pack("!I", 65537),
        struct.pack("!I", 0),
        struct.pack("!I", 1) + b"\xff",
        _frame({"type": "input", "data": "%%%"}),
        _frame({"type": "resize", "rows": True, "columns": 80}),
        _frame({"type": "resize", "rows": 24, "columns": 1001}),
        _frame({"type": "hello", "token": "wrong"}),
    ],
)
def test_invalid_authenticated_frames_kill_and_reap_the_child(broker_factory, malformed):
    broker = broker_factory(
        "import os,signal,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        "print('PID:'+str(os.getpid()),flush=True)\ntime.sleep(60)"
    )
    with _connect(broker) as connection:
        output = _output_until(connection, b"\n")
        pid = int(output.split(b"PID:")[1].splitlines()[0])
        connection.sendall(malformed)
        code, _ = _exit(connection)
    assert code == 125 and broker.process.wait(timeout=5) == 125
    _gone(pid)
    assert not broker.path.exists()


@LINUX
@pytest.mark.parametrize("shutdown", ["disconnect", "close", "terminate", "idle", "deadline"])
def test_shutdown_reaps_child_and_descendants_even_when_they_ignore_term(broker_factory, shutdown):
    source = (
        "import os,signal,time\n"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN)\n"
        "child=os.fork()\n"
        "if child==0:\n"
        " os.setsid()\n"
        " signal.signal(signal.SIGHUP,signal.SIG_IGN)\n"
        " time.sleep(60)\n"
        "else:\n"
        " print('PIDS:'+str(os.getpid())+','+str(child),flush=True)\n"
        " time.sleep(60)\n"
    )
    settings = {"idle_timeout_seconds": 0.5} if shutdown == "idle" else {}
    if shutdown == "deadline":
        settings.update(timeout_seconds=0.8)
    broker = broker_factory(source, **settings)
    connection = _connect(broker)
    output = _output_until(connection, b"\n")
    parent, child = map(int, output.split(b"PIDS:")[1].splitlines()[0].split(b","))
    if shutdown == "disconnect":
        connection.close()
    elif shutdown == "close":
        connection.sendall(_frame({"type": "close"}))
        _exit(connection)
    elif shutdown == "terminate":
        broker.process.send_signal(signal.SIGTERM)
        _exit(connection)
    else:
        code, _ = _exit(connection)
        assert code == 124
    connection.close()
    broker.process.wait(timeout=6)
    _gone(parent)
    _gone(child)
    assert not broker.path.exists()


@LINUX
def test_ready_file_existing_target_is_never_replaced(tmp_path):
    spec = _spec(tmp_path, [sys.executable, "-c", "pass"])
    ready = Path(spec["ready_path"])
    ready.write_text("keep original")
    process = subprocess.run(
        build_broker_command(sys.executable, spec),
        input=(spec["token"] + "\n").encode(),
        capture_output=True,
        timeout=5,
    )
    assert process.returncode != 0 and ready.read_text() == "keep original"
    assert spec["token"].encode() not in process.stdout + process.stderr


@LINUX
def test_missing_stdin_token_never_creates_ready_file(tmp_path):
    spec = _spec(tmp_path)
    process = subprocess.run(build_broker_command(sys.executable, spec), input=b"", capture_output=True, timeout=5)
    assert process.returncode == 2 and not Path(spec["ready_path"]).exists()
    assert json.loads(process.stderr)["error_code"] == "TOKEN_STDIN_REQUIRED"
