"""Exercise the fixed relay protocol with a real loopback server."""

import base64
from ipaddress import IPv4Address
import json
import os
import socket
import struct
import subprocess
import sys
import threading

import pytest

from hypershell.runner.terminal_relay import build_relay_command


@pytest.mark.parametrize(
    "field,value",
    [("port", 0), ("port", True), ("token_fd", 0), ("capture", 1), ("timeout_seconds", 0), ("output_limit", 0)],
)
def test_relay_builder_rejects_invalid_controls(field, value):
    options = dict(port=12345, token_fd=3, capture=True, timeout_seconds=5, output_limit=100)
    options[field] = value
    with pytest.raises(ValueError):
        build_relay_command(sys.executable, **options)


def test_relay_has_no_command_path_or_token_argument():
    argv = build_relay_command(sys.executable, port=12345, token_fd=3, capture=True)
    assert argv[:4] == [sys.executable, "-I", "-S", "-c"]
    assert set(json.loads(argv[-1])) == {"port", "token_fd", "capture", "timeout_seconds", "output_limit"}


def _frame(value):
    payload = json.dumps(value).encode()
    return struct.pack("!I", len(payload)) + payload


@pytest.mark.skipif(sys.platform != "linux", reason="relay terminal modules and inherited FD require Linux")
@pytest.mark.parametrize(
    "response,code,expected",
    [
        ("normal", 7, b"PTY_OUTPUT"),
        ("bad_ready", 125, b""),
        ("bad_frame", 125, b""),
        ("bad_base64", 125, b""),
        ("output_limit", 125, b""),
    ],
)
def test_real_relay_handles_output_and_rejects_malformed_broker(response, code, expected):
    server = socket.socket()
    server.bind((str(IPv4Address(socket.INADDR_LOOPBACK)), 0))
    server.listen(1)
    token = "a" * 64
    failures = []

    def serve():
        try:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(5)
                size = struct.unpack("!I", connection.recv(4))[0]
                data = bytearray()
                while len(data) < size:
                    data.extend(connection.recv(size - len(data)))
                assert json.loads(data) == {"type": "hello", "token": token}
                connection.sendall(_frame({"type": "wrong" if response == "bad_ready" else "ready"}))
                if response == "bad_ready":
                    return
                if response == "bad_frame":
                    connection.sendall(struct.pack("!I", 65537))
                    return
                output = {
                    "type": "output",
                    "data": "invalid***" if response == "bad_base64" else base64.b64encode(b"PTY_OUTPUT").decode(),
                }
                frame = _frame(output)
                connection.sendall(frame[:2])
                connection.sendall(frame[2:])
                connection.sendall(_frame({"type": "exit", "code": 7}))
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            failures.append(exc)
        finally:
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    reader, writer = os.pipe()
    try:
        os.write(writer, token.encode())
        os.close(writer)
        argv = build_relay_command(
            sys.executable,
            port=server.getsockname()[1],
            token_fd=reader,
            capture=True,
            timeout_seconds=5,
            output_limit=2 if response == "output_limit" else 100,
        )
        process = subprocess.run(argv, pass_fds=(reader,), stdin=subprocess.DEVNULL, capture_output=True, timeout=8)
    finally:
        os.close(reader)
    thread.join(timeout=6)
    assert not thread.is_alive() and not failures
    assert process.returncode == code and process.stdout == expected
    assert token.encode() not in process.stderr
