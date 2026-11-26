"""Fixed host-side web byte relay for a managed workspace (P1 prototype).

This is the HTTP/WebSocket analogue of :mod:`terminal_relay`. It does **not**
execute workload code. For each browser connection the host side spawns a small
stdlib bridge *inside the workspace network namespace*, dropped to the workload
UID/GID with no-new-privs, which connects only to the fixed loopback frontend
port and copies raw bytes between that socket and its stdin/stdout. The host
pump connects those pipes to the browser TCP connection.

A raw byte bridge is sufficient because HTTP/1.1 and WebSocket are just TCP
streams, and the only thing listening on the target loopback port is the
jiuwenswarm ``app_web`` front (static files + ``/api`` + ``/ws`` + ``/file-api``).
It never forwards to arbitrary destinations, never speaks ``CONNECT`` and never
loads application code on the host.

Scope for P1: single user, loopback listen, no authentication layer of its own;
the caller (administrator / later the HyperShell gateway) is responsible for
binding the listener to a trusted endpoint.
"""

from __future__ import annotations

import logging
import os
from os import PathLike
import socket
import socketserver
import subprocess
import sys
import threading

_LOGGER = logging.getLogger(__name__)

# Runs inside the workspace netns as the workload identity. Standard library
# only; started with ``python -I -S`` so site initialization and cwd/PYTHONPATH
# cannot influence imports.
RELAY_SOURCE = r"""
import os
import select
import socket
import sys


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def drain(sock):
    while True:
        try:
            data = sock.recv(65536)
        except OSError:
            return 0
        if not data:
            return 0
        write_all(1, data)


def main():
    if len(sys.argv) != 2:
        raise SystemExit(2)
    port = int(sys.argv[1])
    if not 1 <= port <= 65535:
        raise SystemExit(2)
    connection = socket.create_connection(('127.0.0.1', port), timeout=15)
    while True:
        try:
            readable, _, _ = select.select([connection, 0], [], [])
        except InterruptedError:
            continue
        if connection in readable:
            try:
                data = connection.recv(65536)
            except OSError:
                return 0
            if not data:
                return 0
            write_all(1, data)
        if 0 in readable:
            try:
                data = os.read(0, 65536)
            except OSError:
                return 0
            if not data:
                try:
                    connection.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                return drain(connection)
            try:
                connection.sendall(data)
            except OSError:
                return 0


try:
    _code = main()
except (OSError, ValueError):
    _code = 125
raise SystemExit(_code)
"""


def build_web_relay_command(python_path: str | PathLike, *, port: int) -> list[str]:
    """Return argv for the in-netns bridge. Only a fixed loopback port, no command."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid web relay port")
    return [str(python_path), "-I", "-S", "-c", RELAY_SOURCE, str(port)]


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        view = view[written:]


def _relay_argv(runner, state, frontend_port):
    import grp
    import pwd

    sid = state["sandbox_id"]
    if not isinstance(sid, str) or not sid:
        raise ValueError("invalid sandbox identity for web relay")
    profile = runner.config.users[runner.user_id]
    uid = pwd.getpwnam(profile.run_as_user).pw_uid
    gid = grp.getgrnam(profile.run_as_group).gr_gid
    if uid <= 0 or gid <= 0:
        raise ValueError("web relay requires a non-root workload identity")
    return [
        "/usr/sbin/ip",
        "netns",
        "exec",
        "jbx-" + sid,
        "setpriv",
        "--reuid",
        str(uid),
        "--regid",
        str(gid),
        "--clear-groups",
        "--no-new-privs",
        *build_web_relay_command(sys.executable, port=frontend_port),
    ]


def make_gate_authorizer(gate_url: str, require_user: str):
    """Return ``authorize(head_bytes) -> bool`` backed by the gateway session.

    The relay forwards the browser ``Cookie`` header to the gateway's internal
    ``/_gate/whoami``; only a ``user`` principal bound to ``require_user`` is
    allowed. Keeping signer details in the gateway avoids duplicating them here.
    """
    import http.client
    import json
    import urllib.parse

    parsed = urllib.parse.urlparse(gate_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if not host:
        raise ValueError("invalid gate URL")
    if not isinstance(require_user, str) or not require_user:
        raise ValueError("require_user is required")

    def authorize(head) -> bool:
        if not isinstance(head, (bytes, bytearray)) or not head or len(head) > 65536:
            return False
        try:
            text = bytes(head).decode("latin-1")
        except Exception:  # noqa: BLE001 - any decode failure denies
            return False
        cookie = None
        for line in text.split("\r\n")[1:]:
            if not line:
                break
            if line.lower().startswith("cookie:"):
                cookie = line.split(":", 1)[1].strip()
                break
        if not cookie:
            return False
        connection = None
        try:
            connection = http.client.HTTPConnection(host, port, timeout=3)
            connection.request("GET", "/_gate/whoami", headers={"Cookie": cookie})
            response = connection.getresponse()
            body = response.read()
            status = response.status
        except Exception:  # noqa: BLE001 - fail closed
            return False
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
        if status != 200:
            return False
        try:
            data = json.loads(body)
        except Exception:  # noqa: BLE001
            return False
        who = data.get("user") or {}
        return who.get("role") == "user" and who.get("user_id") == require_user

    return authorize


class _WebRelayHandler(socketserver.BaseRequestHandler):
    def handle(self):  # noqa: C901 - small explicit pump
        server = self.server
        client = self.request
        # Read the first request head (and any overflow) before authorizing.
        head = b""
        try:
            while b"\r\n\r\n" not in head and len(head) < 65536:
                chunk = client.recv(4096)
                if not chunk:
                    return
                head += chunk
        except OSError:
            return
        if server.authorize is not None:
            try:
                allowed = server.authorize(head)
            except Exception:  # noqa: BLE001 - fail closed
                allowed = False
            if not allowed:
                login_url = server.login_url or "/login"
                try:
                    client.sendall(
                        (
                            "HTTP/1.1 302 Found\r\nLocation: "
                            + login_url
                            + "\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        ).encode("latin-1")
                    )
                except OSError:
                    pass
                return
        try:
            argv = _relay_argv(server.runner, server.state, server.frontend_port)
            child = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0
            )
        except (OSError, ValueError):
            try:
                client.close()
            except OSError:
                pass
            return
        try:
            _write_all(child.stdin.fileno(), head)
        except OSError:
            return

        def client_to_child():
            try:
                while True:
                    data = client.recv(65536)
                    if not data:
                        break
                    _write_all(child.stdin.fileno(), data)
            except OSError:
                pass
            finally:
                try:
                    child.stdin.close()
                except OSError:
                    pass

        pump = threading.Thread(target=client_to_child, daemon=True)
        pump.start()
        try:
            while True:
                data = os.read(child.stdout.fileno(), 65536)
                if not data:
                    break
                client.sendall(data)
        except OSError:
            pass
        finally:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass
            pump.join(timeout=5)
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()


class WebRelayServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address, runner, state, frontend_port, *, authorize=None, login_url=None):
        self.runner = runner
        self.state = state
        self.frontend_port = frontend_port
        self.authorize = authorize
        self.login_url = login_url
        super().__init__(address, _WebRelayHandler)


def serve_web_relay(
    runner,
    state,
    *,
    host: str = "127.0.0.1",
    port: int = 8091,
    frontend_port: int = 5173,
    authorize=None,
    login_url=None,
) -> None:
    """Block serving the workspace web UI on a host loopback endpoint."""
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("invalid listen port")
    server = WebRelayServer((host, port), runner, state, frontend_port, authorize=authorize, login_url=login_url)
    _LOGGER.info(
        "[hypershell-web] serving workspace '%s' web UI on http://%s:%s  (frontend loopback %s)",
        runner.user_id,
        host,
        port,
        frontend_port,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
