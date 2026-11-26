"""A stdlib PTY endpoint launched inside the existing restricted backend.

The executable source imports no application packages. Its child inherits the
backend's security context; the host only relays framed terminal bytes. Pass the
token to the background job's stdin, never through argv, environment or a file.
"""

from __future__ import annotations

import json
import re
from os import PathLike
from typing import Any, Mapping


def _validated_spec(spec: Mapping[str, Any]) -> dict:
    value = dict(spec)
    expected = {"token", "command", "ready_path", "rows", "columns", "timeout_seconds", "idle_timeout_seconds"}
    if set(value) != expected:
        raise ValueError("invalid terminal broker specification fields")
    token = value.pop("token")
    if not isinstance(token, str) or re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise ValueError("terminal token must be 256 random bits encoded as lowercase hex")
    command = value["command"]
    if not isinstance(command, list) or not 1 <= len(command) <= 128:
        raise ValueError("terminal command must be a bounded absolute executable argv")
    if any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        raise ValueError("terminal command must be a bounded absolute executable argv")
    if not command[0].startswith("/") or sum(map(len, command)) > 32768:
        raise ValueError("terminal command must be a bounded absolute executable argv")
    ready = value["ready_path"]
    if not isinstance(ready, str) or not ready.startswith("/") or len(ready) > 4096:
        raise ValueError("terminal readiness path must be absolute and uniquely named")
    if (
        "\x00" in ready
        or ".." in ready.split("/")
        or re.fullmatch(r"\.hs-terminal-[0-9a-fA-F-]{32,36}\.json", ready.rsplit("/", 1)[-1]) is None
    ):
        raise ValueError("terminal readiness path must be absolute and uniquely named")
    for field, maximum in (("rows", 500), ("columns", 1000)):
        if type(value[field]) is not int or not 1 <= value[field] <= maximum:
            raise ValueError("terminal dimensions are invalid")
    for field in ("timeout_seconds", "idle_timeout_seconds"):
        if type(value[field]) not in (int, float) or not 0.1 <= value[field] <= 86400:
            raise ValueError("terminal deadlines must be between 0.1 and 86400 seconds")
    serialized = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
    if token in serialized:
        raise ValueError("terminal token must not occur in broker argv")
    return value


# Keep the framing and validation self-contained: this runs under the application
# interpreter with both cwd/PYTHONPATH and site initialization excluded.
BROKER_SOURCE = r"""
import base64
import errno
import hashlib
import hmac
import json
import os
import re
import select
import signal
import socket
import struct
import sys
import time

MAX_FRAME = 65536
MAX_QUEUE = 262144
STOP_SIGNAL = 0
SUBREAPER = False


class BrokerError(Exception):
    def __init__(self, code, exit_code=125):
        self.code, self.exit_code = code, exit_code


def stop_signal(number, frame):
    global STOP_SIGNAL
    STOP_SIGNAL = number


def check_stop():
    if STOP_SIGNAL:
        raise BrokerError("INTERRUPTED", 128 + STOP_SIGNAL)


def reject_constant(value):
    raise ValueError()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError()
        result[key] = value
    return result


def decode_json(data):
    return json.loads(data, parse_constant=reject_constant, object_pairs_hook=unique_object)


def spec_from_argv():
    if len(sys.argv) != 2 or len(sys.argv[1]) > 65536:
        raise BrokerError("INVALID_SPEC", 2)
    try:
        spec = decode_json(sys.argv[1])
        expected = {"command", "ready_path", "rows", "columns", "timeout_seconds", "idle_timeout_seconds"}
        if not isinstance(spec, dict) or set(spec) != expected:
            raise ValueError()
        command = spec["command"]
        if (not isinstance(command, list) or not 1 <= len(command) <= 128
                or any(not isinstance(value, str) or not value or "\x00" in value for value in command)
                or not command[0].startswith("/") or sum(map(len, command)) > 32768):
            raise ValueError()
        ready = spec["ready_path"]
        if (not isinstance(ready, str) or not ready.startswith("/") or "\x00" in ready
                or len(ready) > 4096 or ".." in ready.split("/")
                or re.fullmatch(r"\.hs-terminal-[0-9a-fA-F-]{32,36}\.json", ready.rsplit("/", 1)[-1]) is None):
            raise ValueError()
        for name, maximum in (("rows", 500), ("columns", 1000)):
            if type(spec[name]) is not int or not 1 <= spec[name] <= maximum:
                raise ValueError()
        for name in ("timeout_seconds", "idle_timeout_seconds"):
            if type(spec[name]) not in (int, float) or not 0.1 <= spec[name] <= 86400:
                raise ValueError()
        return spec
    except (ValueError, TypeError, KeyError):
        raise BrokerError("INVALID_SPEC", 2) from None


def read_token(deadline):
    data = bytearray()
    limit = min(deadline, time.monotonic() + 5)
    while time.monotonic() < limit:
        check_stop()
        if not select.select([sys.stdin.fileno()], [], [], min(0.2, max(0, limit - time.monotonic())))[0]:
            continue
        chunk = os.read(sys.stdin.fileno(), 66 - len(data))
        if not chunk:
            break
        data.extend(chunk)
        if b"\n" in data or len(data) >= 66:
            break
    if re.fullmatch(b"[0-9a-f]{64}\n", bytes(data)) is None:
        raise BrokerError("TOKEN_STDIN_REQUIRED", 2)
    return bytes(data[:-1])


def encode_frame(value):
    payload = json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    if not 1 <= len(payload) <= MAX_FRAME:
        raise BrokerError("FRAME_TOO_LARGE")
    return struct.pack("!I", len(payload)) + payload


class Reader:
    def __init__(self):
        self.buffer = bytearray()

    def receive(self, connection):
        capacity = MAX_FRAME + 4 - len(self.buffer)
        if capacity <= 0:
            raise BrokerError("FRAME_TOO_LARGE")
        chunk = connection.recv(min(16384, capacity))
        if not chunk:
            raise BrokerError("CLIENT_DISCONNECTED", 130)
        self.buffer.extend(chunk)

    def pop(self):
        if len(self.buffer) < 4:
            return None
        size = struct.unpack("!I", self.buffer[:4])[0]
        if not 1 <= size <= MAX_FRAME:
            raise BrokerError("INVALID_FRAME_LENGTH")
        if len(self.buffer) < 4 + size:
            return None
        payload = bytes(self.buffer[4:4 + size])
        del self.buffer[:4 + size]
        try:
            value = decode_json(payload.decode("utf-8"))
            if not isinstance(value, dict):
                raise ValueError()
            return value
        except (ValueError, TypeError):
            raise BrokerError("INVALID_FRAME_JSON") from None


def authenticate(connection, reader, token, deadline):
    limit = min(deadline, time.monotonic() + 5)
    try:
        while time.monotonic() < limit:
            check_stop()
            frame = reader.pop()
            if frame is not None:
                received = frame.get("token")
                return (set(frame) == {"type", "token"} and frame["type"] == "hello"
                        and isinstance(received, str) and received.isascii()
                        and hmac.compare_digest(received.encode("ascii"), token))
            if select.select([connection], [], [], min(0.2, max(0, limit - time.monotonic())))[0]:
                reader.receive(connection)
        return False
    except (BrokerError, OSError):
        check_stop()
        return False


def resize(descriptor, rows, columns):
    import fcntl
    import termios
    fcntl.ioctl(descriptor, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


def try_prctl(option, value):
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(option, value, 0, 0, 0) == 0
    except (ImportError, AttributeError, OSError):
        return False


def parent_death_signal(parent):
    # Linux resets this setting across fork, so install it in the PTY child.
    if not try_prctl(1, signal.SIGKILL):
        os._exit(125)
    if os.getppid() != parent:
        os._exit(125)


def child_exited(pid):
    # WNOWAIT keeps the PID reserved until group cleanup; killpg cannot target
    # an unrelated process group after an early waitpid reaped our child.
    try:
        return os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
    except ChildProcessError:
        raise BrokerError("CHILD_ALREADY_REAPED") from None


def signal_group(pid, number):
    try:
        os.killpg(pid, number)
    except ProcessLookupError:
        pass


def stop_child(pid, state):
    if state["reaped"]:
        return state["exit_code"]
    signal_group(pid, signal.SIGTERM)
    grace = time.monotonic() + 0.3
    while time.monotonic() < grace:
        # Keep the group alive/PID reserved until the mandatory final KILL.
        time.sleep(0.02)
    signal_group(pid, signal.SIGKILL)
    limit = time.monotonic() + 3
    while time.monotonic() < limit:
        try:
            waited, status = os.waitpid(pid, os.WNOHANG)
        except ChildProcessError:
            raise BrokerError("CHILD_ALREADY_REAPED") from None
        if waited == pid:
            code = os.waitstatus_to_exitcode(status)
            state.update(reaped=True, exit_code=min(255, code if code >= 0 else 128 - code))
            if SUBREAPER:
                reap_descendants()
            return state["exit_code"]
        time.sleep(0.02)
    raise BrokerError("CHILD_CLEANUP_TIMED_OUT")


def reap_descendants():
    # Adopted descendants can have created another session/process group.
    # Kill only this broker's unreaped children, whose PIDs cannot be reused.
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            waited, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return
        if waited:
            continue
        try:
            with open("/proc/self/task/" + str(os.getpid()) + "/children", encoding="ascii") as handle:
                children = [int(value) for value in handle.read(65536).split()]
            for child in children:
                try:
                    os.kill(child, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        except (OSError, ValueError):
            # Same-group children were already killed; continue reaping them.
            pass
        time.sleep(0.02)
    raise BrokerError("DESCENDANT_CLEANUP_TIMED_OUT")


def session(connection, reader, spec, deadline):
    import pty
    check_stop()
    parent = os.getpid()
    startup_read, startup_write = os.pipe()
    try:
        pid, master = pty.fork()
    except BaseException:
        os.close(startup_read)
        os.close(startup_write)
        raise
    if pid == 0:
        try:
            os.close(startup_read)
            for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGPIPE):
                signal.signal(number, signal.SIG_DFL)
            parent_death_signal(parent)
            resize(0, spec["rows"], spec["columns"])
            os.write(startup_write, b"1")
            os.close(startup_write)
            environment = dict(os.environ)
            environment["TERM"] = "xterm-256color"
            os.execvpe(spec["command"][0], spec["command"], environment)
        except BaseException:
            os._exit(127)
    os.close(startup_write)
    child = {"reaped": False, "exit_code": None}
    outbound = bytearray()
    exit_queued = False
    try:
        startup_deadline = min(deadline, time.monotonic() + 5)
        while True:
            check_stop()
            if time.monotonic() >= startup_deadline:
                raise BrokerError("CHILD_SETUP_TIMED_OUT")
            if select.select([startup_read], [], [], min(0.2, max(0, startup_deadline - time.monotonic())))[0]:
                if os.read(startup_read, 1) != b"1":
                    raise BrokerError("CHILD_SETUP_FAILED")
                break
        os.close(startup_read)
        startup_read = None
        os.set_blocking(master, False)
        outbound.extend(encode_frame({"type": "ready"}))
        inbound = bytearray()
        last_activity = time.monotonic()
        eof = False
        exit_code = None
        while True:
            check_stop()
            now = time.monotonic()
            if now >= deadline:
                raise BrokerError("SESSION_DEADLINE", 124)
            if now - last_activity >= spec["idle_timeout_seconds"]:
                raise BrokerError("SESSION_IDLE_TIMEOUT", 124)
            while True:
                frame = reader.pop()
                if frame is None:
                    break
                kind = frame.get("type")
                if kind == "close" and set(frame) == {"type"}:
                    raise BrokerError("CLIENT_CLOSED", 130)
                if kind == "resize" and set(frame) == {"type", "rows", "columns"}:
                    rows, columns = frame["rows"], frame["columns"]
                    if type(rows) is not int or type(columns) is not int:
                        raise BrokerError("INVALID_RESIZE")
                    if not 1 <= rows <= 500 or not 1 <= columns <= 1000:
                        raise BrokerError("INVALID_RESIZE")
                    if not child["reaped"]:
                        resize(master, rows, columns)
                elif kind == "input" and set(frame) == {"type", "data"}:
                    try:
                        if not isinstance(frame["data"], str):
                            raise ValueError()
                        data = base64.b64decode(frame["data"], validate=True)
                    except (ValueError, TypeError):
                        raise BrokerError("INVALID_INPUT_BASE64") from None
                    if len(inbound) + len(data) > MAX_QUEUE:
                        raise BrokerError("INPUT_QUEUE_FULL")
                    if not child["reaped"]:
                        inbound.extend(data)
                else:
                    raise BrokerError("UNKNOWN_FRAME")
                last_activity = time.monotonic()
            if not child["reaped"] and child_exited(pid):
                exit_code = stop_child(pid, child)
                inbound.clear()
            if child["reaped"] and eof and not exit_queued:
                outbound.extend(encode_frame({"type": "exit", "code": exit_code}))
                exit_queued = True
            if exit_queued and not outbound:
                return exit_code
            reads = [connection]
            if not eof and len(outbound) < MAX_QUEUE - 32768:
                reads.append(master)
            writes = ([connection] if outbound else []) + ([master] if inbound and not child["reaped"] else [])
            timeout = min(0.2, max(0, deadline - time.monotonic()),
                          max(0, spec["idle_timeout_seconds"] - (time.monotonic() - last_activity)))
            readable, writable, _ = select.select(reads, writes, [], timeout)
            if connection in readable:
                reader.receive(connection)
            if master in readable:
                try:
                    data = os.read(master, 16384)
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    data = b""
                if data:
                    outbound.extend(encode_frame({"type": "output", "data": base64.b64encode(data).decode("ascii")}))
                    last_activity = time.monotonic()
                else:
                    eof = True
            if connection in writable:
                try:
                    count = connection.send(outbound)
                except BlockingIOError:
                    count = 0
                del outbound[:count]
            if master in writable:
                try:
                    count = os.write(master, inbound)
                    del inbound[:count]
                except BlockingIOError:
                    pass
                except OSError as exc:
                    if exc.errno != errno.EIO:
                        raise
                    inbound.clear()
    except (BrokerError, OSError) as exc:
        code = exc.exit_code if isinstance(exc, BrokerError) else 125
        if not child["reaped"]:
            stop_child(pid, child)
        try:
            # Preserve any already-partially-sent output frame. Inserting an
            # exit header ahead of its remaining bytes would corrupt framing.
            if not exit_queued:
                outbound.extend(encode_frame({"type": "exit", "code": code}))
            connection.settimeout(0.5)
            connection.sendall(outbound)
        except OSError:
            pass
        return code
    finally:
        try:
            if not child["reaped"]:
                stop_child(pid, child)
        finally:
            os.close(master)
            if startup_read is not None:
                os.close(startup_read)


def main():
    global SUBREAPER
    if not sys.platform.startswith("linux"):
        raise BrokerError("LINUX_REQUIRED", 2)
    for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        signal.signal(number, stop_signal)
    SUBREAPER = try_prctl(36, 1)
    if not SUBREAPER:
        raise BrokerError("SUBREAPER_UNAVAILABLE", 125)
    spec = spec_from_argv()
    deadline = time.monotonic() + spec["timeout_seconds"]
    token = read_token(deadline)
    directory, name = os.path.split(spec["ready_path"])
    directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700)
    ready_identity = None
    connection = None
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        server.setblocking(False)
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        with os.fdopen(descriptor, "w", encoding="ascii") as handle:
            info = os.fstat(handle.fileno())
            ready_identity = (info.st_dev, info.st_ino)
            os.fchmod(handle.fileno(), 0o600)
            json.dump({"version": 1, "port": server.getsockname()[1],
                       "token_digest": hashlib.sha256(token).hexdigest()}, handle, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        while time.monotonic() < deadline:
            check_stop()
            if not select.select([server], [], [], min(0.2, max(0, deadline - time.monotonic())))[0]:
                continue
            candidate, _ = server.accept()
            candidate.setblocking(False)
            reader = Reader()
            if authenticate(candidate, reader, token, deadline):
                connection = candidate
                server.close()
                return session(connection, reader, spec, deadline)
            candidate.close()
        raise BrokerError("ACCEPT_DEADLINE", 124)
    finally:
        if connection is not None:
            connection.close()
        server.close()
        try:
            if ready_identity is not None:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (info.st_dev, info.st_ino) != ready_identity:
                    raise BrokerError("READY_IDENTITY_CHANGED")
                os.unlink(name, dir_fd=directory_fd)
        finally:
            os.close(directory_fd)


try:
    exit_code = main()
except BrokerError as exc:
    print(json.dumps({"error_code": exc.code}), file=sys.stderr)
    exit_code = exc.exit_code
except Exception:
    print(json.dumps({"error_code": "BROKER_FAILED"}), file=sys.stderr)
    exit_code = 125
sys.exit(exit_code)
"""


def build_broker_command(python_path: str | PathLike[str], spec: Mapping[str, Any]) -> list[str]:
    """Build isolated argv; the caller must separately supply ``token + '\\n'`` on stdin."""
    payload = _validated_spec(spec)
    return [
        str(python_path),
        "-I",
        "-S",
        "-c",
        BROKER_SOURCE,
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), allow_nan=False),
    ]
