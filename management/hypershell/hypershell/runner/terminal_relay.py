"""Fixed host-side terminal byte relay; never executes workload commands.

The relay is launched after entering only the workspace network namespace and
dropping to the workload UID/GID. Its isolated stdlib interpreter accepts a
loopback endpoint and one inherited authentication FD, never a command/path.
"""

from __future__ import annotations

import json
from os import PathLike

RELAY_SOURCE = r"""
import base64
import fcntl
import json
import os
import select
import signal
import socket
import struct
import sys
import termios
import time
import tty

MAX_FRAME = 65536

def send_frame(connection, frame):
    data = json.dumps(frame, separators=(',', ':')).encode('utf-8')
    if len(data) > MAX_FRAME:
        raise ValueError('frame too large')
    connection.sendall(struct.pack('!I', len(data)) + data)

def receive_exact(connection, size):
    parts = bytearray()
    while len(parts) < size:
        part = connection.recv(size - len(parts))
        if not part:
            raise EOFError('terminal connection closed')
        parts.extend(part)
    return bytes(parts)

def receive_frame(connection):
    size = struct.unpack('!I', receive_exact(connection, 4))[0]
    if not 1 <= size <= MAX_FRAME:
        raise ValueError('invalid frame size')
    value = json.loads(receive_exact(connection, size))
    if not isinstance(value, dict):
        raise ValueError('invalid frame')
    return value

def main():
    spec = json.loads(sys.argv[1])
    port, token_fd = spec['port'], spec['token_fd']
    capture, timeout = spec['capture'], spec['timeout_seconds']
    if (type(port) is not int or not 1 <= port <= 65535
            or type(token_fd) is not int or token_fd < 3
            or not isinstance(capture, bool) or not 1 <= timeout <= 86400):
        raise ValueError('invalid relay spec')
    token = os.read(token_fd, 65)
    os.close(token_fd)
    if len(token) != 64 or any(ch not in b'0123456789abcdef' for ch in token):
        raise ValueError('invalid terminal credential')
    if not capture and (not os.isatty(0) or not os.isatty(1)):
        raise ValueError('interactive terminal required')
    connection = socket.create_connection(('127.0.0.1', port), timeout=5)
    connection.settimeout(3)
    previous = None
    resize_pending = [True]
    def resize(signum, frame):
        resize_pending[0] = True
    def interrupted(signum, frame):
        raise InterruptedError('terminal relay interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    signal.signal(signal.SIGWINCH, resize)
    try:
        send_frame(connection, {'type':'hello','token':token.decode('ascii')})
        del token
        if receive_frame(connection).get('type') != 'ready':
            raise ValueError('missing terminal readiness')
        if not capture:
            previous = termios.tcgetattr(0)
            tty.setraw(0)
        deadline = time.monotonic() + timeout
        total = 0
        closed = False
        while time.monotonic() < deadline:
            if not capture and resize_pending[0]:
                rows, columns, _, _ = struct.unpack('HHHH', fcntl.ioctl(0, termios.TIOCGWINSZ, b'\0'*8))
                send_frame(connection, {'type':'resize','rows':max(1,min(rows,500)),
                    'columns':max(1,min(columns,1000))})
                resize_pending[0] = False
            inputs = [connection] + ([0] if not capture and not closed else [])
            readable, _, _ = select.select(inputs, [], [], min(0.25,max(0,deadline-time.monotonic())))
            if 0 in readable:
                data = os.read(0, 16384)
                if data:
                    send_frame(connection, {'type':'input','data':base64.b64encode(data).decode('ascii')})
                else:
                    send_frame(connection, {'type':'close'})
                    closed = True
            if connection in readable:
                frame = receive_frame(connection)
                if frame.get('type') == 'output':
                    data = base64.b64decode(frame['data'], validate=True)
                    total += len(data)
                    if capture and total > spec['output_limit']:
                        raise ValueError('captured terminal output exceeded limit')
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                elif frame.get('type') == 'exit':
                    code = frame.get('code')
                    if type(code) is not int or not 0 <= code <= 255:
                        raise ValueError('invalid exit status')
                    return code
                else:
                    raise ValueError('unknown terminal response')
        raise TimeoutError('terminal relay deadline reached')
    finally:
        if previous is not None:
            termios.tcsetattr(0, termios.TCSADRAIN, previous)
        try:
            send_frame(connection, {'type':'close'})
        except (OSError, ValueError):
            pass
        connection.close()

try:
    code = main()
except KeyboardInterrupt:
    code = 130
except (OSError, ValueError, KeyError, TypeError, EOFError):
    print('terminal relay failed; no host fallback', file=sys.stderr)
    code = 125
raise SystemExit(code)
"""


def build_relay_command(
    python_path: str | PathLike,
    *,
    port: int,
    token_fd: int,
    capture: bool,
    timeout_seconds: int = 7200,
    output_limit: int = 2 * 1024 * 1024,
) -> list[str]:
    for value, maximum in ((port, 65535), (timeout_seconds, 86400), (output_limit, 16 * 1024 * 1024)):
        if type(value) is not int or not 1 <= value <= maximum:
            raise ValueError("invalid terminal relay parameters")
    if type(token_fd) is not int or token_fd < 3 or not isinstance(capture, bool):
        raise ValueError("invalid terminal relay parameters")
    spec = {
        "port": port,
        "token_fd": token_fd,
        "capture": capture,
        "timeout_seconds": timeout_seconds,
        "output_limit": output_limit,
    }
    return [str(python_path), "-I", "-S", "-c", RELAY_SOURCE, json.dumps(spec, separators=(",", ":"))]
