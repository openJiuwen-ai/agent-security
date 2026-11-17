# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Authenticated loopback recovery service for the sandbox account."""

from __future__ import annotations

import logging
import os
import secrets
import socket
import struct
import sys
import threading
from collections.abc import Callable
from functools import lru_cache

from jiuwenbox.supervisor.win_softdelete import (
    ENV_ARCHIVE,
    ENV_RECYCLE_PORT,
    ENV_RECYCLE_TOKEN,
    enabled_from_environ,
)

logger = logging.getLogger(__name__)

_FRAME_MAX = 256 * 1024
_TOKEN_MAX = 256
_PATH_MAX = 48 * 1024
_OK = b"ok"
_NO = b"no"

Recycler = Callable[[str], bool | None]

_broker: RecycleBroker | None = None
_permit_ports: list[int] = []
_broker_lock = threading.Lock()


def _norm_key(path: str) -> str:
    text = path
    if text.startswith("\\\\?\\"):
        text = text[4:]
    return os.path.normcase(os.path.normpath(text))


def _is_volume_recycle_bin(path: str) -> bool:
    """只认盘符根上的系统回收站, 工作区里的同名文件夹不算."""
    text = path[4:] if path.startswith("\\\\?\\") else path
    drive, rest = os.path.splitdrive(text)
    if len(drive) != 2 or drive[1] != ":":
        return False
    parts = [part for part in rest.replace("/", "\\").split("\\") if part]
    return bool(parts) and parts[0].lower() == "$recycle.bin"


def _under_archive(path: str) -> bool:
    archive = _norm_key((os.environ.get(ENV_ARCHIVE) or "").strip())
    if not archive:
        return False
    key = _norm_key(path)
    return key == archive or key.startswith(archive + os.sep)


_REPARSE_POINT = 0x400
_INVALID_ATTR = 0xFFFFFFFF


def _filesystem_path(path: str) -> str:
    """Extend filesystem API inputs without changing policy/IPC path names."""
    if sys.platform != "win32" or path.startswith("\\\\?\\"):
        return path
    absolute = os.path.abspath(path)
    if len(absolute) < 260:
        return path
    drive, tail = os.path.splitdrive(absolute)
    relative = tail.lstrip("\\/")
    if absolute.startswith("\\\\"):
        extended_root = "\\\\?\\UNC{}".format(drive[1:])
        return os.path.join(extended_root, relative)
    extended_root = "\\\\?\\{}\\".format(drive)
    return os.path.join(extended_root, relative)


def _file_attrs(path: str) -> int | None:
    import ctypes
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetFileAttributesW.argtypes = [wintypes.LPCWSTR]
    kernel.GetFileAttributesW.restype = wintypes.DWORD
    value = int(kernel.GetFileAttributesW(_filesystem_path(path)))
    if value == _INVALID_ATTR:
        return None
    return value


def _path_has_reparse(path: str) -> bool:
    """路径自己或任一父目录是连接点/符号链接时返回 True."""
    current = os.path.abspath(path)
    seen: set[str] = set()
    while current not in seen:
        seen.add(current)
        attrs = _file_attrs(current)
        if attrs is not None and attrs & _REPARSE_POINT:
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent
    return False


def _root_variants(path: str) -> list[str]:
    if not path or "\x00" in path:
        return []
    raw = os.path.normpath(os.path.abspath(path))
    if not os.path.isabs(raw) or not os.path.isdir(raw):
        return []
    found = [raw]
    real = os.path.normpath(os.path.realpath(raw))
    if _norm_key(real) != _norm_key(raw) and os.path.isdir(real):
        found.append(real)
    return found


def path_allowed(path: str) -> str | None:
    """返回可以回收的路径, 不展开连接点.

    沙箱钩子会先把相对路径变成完整路径再发过来. 这里仍拒绝没带盘符的路径,
    因为本服务的当前目录不是那条命令的目录. 系统回收站、归档目录、不存在的
    路径、符号链接和目录连接点仍然拒绝.
    """
    if not path or "\x00" in path or not os.path.isabs(path):
        return None
    normalized = os.path.normpath(os.path.abspath(path))
    if _is_volume_recycle_bin(normalized) or _under_archive(normalized):
        return None
    api_path = _filesystem_path(normalized)
    if not os.path.lexists(api_path) or os.path.islink(api_path):
        return None
    if _path_has_reparse(normalized) or not os.path.exists(api_path):
        return None
    return normalized


def _recv_exact(conn: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        chunk = conn.recv(size - len(buf))
        if not chunk:
            raise ConnectionError("recycle broker got a short read")
        buf += chunk
    return bytes(buf)


def _read_frame(conn: socket.socket) -> bytes:
    raw_len = _recv_exact(conn, 4)
    length = struct.unpack(">I", raw_len)[0]
    if length == 0 or length > _FRAME_MAX:
        raise ValueError(f"recycle frame length {length} is out of range")
    return _recv_exact(conn, length)


def _write_frame(conn: socket.socket, payload: bytes) -> None:
    conn.sendall(struct.pack(">I", len(payload)) + payload)


def parse_request(payload: bytes) -> tuple[int, bytes, str, str] | None:
    return _parse_request(payload)


def _parse_request(payload: bytes) -> tuple[int, bytes, str, str] | None:
    if len(payload) < 25 or payload[0] not in (1, 2):
        return None
    action, operation, payload = payload[0], payload[1:17], payload[17:]
    if len(payload) < 8:
        return None
    token_len = struct.unpack_from(">I", payload, 0)[0]
    if token_len == 0 or token_len > _TOKEN_MAX:
        return None
    token_end = 4 + token_len
    if token_end + 4 > len(payload):
        return None
    path_len = struct.unpack_from(">I", payload, token_end)[0]
    if path_len == 0 or path_len > _PATH_MAX:
        return None
    path_end = token_end + 4 + path_len
    if path_end != len(payload):
        return None
    try:
        token = payload[4:token_end].decode("utf-8")
        path = payload[token_end + 4:path_end].decode("utf-8")
    except UnicodeDecodeError:
        return None
    if "\x00" in token or "\x00" in path:
        return None
    return action, operation, token, path


def recycle_with_shell(path: str) -> bool | None:
    """Execute recovery as the desktop user using the shared native library."""
    result = _native_recycler()(path)
    return None if result < 0 else bool(result)


@lru_cache(maxsize=1)
def _native_recycler():
    import ctypes
    from .win_softdelete import dll_path

    dll = ctypes.CDLL(str(dll_path()))
    recover = dll.guard_recover_local
    recover.argtypes = [ctypes.c_wchar_p]
    recover.restype = ctypes.c_int
    return recover


class RecycleBroker:
    """本机回环上的回收请求. 一个沙箱一把令牌, 令牌有效就回收它报来的文件."""

    def __init__(self, recycler: Recycler | None = None) -> None:
        self._recycler = recycler or recycle_with_shell
        self._lock = threading.Lock()
        self._shell_lock = threading.Lock()
        self._receipts: dict[str, dict[bytes, tuple[str, bytes]]] = {}
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stopped = threading.Event()
        self.port = 0

    @property
    def running(self) -> bool:
        return (self._sock is not None and not self._stopped.is_set()
                and self._thread is not None and self._thread.is_alive())

    def start(self, ports: list[int] | None = None) -> int:
        """监听 ``127.0.0.1``. ``ports`` 按顺序尝试, 省略时由系统分配.

        沙箱里要传 WFP 放行范围内、且不是代理端口的候选. 重复调用返回已有端口.
        """
        candidates = list(ports) if ports else [0]
        if not candidates:
            raise RuntimeError("回收站转发没有可监听的放行端口")
        with self._lock:
            if self.running:
                return self.port
            self._stopped.clear()
            sock: socket.socket | None = None
            last_error: OSError | None = None
            for port in candidates:
                trial = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    option = socket.SO_EXCLUSIVEADDRUSE if sys.platform == "win32" else socket.SO_REUSEADDR
                    trial.setsockopt(socket.SOL_SOCKET, option, 1)
                    trial.bind(("127.0.0.1", port))
                    trial.listen(16)
                except OSError as exc:
                    last_error = exc
                    trial.close()
                    continue
                sock = trial
                break
            if sock is None:
                raise RuntimeError("回收站转发未能绑定放行端口") from last_error
            self.port = int(sock.getsockname()[1])
            self._sock = sock
            self._thread = threading.Thread(
                target=self._serve, name="jiuwen-recycle-broker", daemon=True,
            )
            self._thread.start()
        logger.info("recycle broker listening on 127.0.0.1:%s", self.port)
        return self.port

    def stop(self) -> None:
        self._stopped.set()
        with self._lock:
            sock = self._sock
            self._sock = None
            thread = self._thread
            self._thread = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def register(self, roots: list[str]) -> str:
        """确认沙箱至少有一个真实目录, 然后发令牌.

        令牌只用来认出是哪一个沙箱. 之后这个沙箱报来的删除不再按目录收口.
        """
        if not any(_root_variants(root or "") for root in roots):
            raise RuntimeError("回收站转发没有可写根目录, 无法登记沙箱")
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._receipts[token] = {}
        return token

    def unregister(self, token: str) -> None:
        with self._lock:
            self._receipts.pop(token, None)

    def handle_payload(self, payload: bytes) -> bytes:
        """处理一帧请求. 只有回收被确认后才返回 ``ok``."""
        parsed = _parse_request(payload)
        if parsed is None:
            return _NO
        action, operation, token, path = parsed
        with self._lock:
            receipts = self._receipts.get(token)
            if receipts is None:
                return _NO
            existing = receipts.get(operation)
            if existing is not None:
                return existing[1] if existing[0] == path else _NO
            if action == 2:
                return b"??"
            receipts[operation] = (path, b"??")
        result = b"??"
        try:
            with self._shell_lock:
                real = path_allowed(path)
                if real is None:
                    result = _NO
                else:
                    outcome = self._recycler(real)
                    if outcome is not None:
                        result = _OK if outcome else _NO
        except Exception:
            logger.exception("recovery outcome could not be confirmed")
        with self._lock:
            receipts[operation] = (path, result)
        return result

    def _serve(self) -> None:
        sock = self._sock
        if sock is None:
            return
        try:
            while not self._stopped.is_set():
                try:
                    conn, _addr = sock.accept()
                except OSError:
                    return
                threading.Thread(
                    target=self._handle_conn, args=(conn,), name="jiuwen-recycle-conn",
                    daemon=True,
                ).start()
        finally:
            with self._lock:
                if self._sock is sock:
                    self._sock = None
                    self._stopped.set()
            sock.close()

    def _handle_conn(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(15)
            payload = _read_frame(conn)
            _write_frame(conn, self.handle_payload(payload))
        except (OSError, ValueError):
            logger.debug("recycle connection closed", exc_info=True)
        finally:
            try:
                conn.close()
            except OSError:
                pass


def permitted_loopback_ports(port_start: int, port_end: int) -> list[int]:
    """返回沙箱能连上的回环端口, 去掉代理自己占用的起始端口.

    WFP 放行 ``[port_start, port_end]``. 出站代理只绑定 ``port_start``,
    其余端口从高到低留给回收转发.
    """
    if port_end <= port_start:
        return []
    return list(range(port_end, port_start, -1))


def get_broker() -> RecycleBroker | None:
    return _broker


def start_broker(ports: list[int] | None = None) -> RecycleBroker:
    """启动进程内唯一的转发服务."""
    global _broker, _permit_ports
    with _broker_lock:
        if ports:
            _permit_ports = list(ports)
        if _broker is not None and _broker.running:
            return _broker
        broker = RecycleBroker()
        broker.start(_permit_ports or ports)
        _broker = broker
        return broker


def stop_broker() -> None:
    global _broker
    with _broker_lock:
        broker = _broker
        _broker = None
        _permit_ports.clear()
    if broker is not None:
        broker.stop()


def _recover_broker() -> RecycleBroker | None:
    """Recover only while a permitted-port configuration is still active."""
    global _broker
    with _broker_lock:
        if _broker is not None and _broker.running:
            return _broker
        if not _permit_ports:
            return None
        broker = RecycleBroker()
        broker.start(list(_permit_ports))
        _broker = broker
        return broker


def prepare_runner_recycle(env: dict[str, str], roots: list[str]) -> str | None:
    """软删除开启时登记根目录, 并把端口和令牌写进 runner 环境.

    转发服务没起来, 或没有可登记的目录时, 不阻止沙箱启动.
    端口写成 0, 让沙箱里的 DLL 走转发而不是在沙箱内直接调用回收站.
    转发不可用时，受保护删除返回失败。
    """
    env.pop(ENV_RECYCLE_PORT, None)
    env.pop(ENV_RECYCLE_TOKEN, None)
    if not enabled_from_environ():
        return None
    broker = get_broker()
    if broker is None or not broker.running:
        try:
            broker = _recover_broker()
        except Exception:
            logger.exception("回收站转发未能在已放行端口恢复")
    if broker is None or not broker.running:
        logger.error(
            "软删除已开启, 但回收站转发服务没有在监听; 沙箱仍会启动, 受保护删除将返回失败"
        )
        env[ENV_RECYCLE_PORT] = "0"
        env.pop(ENV_RECYCLE_TOKEN, None)
        return None
    try:
        token = broker.register(roots)
    except RuntimeError:
        logger.exception("软删除回收站转发登记失败, 沙箱仍会启动, 受保护删除将返回失败")
        env[ENV_RECYCLE_PORT] = "0"
        env.pop(ENV_RECYCLE_TOKEN, None)
        return None
    env[ENV_RECYCLE_PORT] = str(broker.port)
    env[ENV_RECYCLE_TOKEN] = token
    return token


def detach_runner_recycle(token: str | None) -> None:
    if not token:
        return
    broker = get_broker()
    if broker is not None:
        broker.unregister(token)
