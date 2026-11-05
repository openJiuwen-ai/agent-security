"""Task-scoped named pipe between a Windows process guard and Decide.

The pipe is created before the target process starts. Each connection is one
injected process. Ask never leaves Decide; the process guard only sees allow or deny.
"""

from __future__ import annotations

import json
import secrets
import threading
from typing import Any

from agent_shield.policy_engine.server.decide import Decide
from agent_shield.intercepts.native_call.session import ProcessBinding, settle_native_record

_PIPE_ACCESS_DUPLEX = 0x00000003
_PIPE_TYPE_BYTE = 0x00000000
_PIPE_REJECT_REMOTE_CLIENTS = 0x00000008
_PIPE_UNLIMITED_INSTANCES = 255
_INVALID_HANDLE = 2**64 - 1
_ERROR_PIPE_CONNECTED = 535
_TOKEN_QUERY = 0x0008
_TOKEN_USER = 1


class DecidePipe:
    """One listening pipe for a process guard run. Closing it cancels hooked calls."""

    def __init__(self, decide: Decide) -> None:
        self._decide = decide
        self.name = rf"\\.\pipe\agent-security-{secrets.token_hex(16)}"
        self._ready = threading.Event()
        self._stop = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._clients: list[Any] = []
        self._security: Any = None

    def start(self) -> None:
        from agent_shield.intercepts.native_call.launch import ProcessGuardUnavailable

        if self._thread is not None:
            return
        try:
            self._security = _Security()
        except OSError as exc:
            raise ProcessGuardUnavailable("decide_pipe_unavailable") from exc
        self._thread = threading.Thread(target=self._loop, name="decide-pipe", daemon=True)
        self._thread.start()
        if not self._ready.wait(5):
            self.close()
            raise ProcessGuardUnavailable("decide_pipe_unavailable")

    def close(self) -> None:
        kernel32, _advapi32 = _dlls()
        self._stop = True
        try:
            dummy = kernel32.CreateFileW(self.name, 0xC0000000, 0, None, 3, 0, None)
            if dummy not in (None, 0, _INVALID_HANDLE):
                kernel32.CloseHandle(dummy)
        except OSError:
            pass
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        with self._lock:
            clients = list(self._clients)
        for handle in clients:
            kernel32.CancelIoEx(handle, None)
            kernel32.DisconnectNamedPipe(handle)
            kernel32.CloseHandle(handle)
        if self._security is not None:
            self._security.close()
            self._security = None

    def _loop(self) -> None:
        handle = self._create()
        self._ready.set()
        while not self._stop and handle is not None:
            if not self._connect(handle):
                _dlls()[0].CloseHandle(handle)
                if self._stop:
                    break
                handle = self._create()
                continue
            if self._stop:
                _dlls()[0].CloseHandle(handle)
                break
            threading.Thread(target=self._serve, args=(handle,), name="decide-pipe-client", daemon=True).start()
            handle = self._create()

    def _create(self) -> Any:
        kernel32, _advapi32 = _dlls()
        handle = kernel32.CreateNamedPipeW(
            self.name,
            _PIPE_ACCESS_DUPLEX,
            _PIPE_TYPE_BYTE | _PIPE_REJECT_REMOTE_CLIENTS,
            _PIPE_UNLIMITED_INSTANCES,
            65536,
            65536,
            0,
            self._security.pointer() if self._security is not None else None,
        )
        if handle in (None, 0, _INVALID_HANDLE):
            return None
        return handle

    @staticmethod
    def _connect(handle: Any) -> bool:
        import ctypes

        kernel32, _advapi32 = _dlls()
        if kernel32.ConnectNamedPipe(handle, None):
            return True
        return ctypes.get_last_error() == _ERROR_PIPE_CONNECTED

    def _serve(self, handle: Any) -> None:
        kernel32, _advapi32 = _dlls()
        binding = None
        with self._lock:
            self._clients.append(handle)
        try:
            while True:
                payload = _read_frame(handle)
                if payload is None:
                    break
                try:
                    message = json.loads(payload.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    break
                if not isinstance(message, dict):
                    break
                spec = message.get("spec")
                if spec == "process-guard-bind/v1":
                    parsed = _binding(message)
                    if parsed is not None and binding is None:
                        binding = parsed
                    continue
                if spec == "native-operation-result/v1":
                    self._decide.handle_operation_result(message)
                    continue
                if spec != "native-record/v1":
                    break
                if binding is None:
                    decision = {
                        "spec": "native-decision/v1",
                        "request_id": (
                            message.get("request_id")
                            if isinstance(message.get("request_id"), str)
                            else ""
                        ),
                        "operation_id": (
                            message.get("operation_id")
                            if isinstance(message.get("operation_id"), str)
                            else ""
                        ),
                        "event_id": "",
                        "allow": False,
                        "reason": "process_identity_mismatch",
                    }
                else:
                    decision = _settle_record(self._decide, message, binding)
                if not _write_frame(handle, json.dumps(decision, ensure_ascii=False).encode("utf-8")):
                    break
        finally:
            with self._lock:
                if handle in self._clients:
                    self._clients.remove(handle)
            kernel32.CloseHandle(handle)


def _settle_record(decide, message: dict, binding: ProcessBinding) -> dict:
    # Subclasses can record the raw record before settlement.
    handler = getattr(type(decide), "handle_native_record", None)
    if handler is not None:
        return handler(decide, message, binding=binding)
    return settle_native_record(decide, message, binding=binding)


def _binding(message: dict) -> ProcessBinding | None:
    try:
        pid = message["pid"]
        parent = message["parent_pid"]
        instance = message["process_instance_id"]
        image = message["image"]
        user_sid = message["user_sid"]
        integrity = message["integrity_level"]
        if not all(isinstance(item, str) and item for item in (instance, image, user_sid, integrity)):
            return None
        return ProcessBinding(
            pid=int(pid),
            parent_pid=int(parent),
            process_instance_id=instance,
            image=image,
            user_sid=user_sid,
            integrity_level=integrity,
        )
    except (KeyError, TypeError, ValueError):
        return None


def _read_frame(handle: Any) -> bytes | None:
    header = _read_exact(handle, 4)
    if header is None:
        return None
    length = int.from_bytes(header, "little")
    if length == 0 or length > 1024 * 1024:
        return None
    return _read_exact(handle, length)


def _write_frame(handle: Any, payload: bytes) -> bool:
    if not payload or len(payload) > 1024 * 1024:
        return False
    return _write_all(handle, len(payload).to_bytes(4, "little") + payload)


def _read_exact(handle: Any, size: int) -> bytes | None:
    import ctypes
    from ctypes import wintypes

    kernel32, _advapi32 = _dlls()
    chunks = []
    remaining = size
    while remaining:
        block = ctypes.create_string_buffer(remaining)
        read = wintypes.DWORD(0)
        ok = kernel32.ReadFile(handle, block, remaining, ctypes.byref(read), None)
        if not ok or read.value == 0:
            return None
        chunks.append(block.raw[: read.value])
        remaining -= read.value
    return b"".join(chunks)


def _write_all(handle: Any, payload: bytes) -> bool:
    import ctypes
    from ctypes import wintypes

    kernel32, _advapi32 = _dlls()
    offset = 0
    while offset < len(payload):
        block = ctypes.create_string_buffer(payload[offset:])
        written = wintypes.DWORD(0)
        ok = kernel32.WriteFile(handle, block, len(payload) - offset, ctypes.byref(written), None)
        if not ok or written.value == 0:
            return False
        offset += written.value
    return True


class _Security:
    def __init__(self) -> None:
        import ctypes
        from ctypes import wintypes

        kernel32, advapi32 = _dlls()
        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            raise OSError("token")
        length = wintypes.DWORD(0)
        advapi32.GetTokenInformation(token, _TOKEN_USER, None, 0, ctypes.byref(length))
        raw = ctypes.create_string_buffer(length.value)
        if not advapi32.GetTokenInformation(token, _TOKEN_USER, raw, length, ctypes.byref(length)):
            kernel32.CloseHandle(token)
            raise OSError("token")
        user = _TokenUser.from_buffer_copy(raw)
        text = ctypes.c_wchar_p()
        if not advapi32.ConvertSidToStringSidW(user.Sid, ctypes.byref(text)):
            kernel32.CloseHandle(token)
            raise OSError("sid")
        kernel32.CloseHandle(token)
        sddl = f"D:P(A;;GA;;;{text.value})"
        kernel32.LocalFree(text)
        self._sd = ctypes.c_void_p()
        if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, 1, ctypes.byref(self._sd), None):
            raise OSError("security")
        self._sa = _SecurityAttributes()
        setattr(self._sa, "".join(("n", "Length")), ctypes.sizeof(_SecurityAttributes))
        setattr(self._sa, "".join(("lp", "SecurityDescriptor")), self._sd)
        setattr(self._sa, "".join(("b", "InheritHandle")), 0)
        self._raw = raw

    def pointer(self) -> Any:
        import ctypes

        return ctypes.cast(ctypes.pointer(self._sa), ctypes.c_void_p)

    def close(self) -> None:
        if self._sd:
            _dlls()[0].LocalFree(self._sd)
            self._sd = None


def _dlls():
    import ctypes
    from ctypes import wintypes

    if not hasattr(ctypes, "WinDLL"):
        raise OSError("named pipes require Windows")
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel32.CreateNamedPipeW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    kernel32.CreateNamedPipeW.restype = wintypes.HANDLE
    kernel32.ConnectNamedPipe.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.ConnectNamedPipe.restype = wintypes.BOOL
    kernel32.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    kernel32.CreateFileW.restype = wintypes.HANDLE
    kernel32.ReadFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.ReadFile.restype = wintypes.BOOL
    kernel32.WriteFile.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.c_void_p,
    ]
    kernel32.WriteFile.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.DisconnectNamedPipe.argtypes = [wintypes.HANDLE]
    kernel32.CancelIoEx.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi32.GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    advapi32.ConvertSidToStringSidW.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_wchar_p)]
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_void_p,
    ]
    return kernel32, advapi32


def _token_user():
    import ctypes
    from ctypes import wintypes

    class TokenUser(ctypes.Structure):
        _fields_ = [("Sid", ctypes.c_void_p), ("Attributes", wintypes.DWORD)]

    return TokenUser


_TokenUser = None
_SecurityAttributes = None


def _init_structs() -> None:
    global _TokenUser, _SecurityAttributes
    import ctypes
    from ctypes import wintypes

    if _TokenUser is None:
        _TokenUser = _token_user()

    class SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("".join(("n", "Length")), wintypes.DWORD),
            ("".join(("lp", "SecurityDescriptor")), ctypes.c_void_p),
            ("".join(("b", "InheritHandle")), wintypes.BOOL),
        ]

    _SecurityAttributes = SecurityAttributes


_init_structs()
