"""Decide's named pipe settles native records before a process guard runs."""

import json
import sys

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="named pipes require Windows")

from agent_shield.policy_engine.server import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry
from agent_shield.intercepts.native_call.decide_pipe import DecidePipe


class FakeHost:
    @staticmethod
    def user_intent():
        return {"text": "work in the project"}

    @staticmethod
    def workspace():
        return {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"}

    @staticmethod
    def capabilities():
        return {"hitl": False, "auto_intent": True}

    @staticmethod
    def request_approval(decision, event):
        return False

    @staticmethod
    def user_rules():
        return []

    @staticmethod
    def grants():
        return []


def _bind():
    return {
        "spec": "process-guard-bind/v1",
        "pid": 10,
        "parent_pid": 9,
        "process_instance_id": "10:100",
        "image": "C:/Windows/System32/cmd.exe",
        "user_sid": "S-1-5-21-1",
        "integrity_level": "medium",
    }


def _record(kind, access, operation_id, resources, category="file"):
    return {
        "spec": "native-record/v1",
        "request_id": f"req-{operation_id}",
        "operation_id": operation_id,
        "time": "2026-10-20T00:00:00Z",
        "process": {
            "pid": 10,
            "tid": 11,
            "parent_pid": 9,
            "process_instance_id": "10:100",
            "image": "C:/Windows/System32/cmd.exe",
            "identity": {"user_sid": "S-1-5-21-1", "integrity_level": "medium"},
        },
        "operation": {"category": category, "kind": kind, "access": access, "resources": resources},
    }


def _client(name):
    ctypes = pytest.importorskip("ctypes")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
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
    handle = kernel32.CreateFileW(name, 0xC0000000, 0, None, 3, 0, None)
    if not handle or handle == ctypes.c_void_p(-1).value:
        raise AssertionError(f"pipe connect failed: {ctypes.get_last_error()}")
    return kernel32, handle


def _write(kernel32, handle, payload: bytes) -> None:
    import ctypes
    from ctypes import wintypes

    frame = len(payload).to_bytes(4, "little") + payload
    written = wintypes.DWORD(0)
    ok = kernel32.WriteFile(handle, ctypes.create_string_buffer(frame), len(frame), ctypes.byref(written), None)
    assert ok and written.value == len(frame)


def _read(kernel32, handle) -> dict:
    import ctypes
    from ctypes import wintypes

    header = ctypes.create_string_buffer(4)
    read = wintypes.DWORD(0)
    assert kernel32.ReadFile(handle, header, 4, ctypes.byref(read), None) and read.value == 4
    length = int.from_bytes(header.raw[:4], "little")
    body = ctypes.create_string_buffer(length)
    assert kernel32.ReadFile(handle, body, length, ctypes.byref(read), None) and read.value == length
    return json.loads(body.raw[:length].decode("utf-8"))


def _send(kernel32, handle, message: dict) -> None:
    _write(kernel32, handle, json.dumps(message).encode("utf-8"))


def test_pipe_settles_allow_deny_mismatch_and_bulk_delete():
    registry = RulesetRegistry()
    info = registry.register({"spec": "agent-pdp/v1"})
    registry.open_task(info.ruleset_id, "user-a", "task-a")
    decide = Decide(
        FakeHost(),
        source={"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
        registry=registry,
        ruleset_id=info.ruleset_id,
        subject_id="user-a",
        task_id="task-a",
        delete_threshold=1,
    )
    pipe = DecidePipe(decide)
    pipe.start()
    try:
        kernel32, handle = _client(pipe.name)
        _send(
            kernel32,
            handle,
            _record("open", "read", "op-read", [{"path": "C:/Users/me/proj/a.txt", "role": "subject"}]),
        )
        unbound = _read(kernel32, handle)
        assert unbound["allow"] is False
        assert unbound["reason"] == "process_identity_mismatch"

        _send(kernel32, handle, _bind())
        _send(
            kernel32,
            handle,
            _record("open", "read", "op-read", [{"path": "C:/Users/me/proj/a.txt", "role": "subject"}]),
        )
        allowed = _read(kernel32, handle)
        assert allowed["allow"] is True
        assert allowed["request_id"] == "req-op-read"
        assert allowed["operation_id"] == "op-read"

        _send(
            kernel32,
            handle,
            _record(
                "delete",
                "delete",
                "op-protected",
                [{"path": "C:/Windows/System32/drivers/etc/hosts", "role": "target"}],
            ),
        )
        denied = _read(kernel32, handle)
        assert denied["allow"] is False

        mismatched = _record("open", "read", "op-mismatch", [{"path": "C:/Users/me/proj/a.txt", "role": "subject"}])
        mismatched["process"]["pid"] = 99
        _send(kernel32, handle, mismatched)
        mismatch = _read(kernel32, handle)
        assert mismatch["allow"] is False
        assert mismatch["reason"] == "process_identity_mismatch"

        _send(
            kernel32,
            handle,
            _record("delete", "delete", "op-del-1", [{"path": "C:/Users/me/proj/a.txt", "role": "target"}]),
        )
        first = _read(kernel32, handle)
        assert first["allow"] is True
        _send(
            kernel32,
            handle,
            {
                "spec": "native-operation-result/v1",
                "request_id": "req-op-del-1",
                "operation_id": "op-del-1",
                "success": True,
                "disposition": "trash",
            },
        )
        _send(
            kernel32,
            handle,
            _record("delete", "delete", "op-del-2", [{"path": "C:/Users/me/proj/b.txt", "role": "target"}]),
        )
        second = _read(kernel32, handle)
        assert second["allow"] is False
        kernel32.CloseHandle(handle)
    finally:
        pipe.close()
