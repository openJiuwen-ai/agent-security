"""Real Windows startup/IPC tests; no model, external network or user files."""

import asyncio
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard import (
    GuardBundleError,
    GuardBundleMissingError,
    GuardInjectionError,
    GuardPipeError,
    GuardPolicyDenied,
    RuntimeGuardManager,
    create_process,
)
from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse

ROOT = Path(__file__).resolve().parents[4]

DLL = guard_binary_directory() / "jiuwen_runtime_guard.dll"

CLIENT = ROOT / "agent_shield/native/windows-dll-guard/build/client.exe"
PYTHON = getattr(sys, "_base_executable", sys.executable)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file() or not CLIENT.is_file(),
    reason="Build the Windows x64 integration client and DLL first",
)


@pytest.mark.parametrize("image", [DLL, CLIENT], ids=["packaged-dll", "client"])
def test_built_image_has_control_flow_guard(image):
    data = image.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    optional = pe + 24
    assert data[pe:pe + 4] == b"PE\0\0"
    assert struct.unpack_from("<H", data, optional)[0] == 0x20B  # PE32+
    characteristics = struct.unpack_from("<H", data, optional + 70)[0]
    required = 0x0040 | 0x0100 | 0x4000  # DYNAMIC_BASE, NX_COMPAT, GUARD_CF
    assert characteristics & required == required


@pytest.mark.parametrize(
    "field,expected",
    [
        ("valid", 0),
        ("dos", 193),
        ("offset", 193),
        ("signature", 193),
        ("machine", 216),
        ("optional_magic", 216),
    ],
)
def test_root_and_child_image_validation_agree(tmp_path, field, expected):
    from agent_shield.intercepts.native_call.dll_guard.windows import _validate_child_header

    with CLIENT.open("rb") as source:
        header = bytearray(source.read(4096))
    pe = struct.unpack_from("<I", header, 0x3C)[0]
    assert header[pe:pe + 4] == b"PE\0\0"
    if field == "dos":
        header[:2] = b"XX"
    elif field == "offset":
        struct.pack_into("<I", header, 0x3C, 3001)
    elif field == "signature":
        header[pe:pe + 4] = b"PE\0X"
    elif field == "machine":
        struct.pack_into("<H", header, pe + 4, 0xAA64)
    elif field == "optional_magic":
        struct.pack_into("<H", header, pe + 24, 0x10B)
    fixture = tmp_path / "header.bin"
    fixture.write_bytes(header)
    assert subprocess.run([CLIENT, "check-child-pe", fixture], check=False).returncode == expected
    if expected:
        with pytest.raises(OSError) as error:
            _validate_child_header(bytes(header))
        assert error.value.winerror == expected
    else:
        assert _validate_child_header(bytes(header)) == pe + 24


@pytest.mark.parametrize(
    "count,size,expected",
    [
        (0, 1, 0),
        (127, 1200, 0),
        (128, 1, 214),
        (1, 1201, 122),
    ],
)
def test_root_and_child_import_limits_agree(count, size, expected):
    from agent_shield.intercepts.native_call.dll_guard.windows import _validate_import_limits

    native = subprocess.run([CLIENT, "check-import-limits", str(count), str(size)], check=False)
    assert native.returncode == expected
    if expected:
        with pytest.raises(OSError) as error:
            _validate_import_limits(count, size)
        assert error.value.winerror == expected
    else:
        _validate_import_limits(count, size)


def test_native_file_name_snapshots_own_the_checked_bytes():
    subprocess.run([CLIENT, "check-name-snapshots"], check=True)


def test_native_address_snapshot_survives_cross_thread_updates():
    subprocess.run([CLIENT, "check-address-snapshots"], check=True, timeout=15)


@pytest.mark.asyncio
async def test_x86_start_reports_architecture_for_root_and_descendant(tmp_path):
    x86 = Path(os.environ["SystemRoot"]) / "SysWOW64" / "cmd.exe"
    if not x86.is_file():
        pytest.skip("WOW64 system executable unavailable")
    manager = RuntimeGuardManager(
        session_id="architecture", dll=DLL, engine=PermissionEngine({"enabled": False})
    )
    try:
        async with manager.tool_execution(
            tool_name="bash", inputs={}, session=None, tool_call_id="root"
        ):
            with pytest.raises(GuardInjectionError) as failure:
                await create_process(asyncio.create_subprocess_exec, str(x86), "/d", "/c", "exit 0")
            assert failure.value.__cause__.winerror == 216
        async with manager.tool_execution(
            tool_name="bash", inputs={}, session=None, tool_call_id="child"
        ):
            script = (
                "import subprocess,sys\n"
                "try: subprocess.run([sys.argv[1], '/d', '/c', 'exit 0'], check=True)\n"
                "except OSError as exc: print(exc.winerror)\n"
            )
            process = await create_process(
                asyncio.create_subprocess_exec,
                PYTHON,
                "-I",
                "-c",
                script,
                str(x86),
                cwd=tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), 10)
            assert process.returncode == 0 and stdout.strip() == b"216", (stdout, stderr)
    finally:
        await manager.close(permanent=True)


@pytest.mark.asyncio
async def test_process_endpoint_cache_revokes_on_active_callback(tmp_path):
    received = asyncio.get_running_loop().create_future()

    async def receive(reader, writer):
        received.set_result(await reader.read())
        writer.close()
        await writer.wait_closed()

    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "net_guard": {"enabled": True, "defaults": "allow"},
        },
        workspace_root=tmp_path,
    )

    async def unexpected(card):
        raise AssertionError(card)

    async with (
        await asyncio.start_server(receive, "127.0.0.1", 0) as server,
        WindowsGuardExecution(
            session_id="cache",
            tool_call_id="endpoint",
            dll=DLL,
            approvals=RuntimeApprovalRequests(),
            engine=engine,
            root_command_approved=True,
            emit=unexpected,
        ) as guard,
    ):
        port = server.sockets[0].getsockname()[1]
        checks = []
        original = guard.check_resource

        async def record(pid, subject, **kwargs):
            if subject["kind"] == "endpoint" and subject["port"] == port:
                checks.append(subject)
            return await original(pid, subject, **kwargs)

        guard.check_resource = record
        script = (
            f"import socket,sys\ns=socket.create_connection(('127.0.0.1',{port}))\n"
            "for _ in range(4): s.sendall(b'x')\nprint('READY',flush=True)\nsys.stdin.readline()\n"
            "s.sendall(b'y'); s.close()"
        )
        process = await guard.launch(
            asyncio.create_subprocess_exec,
            PYTHON,
            "-I",
            "-c",
            script,
            cwd=tmp_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        assert (await asyncio.wait_for(process.stdout.readline(), 10)).strip() == b"READY"
        assert len(checks) == 1
        engine.set_permission_checks_active(lambda: True)
        await asyncio.wait_for(process.communicate(b"continue\n"), 10)
        assert process.returncode == 0 and len(checks) == 2
        assert await asyncio.wait_for(received, 5) == b"xxxxy"


@pytest.mark.asyncio
@pytest.mark.parametrize("uniform", [True, False])
async def test_process_read_cache_obeys_live_policy(tmp_path, uniform):
    target = tmp_path / "sample"
    target.write_bytes(b"x")
    rules = [] if uniform else [{"path": str(tmp_path / "private"), "read": "deny"}]
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "tools": {"bash": "allow"},
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "exec": "allow"},
            "paths": rules,
        },
    }
    engine = PermissionEngine(config, workspace_root=tmp_path)

    async def unexpected(card):
        raise AssertionError(card)

    async with WindowsGuardExecution(
        session_id="cache",
        tool_call_id="read",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=engine,
        root_command_approved=True,
        emit=unexpected,
    ) as guard:
        observed = []
        check = guard.check_access

        async def record(pid, path, mask):
            if path.endswith("\\sample"):
                observed.append(mask)
            return await check(pid, path, mask)

        guard.check_access = record
        script = (
            "import sys\nfor _ in range(4):\n with open('sample','rb') as f: assert f.read()==b'x'\n"
            "print('READY',flush=True)\nsys.stdin.readline()\n"
            "try: open('sample','rb')\nexcept PermissionError: print('DENIED')"
        )
        process = await guard.launch(
            asyncio.create_subprocess_exec,
            PYTHON,
            "-I",
            "-c",
            script,
            cwd=tmp_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
        )
        assert (await asyncio.wait_for(process.stdout.readline(), 10)).strip() == b"READY"
        assert observed == [1] * (1 if uniform else 4)
        engine.update_config(
            {
                **config,
                "file_guard": {
                    **config["file_guard"],
                    "paths": [{"path": str(target), "read": "deny"}],
                },
            }
        )
        stdout, _ = await asyncio.wait_for(process.communicate(b"continue\n"), 10)
        assert process.returncode == 0 and stdout.strip() == b"DENIED"
        assert len(observed) == (2 if uniform else 5)


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
@pytest.mark.parametrize("depth", [0, 2])
async def test_real_process_waits_and_resumes_once(tmp_path, approved, depth):
    target = tmp_path / "data.txt"
    target.write_text("RUNTIME_CONTENT", encoding="utf-8")
    marker = tmp_path / "starts.txt"
    cards = []
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{"path": str(target), "read": "ask", "write": "ask", "exec": "ask"}],
            },
        },
        workspace_root=tmp_path / "workspace",
    )

    async def emit(card):
        cards.append(card)
        await asyncio.sleep(0.05)
        assert marker.read_text() == "START\n"
        assert not manager.approvals.resolve(
            "other-session", card["request_id"], PermissionConfirmResponse(approved=True)
        )
        assert manager.approvals.resolve(
            "session", card["request_id"], PermissionConfirmResponse(approved=approved)
        )

    manager = RuntimeGuardManager(
        session_id="session",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
    )
    try:
        async with manager.tool_execution(
            tool_name="bash", inputs={}, session=None, tool_call_id="real-call"
        ):
            process = await create_process(
                asyncio.create_subprocess_exec,
                str(CLIENT),
                str(target),
                str(marker),
                str(depth),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            execution = next(iter(manager.active))
            assert execution.job.contains(process.pid)
            out, err = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == (0 if approved else 5), (out, err)
        assert (b"RUNTIME_CONTENT" in out) is approved
        assert len(cards) == 1
        if approved:
            lines = out.splitlines()
            assert len(lines) == 3
            assert lines[1] == lines[2]
            # PID/TID was printed before ASK and is unchanged after approval.
            assert lines[0].removeprefix(b"START_") == lines[1].split(b" CONTENT=")[0]
            assert (f"PID={process.pid} ".encode() in out) is (depth == 0)
    finally:
        await manager.close(permanent=True)
    assert marker.read_text() == "START\n"
    assert not execution.context.active


@pytest.mark.asyncio
async def test_missing_dll_never_starts_process(tmp_path):
    async def emit(_card):
        pytest.fail("No approval expected")

    with pytest.raises(GuardBundleMissingError):
        async with WindowsGuardExecution(
            session_id="s",
            tool_call_id="c",
            dll=tmp_path / "absent.dll",
            approvals=RuntimeApprovalRequests(),
            engine=lambda: None,
            emit=emit,
        ):
            pytest.fail("Missing DLL must refuse startup")


@pytest.mark.asyncio
@pytest.mark.parametrize("finish", ["timeout", "cancel"])
async def test_waiting_process_is_denied_or_killed_and_late_answer_rejected(tmp_path, finish):
    target = tmp_path / "data.txt"
    target.write_text("secret")
    marker = tmp_path / "started"
    registry = RuntimeApprovalRequests()
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{"path": str(target), "read": "ask", "write": "ask", "exec": "ask"}],
            },
        },
        workspace_root=tmp_path / "workspace",
    )
    seen = asyncio.Future()
    assert engine.check_file_accesses([(target, "read")]).needs_approval

    async def emit(card):
        seen.set_result(card)

    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        approval_timeout=0.15,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(CLIENT),
            str(target),
            str(marker),
            "2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        card = await asyncio.wait_for(seen, 5)
        assert marker.read_text() == "START\n"
        if finish == "cancel":
            await asyncio.wait_for(execution.close(), 5)
        else:
            stdout, _stderr = await asyncio.wait_for(process.communicate(), 5)
            assert process.returncode == 5
            assert b"secret" not in stdout
        assert not registry.resolve(
            "s", card["request_id"], PermissionConfirmResponse(approved=True)
        )
    assert process.returncode is not None


@pytest.mark.asyncio
async def test_os_peer_pid_rejects_forged_job_member(tmp_path):
    import ctypes as ct
    from ctypes import wintypes as wt

    emitted = []

    async def emit(card):
        emitted.append(card)

    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: None,
        emit=emit,
    ) as execution:
        # Host is outside this Job. Claiming a job PID in the message cannot
        # turn it into an authenticated pipe peer, even with the actual name.
        def forge():
            kernel = ct.WinDLL("kernel32", use_last_error=True)
            kernel.CreateFileW.argtypes = [
                wt.LPCWSTR,
                wt.DWORD,
                wt.DWORD,
                ct.c_void_p,
                wt.DWORD,
                wt.DWORD,
                wt.HANDLE,
            ]
            kernel.CreateFileW.restype = wt.HANDLE
            kernel.WriteFile.argtypes = [wt.HANDLE, ct.c_void_p, wt.DWORD, ct.c_void_p, ct.c_void_p]
            kernel.ReadFile.argtypes = kernel.WriteFile.argtypes
            kernel.CloseHandle.argtypes = [wt.HANDLE]
            handle = kernel.CreateFileW(execution.pipe_name, 0xC0000000, 0, None, 3, 0, None)
            assert handle not in (None, ct.c_void_p(-1).value)
            try:
                packet = struct.pack("<5I", 0x44475231, 12345, 1, 1, 3) + b"X:/"
                size = wt.DWORD()
                kernel.WriteFile(handle, packet, len(packet), ct.byref(size), None)
                response = ct.create_string_buffer(12)
                assert not kernel.ReadFile(handle, response, 12, ct.byref(size), None)
            finally:
                kernel.CloseHandle(handle)

        await asyncio.wait_for(asyncio.to_thread(forge), 5)
        assert emitted == []


@pytest.mark.asyncio
async def test_context_reports_unbound_popen_only(caplog):
    manager = RuntimeGuardManager(
        session_id="audit", dll=DLL, engine=PermissionEngine({"enabled": False})
    )
    try:
        async with manager.tool_execution(
            tool_name="bash", inputs={}, session=None, tool_call_id="c"
        ):
            await asyncio.to_thread(
                subprocess.run, [PYTHON, "-I", "-c", "pass"], check=True
            )
            proc = await create_process(
                asyncio.create_subprocess_exec, PYTHON, "-I", "-c", "pass"
            )
            assert await proc.wait() == 0
        await asyncio.to_thread(
            subprocess.run, [PYTHON, "-I", "-c", "pass"], check=True
        )
        messages = [event for event in caplog.messages if "outside the DLL Guard launcher" in event]
        assert len(messages) == 1
    finally:
        await manager.close(permanent=True)


@pytest.mark.asyncio
async def test_later_denied_launch_preserves_running_background_process(tmp_path):
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [{"path": str(CLIENT), "exec": "deny"}],
            },
        },
        workspace_root=tmp_path,
    )
    manager = RuntimeGuardManager(session_id="background", dll=DLL, engine=engine)
    try:
        with pytest.raises(GuardPolicyDenied):
            async with manager.tool_execution(
                tool_name="bash", inputs={}, session=None, tool_call_id="c"
            ):
                background = await create_process(
                    asyncio.create_subprocess_exec,
                    PYTHON,
                    "-I",
                    "-c",
                    "import sys; print(sys.stdin.readline().strip())",
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                )
                await create_process(asyncio.create_subprocess_exec, str(CLIENT))
        stdout, _ = await asyncio.wait_for(background.communicate(b"still running\n"), 10)
        assert stdout.strip() == b"still running" and background.returncode == 0
    finally:
        await manager.close(permanent=True)


@pytest.mark.asyncio
async def test_injection_failure_kills_suspended_process_before_user_code(tmp_path, monkeypatch):
    async def emit(_card):
        pytest.fail("No resource request before injection")

    marker = tmp_path / "never-started"
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: PermissionEngine({"enabled": False}),
        emit=emit,
    ) as execution:

        def fail(*_args):
            raise OSError("injection failed")

        monkeypatch.setattr(execution.job, "inject_and_resume", fail)
        with pytest.raises(GuardInjectionError, match="injection failed") as failure:
            await execution.launch(
                asyncio.create_subprocess_exec, str(CLIENT), str(tmp_path / "data"), str(marker)
            )
        assert isinstance(failure.value.__cause__, OSError)
        assert execution.processes[0].returncode is not None
        assert not marker.exists()


@pytest.mark.asyncio
async def test_validated_bundle_stays_pinned_and_releases_on_failure(tmp_path):
    import _winapi

    from agent_shield.intercepts.native_call.dll_guard.bundle import guard_manifest_path

    directory = tmp_path / "installed"
    directory.mkdir()
    dll = directory / DLL.name
    manifest = guard_manifest_path(dll)
    shutil.copyfile(DLL, dll)
    shutil.copyfile(guard_manifest_path(DLL), manifest)

    def execution():
        return WindowsGuardExecution(
            session_id="s",
            tool_call_id="c",
            dll=dll,
            approvals=RuntimeApprovalRequests(),
            engine=lambda: None,
            emit=None,
        )

    async with execution():
        for path in (dll, manifest):
            with pytest.raises(PermissionError) as error:
                handle = _winapi.CreateFile(str(path), 0x40000000, 7, 0, 3, 0, 0)
                _winapi.CloseHandle(handle)
            assert error.value.winerror == 32
        with pytest.raises(PermissionError):
            directory.rename(tmp_path / "moved")
        assert manifest.read_bytes()
    with dll.open("r+b"), pytest.raises(GuardBundleError):
        async with execution():
            pytest.fail("An existing writer must prevent validation")
    manifest.write_text("{}", encoding="utf-8")
    with pytest.raises(GuardBundleError, match="mismatch"):
        async with execution():
            pytest.fail("Invalid bundle reached runtime")
    directory.rename(tmp_path / "moved")


@pytest.mark.asyncio
async def test_pipe_instances_use_protected_current_user_dacl(monkeypatch):
    import _winapi
    import ctypes as ct
    from ctypes import wintypes as wt
    from unittest.mock import Mock

    from agent_shield.intercepts.native_call.decide_pipe import _dlls, _TokenUser
    from agent_shield.intercepts.native_call.dll_guard.pipe import GuardPipeServer

    create = Mock(wraps=_winapi.CreateNamedPipe)
    monkeypatch.setattr(_winapi, "CreateNamedPipe", create)
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: None,
        emit=None,
    ) as execution:
        server = execution.servers[0]
        kernel, security = _dlls()
        ptr = ct.c_void_p
        get_security = security.GetSecurityInfo
        get_security.argtypes = [wt.HANDLE, ct.c_int, wt.DWORD, ptr, ptr, ptr, ptr, ct.POINTER(ptr)]
        control, revision = wt.WORD(), wt.DWORD()
        security.GetSecurityDescriptorControl.argtypes = [
            ptr,
            ct.POINTER(wt.WORD),
            ct.POINTER(wt.DWORD),
        ]
        security.GetAce.argtypes = [ptr, wt.DWORD, ct.POINTER(ptr)]
        security.EqualSid.argtypes = [ptr, ptr]
        token, size = wt.HANDLE(), wt.DWORD()
        assert security.OpenProcessToken(kernel.GetCurrentProcess(), 8, ct.byref(token))
        try:
            security.GetTokenInformation(token, 1, None, 0, ct.byref(size))
            user = ct.create_string_buffer(size.value)
            assert security.GetTokenInformation(token, 1, user, size, ct.byref(size))
            sid = _TokenUser.from_buffer_copy(user).Sid
        finally:
            kernel.CloseHandle(token)
        for _ in range(2):
            assert create.call_args.args[2] & 8  # PIPE_REJECT_REMOTE_CLIENTS
            acl, sd, ace = ptr(), ptr(), ptr()
            assert (
                get_security(
                    server.listener.fileno(), 1, 4, None, None, ct.byref(acl), None, ct.byref(sd)
                )
                == 0
            )
            try:
                assert security.GetSecurityDescriptorControl(
                    sd, ct.byref(control), ct.byref(revision)
                )
                assert control.value & 0x1000  # SE_DACL_PROTECTED
                assert acl.value and wt.WORD.from_address(acl.value + 4).value == 1  # ACL.AceCount
                assert security.GetAce(acl, 0, ct.byref(ace))
                assert ct.c_ubyte.from_address(ace.value).value == 0  # ACCESS_ALLOWED_ACE_TYPE
                assert security.EqualSid(sid, ace.value + 8)  # ACCESS_ALLOWED_ACE.SidStart
            finally:
                kernel.LocalFree(sd)
            with pytest.raises(GuardPipeError):
                GuardPipeServer(execution.pipe_name, asyncio.Protocol)
            accepted = server.pending
            client = _winapi.CreateFile(execution.pipe_name, 0xC0000000, 0, 0, 3, 0, 0)
            try:
                await asyncio.wait_for(asyncio.shield(accepted), 2)
                await asyncio.sleep(0)
            finally:
                _winapi.CloseHandle(client)


@pytest.mark.asyncio
async def test_native_codepage_install_path_with_descendants(tmp_path):
    stage = tmp_path / "暂存目录"
    try:
        str(stage).encode("mbcs", errors="strict")
    except UnicodeEncodeError:
        pytest.skip("CJK path is not representable in this Windows code page")
    stage.mkdir()
    installed = stage / DLL.name
    shutil.copyfile(DLL, installed)
    manifest = installed.with_suffix(".manifest.json")
    shutil.copyfile(DLL.with_suffix(".manifest.json"), manifest)
    target, marker = tmp_path / "数据.txt", tmp_path / "starts"
    target.write_text("UNICODE_GUARDED")
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=installed,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: PermissionEngine({"enabled": False}),
        emit=None,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(CLIENT),
            str(target),
            str(marker),
            "2",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0 and b"UNICODE_GUARDED" in output[0], output
    assert set(stage.iterdir()) == {installed, manifest}


@pytest.mark.asyncio
async def test_fixed_dll_concurrent_and_repeated_executions_without_staging(tmp_path, monkeypatch):
    """Same DLL, separate policies, descendants and explicit env; no lifecycle file I/O."""
    target = tmp_path / "target.txt"
    target.write_text("SHARED_DLL_CONTENT")
    before = DLL.stat().st_mtime_ns, hashlib.sha256(DLL.read_bytes()).digest()
    records = []

    async def run(index, allowed):
        requests = RuntimeApprovalRequests()
        session_id = f"session-{index}"
        cards = []
        engine = PermissionEngine(
            {
                "enabled": True,
                "package_builtin_rules": False,
                "tools": {"bash": "allow"},
                "file_guard": {
                    "enabled": True,
                    "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                    "paths": [{"path": str(target), "read": "ask", "write": "ask", "exec": "ask"}],
                },
            },
            workspace_root=tmp_path / "workspace",
        )
        assert engine.check_file_accesses([(target, "read")]).needs_approval

        async def emit(card):
            cards.append(card)
            await asyncio.sleep(0.02)
            requests.resolve(
                session_id, card["request_id"], PermissionConfirmResponse(approved=allowed)
            )

        async with WindowsGuardExecution(
            session_id=session_id,
            tool_call_id=f"c-{index}",
            dll=DLL,
            engine=lambda: engine,
            emit=emit,
            approvals=requests,
        ) as execution:
            assert execution.dll == DLL.resolve()
            records.append((execution.pipe_name, execution.bootstrap))
            process = await execution.launch(
                asyncio.create_subprocess_exec,
                str(CLIENT),
                str(target),
                str(tmp_path / f"starts-{index}"),
                "2",
                env={"SystemRoot": os.environ["SystemRoot"]},
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await asyncio.wait_for(process.communicate(), 15)
            assert process.returncode == (0 if allowed else 5), (out, err)
            assert (b"SHARED_DLL_CONTENT" in out) is allowed
            assert len(cards) == 1 and cards[0]["session_id"] == session_id, (
                index,
                allowed,
                out,
                err,
            )

    # Deny all Python-side staging operations during execution and cleanup.
    with monkeypatch.context() as patch:

        def unexpected(*_args, **_kwargs):
            pytest.fail("Guard lifecycle must not create/copy/write/remove files")

        for method in ("mkdir", "write_bytes", "write_text", "unlink", "rmdir"):
            patch.setattr(Path, method, unexpected)
        patch.setattr(shutil, "copyfile", unexpected)
        await asyncio.gather(run(1, True), run(2, False))
        await run(3, True)
    assert len({pipe for pipe, _ in records}) == 3
    assert len({config for _, config in records}) == 3
    assert before == (DLL.stat().st_mtime_ns, hashlib.sha256(DLL.read_bytes()).digest())
    assert sorted(path.name for path in tmp_path.iterdir()) == [
        "starts-1",
        "starts-2",
        "starts-3",
        "target.txt",
    ]
