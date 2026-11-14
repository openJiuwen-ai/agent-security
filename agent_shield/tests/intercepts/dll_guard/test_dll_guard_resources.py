"""Actual file side effects and loopback traffic, with the combined DLL hooks."""

import asyncio
import os
import sys
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.intercepts.native_call.dll_guard.shell_launch import approved_programs
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse

ROOT = Path(__file__).resolve().parents[4]

DLL = guard_binary_directory() / "jiuwen_runtime_guard.dll"

CLIENT = ROOT / "agent_shield/native/windows-dll-guard/build/client.exe"


def nt_path(prefix, rest):
    """Keep an NT prefix that os.path.join would drop for a drive or absolute tail."""
    marker = "dll-guard-marker"
    return os.path.join(prefix, marker).replace(marker, rest, 1)

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file() or not CLIENT.is_file(),
    reason="Build Windows Guard/client first",
)


def policy(tmp_path, *, paths=None, net=None, tools=None):
    return PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": tools or {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": paths or [],
            },
            "net_guard": net or {"enabled": False},
        },
        workspace_root=tmp_path / "workspace",
    )


async def run_client(tmp_path, engine, arguments, *, approved=True, approval=None):
    registry, cards = RuntimeApprovalRequests(), []

    async def emit(card):
        cards.append(card)
        registry.resolve("s", card["request_id"], PermissionConfirmResponse(approved=approved))

    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="call",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
    ) as execution:
        if approval is not None:
            execution.seed_approved_operation(approval)
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(CLIENT),
            *map(str, arguments),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 10)
        return process.returncode, output, cards


@pytest.mark.asyncio
@pytest.mark.parametrize("host_confirmed", [True, False])
async def test_real_git_bash_forwards_one_batch_delete_confirmation(tmp_path, host_confirmed):
    operation = {
        "kind": "command",
        "command": "rm a.txt b.txt",
        "cwd": str(tmp_path),
        "shell_type": "bash",
    }
    programs = approved_programs(operation)
    if not any(Path(p["exe"]).name.lower() == "rm.exe" for p in programs):
        pytest.skip("Requires Git Bash with rm")
    targets = [tmp_path / name for name in ("a.txt", "b.txt")]
    for path in targets:
        path.touch()
    engine = policy(tmp_path)
    engine.update_config(
        {**engine.config, "soft_delete": {"enabled": True, "batch_delete_threshold": 2}}
    )
    registry, cards = RuntimeApprovalRequests(), []

    async def emit(event):
        cards.append(event)
        registry.resolve(
            "batch",
            event["request_id"],
            PermissionConfirmResponse(not host_confirmed and len(cards) == 1),
        )

    async with WindowsGuardExecution(
        session_id="batch",
        tool_call_id="delete",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        root_command_approved=True,
    ) as execution:
        shell = programs[0]
        if host_confirmed:
            execution.seed_approved_operation({"operation": operation})
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            shell["exe"],
            *shell["argv"],
            cwd=tmp_path,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(process.communicate(), 20)
        assert process.returncode == 0, (stderr, cards)
        assert len(cards) == int(not host_confirmed)
        assert all(not path.exists() for path in targets)


@pytest.mark.asyncio
@pytest.mark.parametrize("source_tool", ["powershell", "core.powershell", "mcp_exec_command"])
async def test_native_powershell_program_does_not_need_an_ast_approval(tmp_path, source_tool):
    target, marker = tmp_path / "data.txt", tmp_path / "started.txt"
    target.write_text("NATIVE_POWERSHELL_CONTENT")
    engine = policy(tmp_path, tools={source_tool: "allow", "bash": "deny"})
    cards, registry = [], RuntimeApprovalRequests()

    async def emit(card):
        cards.append(card)
        registry.resolve("s", card["request_id"], PermissionConfirmResponse(approved=False))

    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="call",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        source_tool=source_tool,
        source_shell="powershell",
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(CLIENT),
            str(target),
            str(marker),
            "0",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode == 0 and not cards, (output, cards)
        assert b"NATIVE_POWERSHELL_CONTENT" in output[0]
    assert marker.read_text() == "START\n"


@pytest.mark.asyncio
async def test_confirmed_root_url_matches_native_winhttp(tmp_path):
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        engine = policy(tmp_path, net={"enabled": True, "defaults": "ask"})
        approval = {"operation": {"kind": "url", "url": f"http://127.0.0.1:{port}"}, "accesses": []}
        code, output, cards = await run_client(
            tmp_path, engine, ["127.0.0.1", port, "http", "/"], approved=False, approval=approval
        )
        assert code == 0 and not cards, (output, cards)
        assert len(received) == 1 and received[0].startswith(b"GET / HTTP/1.1\r\n")


@pytest.mark.asyncio
@pytest.mark.parametrize("allowed", [True, False])
async def test_volume_mount_point_query(tmp_path, allowed, monkeypatch):
    drive = tmp_path.drive
    checked = []
    original = WindowsGuardExecution.check_access

    async def decide_root(execution, pid, path, action):
        if path == "\\??\\" + drive + "\\":
            checked.append(action)
            return allowed
        return await original(execution, pid, path, action)

    monkeypatch.setattr(WindowsGuardExecution, "check_access", decide_root)
    code, output, cards = await run_client(
        tmp_path, policy(tmp_path), [drive + "\\", "unused", "volume"]
    )
    assert checked and set(checked) == {1}
    assert code == (0 if allowed else 44) and not cards, output
    assert (b"VOLUME=1" if allowed else b"VOLUME=0 ERROR=5") in output[0]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "device",
    [
        None,
        r"GLOBALROOT\Device\WebDavRedirector\guard-test",
        r"GLOBALROOT\Device\WinDfs\guard-test",
        r"GLOBALROOT\Device\NamedPipeSuffix\guard-test",
    ],
)
async def test_non_file_device_cannot_open_as_filesystem(tmp_path, device, monkeypatch):
    observed = []
    original = WindowsGuardExecution.check_access

    async def observe(execution, pid, path, action):
        observed.append(path)
        return await original(execution, pid, path, action)

    monkeypatch.setattr(WindowsGuardExecution, "check_access", observe)
    name = device or tmp_path.drive
    code, output, cards = await run_client(
        tmp_path, policy(tmp_path), [nt_path("\\\\?\\", name), "unused", "volume_data"]
    )
    assert nt_path("\\??\\", name) in observed
    assert code == 45 and b"VOLUME_DATA_DENIED=5" in output[0] and not cards, output


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_named_pipe_keeps_os_behavior(tmp_path, enabled):
    import ctypes as ct
    import secrets
    from ctypes import wintypes as wt

    kernel = ct.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateNamedPipeW
    create.argtypes = [
        wt.LPCWSTR,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        wt.DWORD,
        ct.c_void_p,
    ]
    create.restype = wt.HANDLE
    close = kernel.CloseHandle
    close.argtypes = [wt.HANDLE]
    name = os.path.join("\\\\.\\pipe", "dll-policy-test-{}".format(secrets.token_hex(16)))
    handle = create(name, 3 | 0x40000000, 0, 1, 512, 512, 1000, None)
    assert handle not in (None, ct.c_void_p(-1).value)
    try:
        engine = policy(tmp_path)
        engine.update_config({**engine.config, "enabled": enabled})
        code, output, cards = await run_client(tmp_path, engine, [name, "unused", "pipe"])
        assert code == 0 and b"PIPE_OK" in output[0] and not cards, output
    finally:
        close(handle)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rule,allowed",
    [
        ({"action": "allow"}, True),
        ({"fetch": "allow"}, True),
        ("ALLOW", True),
        ({"action": "deny"}, False),
    ],
)
async def test_real_endpoint_uses_netguard_action_formats(tmp_path, rule, allowed):
    received = []

    async def handle(reader, writer):
        received.append(await reader.read(32))
        writer.close()
        await writer.wait_closed()

    async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        engine = policy(
            tmp_path, net={"enabled": True, "defaults": "deny", "urls": {"127.0.0.1": rule}}
        )
        code, output, cards = await run_client(tmp_path, engine, ["127.0.0.1", port, "tcp"])
        await asyncio.sleep(0.05)
        assert (code == 0) is allowed and not cards, output
        assert received == ([b"HELLO"] if allowed else [])


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["allow", "deny"])
@pytest.mark.parametrize("lowercase", [False, True])
@pytest.mark.parametrize("namespace", ["Global", "GLOBALROOT"])
async def test_file_alias_uses_same_fileguard(tmp_path, decision, lowercase, namespace):
    import ctypes as ct
    from ctypes import wintypes as wt

    target = tmp_path / "data.txt"
    target.write_text("ALIAS_CONTENT")
    buffer = ct.create_unicode_buffer(32768)
    query = ct.WinDLL("kernel32").QueryDosDeviceW
    query.argtypes, query.restype = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD], wt.DWORD
    assert query(tmp_path.drive, buffer, len(buffer))
    tail = str(target)[len(target.drive):].lstrip("\\")
    if namespace == "Global":
        alias = nt_path("\\\\?\\Global\\", str(target))
    else:
        alias = os.path.join("\\\\?\\GLOBALROOT", buffer.value.lstrip("\\"), tail)
    if lowercase:
        alias = alias.lower()
    engine = policy(tmp_path, paths=[{"path": str(target), "read": decision}])
    code, output, cards = await run_client(tmp_path, engine, [alias, tmp_path / "marker.txt", "0"])
    assert (code == 0) is (decision == "allow") and not cards, output
    assert (b"ALIAS_CONTENT" in output[0]) is (decision == "allow")


@pytest.mark.asyncio
@pytest.mark.parametrize("restricted", [None, "read", "write", "exec"])
async def test_maximum_allowed_checks_all_file_rights(tmp_path, restricted):
    target = tmp_path / "data.txt"
    target.touch()
    paths = [{"path": str(target), restricted: "deny"}] if restricted else []
    code, output, cards = await run_client(
        tmp_path, policy(tmp_path, paths=paths), [target, "0x02000000", "dir"]
    )
    assert not cards
    if restricted:
        assert code == 47 and b"DIR_ERROR=5" in output[0], output
    else:
        assert code == 0 and b"DIR_OK" in output[0], output


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["rename", "delete", "truncate"])
@pytest.mark.parametrize("decision", ["allow", "deny"])
async def test_file_mutation_side_effects(tmp_path, operation, decision):
    source, target = tmp_path / "source.txt", tmp_path / "target.txt"
    source.write_text("SOURCE")
    target.write_text("TARGET")
    restricted = target if operation == "rename" else source
    engine = policy(
        tmp_path,
        paths=[{"path": str(restricted), "read": "allow", "write": decision, "exec": "allow"}],
    )
    code, output, _cards = await run_client(tmp_path, engine, [source, target, operation])
    assert (code == 0) is (decision == "allow"), output
    if decision == "deny":
        assert source.read_text() == "SOURCE"
        assert target.read_text() == "TARGET"
    elif operation == "rename":
        assert not source.exists() and target.read_text() == "SOURCE"
    elif operation == "delete":
        assert not source.exists()
    else:
        assert source.read_bytes() == b""


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("method", ["tcp", "connectex"])
async def test_raw_tcp_actual_traffic(tmp_path, approved, host, method):
    received = []

    async def handle(reader, writer):
        received.append(await reader.read(32))
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, host, 0)
    port = server.sockets[0].getsockname()[1]
    async with server:
        code, output, cards = await run_client(
            tmp_path,
            policy(tmp_path, net={"enabled": True, "defaults": "ask"}),
            [host, port, method],
            approved=approved,
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is approved, output
    assert received == ([b"HELLO"] if approved else [])
    assert len(cards) == 1
    assert cards[0]["resource"]["kind"] == "endpoint"


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("api", ["udp", "sendmsg"])
async def test_raw_udp_actual_traffic(tmp_path, approved, host, api):
    received = []

    class Receiver(asyncio.DatagramProtocol):
        def datagram_received(self, data, _addr):
            received.append(data)

    transport, _protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        Receiver, local_addr=(host, 0)
    )
    try:
        port = transport.get_extra_info("sockname")[1]
        code, output, cards = await run_client(
            tmp_path,
            policy(tmp_path, net={"enabled": True, "defaults": "ask"}),
            [host, port, api],
            approved=approved,
        )
        await asyncio.sleep(0.05)
        assert (code == 0) is approved, output
        assert received == ([b"HELLO"] if approved else [])
        assert len(cards) == 1 and cards[0]["resource"]["protocol"] == "udp"
    finally:
        transport.close()
        await asyncio.sleep(0)


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", [False, True])
@pytest.mark.parametrize("callback", ["none", "callback", "callback_clear", "async"])
async def test_winhttp_redirect_target_checked_before_traffic(tmp_path, denied, callback):
    received = []

    async def handle(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        path = data.split(b" ")[1].decode()
        received.append(path)
        if path == "/start":
            response = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: http://127.0.0.1:{port}/final\r\n"
                "Content-Length: 0\r\nConnection: close\r\n\r\n"
            ).encode()
        else:
            response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        writer.write(response)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    net = {
        "enabled": True,
        "defaults": "allow",
        "urls": {f"http://127.0.0.1:{port}/final": "deny" if denied else "ask"},
    }
    async with server:
        code, output, cards = await run_client(
            tmp_path, policy(tmp_path, net=net), ["127.0.0.1", port, "http", "/start", callback]
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is not denied, (output, received, cards)
    assert received == (["/start"] if denied else ["/start", "/final"])
    assert len(cards) == (0 if denied else 1)
    assert f"CALLBACKS={1 if callback in {'callback', 'async'} else 0}".encode() in output[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
@pytest.mark.parametrize("approved", [True, False])
async def test_async_winhttp_uses_existing_policy(tmp_path, decision, approved):
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        engine = policy(
            tmp_path, net={"enabled": True, "defaults": "allow", "urls": {url: decision}}
        )
        code, output, cards = await run_client(
            tmp_path, engine, ["127.0.0.1", port, "http", "/", "async"], approved=approved
        )
        allowed = decision == "allow" or decision == "ask" and approved
        assert (code == 0) is allowed, output
        assert len(received) == int(allowed)
        assert len(cards) == int(decision == "ask")


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["none", "async"])
async def test_winhttp_url_allow_is_not_anonymous_endpoint_deny(tmp_path, mode):
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async with await asyncio.start_server(handle, "127.0.0.1", 0) as server:
        port = server.sockets[0].getsockname()[1]
        url = f"http://127.0.0.1:{port}/"
        engine = policy(tmp_path, net={"enabled": True, "defaults": "deny", "urls": {url: "allow"}})
        code, output, cards = await run_client(
            tmp_path, engine, ["127.0.0.1", port, "http", "/", mode]
        )
        assert code == 0 and len(received) == 1 and not cards, (output, cards)
        # A separate connection, even to the same IP, still uses NetGuard's default.
        code, output, cards = await run_client(tmp_path, engine, ["127.0.0.1", port, "tcp"])
        assert code == 12 and len(received) == 1 and not cards, (output, cards)


@pytest.mark.asyncio
async def test_winhttp_callback_socket_keeps_independent_policy(tmp_path):
    accepted = []

    async def http(reader, writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async def raw(_reader, writer):
        accepted.append(True)
        writer.close()
        await writer.wait_closed()

    async with (
        await asyncio.start_server(http, "127.0.0.1", 0) as http_server,
        await asyncio.start_server(raw, "127.0.0.1", 0) as raw_server,
    ):
        port = http_server.sockets[0].getsockname()[1]
        raw_port = raw_server.sockets[0].getsockname()[1]
        engine = policy(
            tmp_path,
            net={
                "enabled": True,
                "defaults": "deny",
                "urls": {f"http://127.0.0.1:{port}/": "allow"},
            },
        )
        code, output, cards = await run_client(
            tmp_path, engine, ["127.0.0.1", port, "http", "/", "async", raw_port]
        )
        await asyncio.sleep(0.05)
        assert code == 0 and not accepted and not cards, (output, accepted, cards)
        assert b"SOCKET=0 SOCKET_ERROR=10013" in output[0], output


@pytest.mark.asyncio
@pytest.mark.parametrize("approved", [True, False])
async def test_https_visible_url_and_actual_tls_traffic(tmp_path, approved):
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    certfile, keyfile = tmp_path / "cert.pem", tmp_path / "key.pem"
    certfile.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    keyfile.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(certfile, keyfile)
    received = []

    async def handle(reader, writer):
        received.append(await reader.readuntil(b"\r\n\r\n"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    async with await asyncio.start_server(handle, "127.0.0.1", 0, ssl=tls) as server:
        port = server.sockets[0].getsockname()[1]
        url = f"https://127.0.0.1:{port}/private"
        net = {"enabled": True, "defaults": "allow", "urls": {url: "ask"}}
        code, output, cards = await run_client(
            tmp_path,
            policy(tmp_path, net=net),
            ["127.0.0.1", port, "http", "/private", "https"],
            approved=approved,
        )
        assert (code == 0) is approved, output
        assert len(received) == (1 if approved else 0)
        assert len(cards) == 1 and cards[0]["resource"]["url"] == url
