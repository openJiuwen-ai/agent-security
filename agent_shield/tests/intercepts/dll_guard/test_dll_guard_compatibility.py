"""Real directory operations, CA loading and HTTP proxy targets with package rules."""

import asyncio
import datetime
import os
import ssl
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tool_permission.runtime.engine import PermissionEngine

ROOT = Path(__file__).resolve().parents[4]

DLL = guard_binary_directory() / "jiuwen_runtime_guard.dll"

CLIENT = ROOT / "agent_shield/native/windows-dll-guard/build/client.exe"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file() or not CLIENT.is_file(),
    reason="Build Windows Guard/client first",
)


def engine_for(root, *, paths=None, urls=None, protected=()):
    return PermissionEngine(
        {
            "enabled": True,
            "tools": {"bash": "allow", "powershell": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": paths or [],
            },
            "net_guard": {"enabled": True, "defaults": "allow", "urls": urls or {}},
        },
        workspace_root=root,
        immutable_control_roots=list(protected),
    )


async def execute(root, engine, args, *, guarded=True, env=None):
    checked = []

    async def run(launch):
        process = await launch(
            asyncio.create_subprocess_exec,
            *map(str, args),
            cwd=str(root),
            env=env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 15)
        return process.returncode, output, checked

    if not guarded:

        async def plain(factory, *args, **kwargs):
            return await factory(*args, **kwargs)

        return await run(plain)

    async def unexpected(card):
        raise AssertionError(card)

    async with WindowsGuardExecution(
        session_id="compat",
        tool_call_id="call",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=unexpected,
        root_command_approved=True,
        source_tool="bash",
    ) as guard:
        original = guard.check_resource

        async def trace(pid, subject, **kwargs):
            allowed = await original(pid, subject, **kwargs)
            checked.append((subject, allowed))
            return allowed

        guard.check_resource = trace
        return await run(guard.launch)


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["chdir", "listdir", "stat"])
async def test_directory_read_operations_match_without_dll(tmp_path, operation):
    protected = tmp_path / "skills"
    protected.mkdir()
    (protected / "example.py").write_text("# public skill\n")
    engine = engine_for(tmp_path, protected=[protected])
    script = f"import os; print(os.{operation}({str(protected)!r})); print('DIRECTORY_OK')"
    for guarded in (False, True):
        code, output, checked = await execute(
            tmp_path, engine, [sys.executable, "-c", script], guarded=guarded
        )
        assert code == 0 and b"DIRECTORY_OK" in output[0], (output, checked)
        assert all(allowed for _, allowed in checked), checked


@pytest.mark.asyncio
@pytest.mark.parametrize("mask", [0x20, 0x20000000, 0x120000])
async def test_native_directory_traverse_and_metadata_are_reads(tmp_path, mask):
    protected = tmp_path / "skills"
    protected.mkdir()
    engine = engine_for(tmp_path, protected=[protected])
    code, output, checked = await execute(tmp_path, engine, [CLIENT, protected, str(mask), "dir"])
    assert code == 0 and b"DIR_OK" in output[0], (output, checked)
    accesses = []
    for subject, _allowed in checked:
        if subject["kind"] != "file":
            continue
        for pair in subject["accesses"]:
            if Path(pair[0]) == protected:
                accesses.append(pair)
    assert accesses and all(pair[1] == "read" for pair in accesses), accesses


@pytest.mark.asyncio
async def test_git_bash_cd_into_skill_directory(tmp_path):
    candidates = [
        Path(os.environ.get("GIT_BASH", "missing")),
        Path(os.environ.get("GIT_BASH_PATH", "missing")),
        Path(os.environ.get("ProgramFiles", ".")) / "Git/bin/bash.exe",
    ]
    bash = next((path for path in candidates if path.is_file()), None)
    if not bash:
        pytest.skip("Git Bash not installed")
    protected = tmp_path / "skills"
    protected.mkdir()
    command = f'cd "{protected.as_posix()}" && pwd'
    code, output, checked = await execute(
        tmp_path,
        engine_for(tmp_path, protected=[protected]),
        [bash, "--noprofile", "--norc", "-c", command],
    )
    assert code == 0 and b"skills" in output[0], (output, checked)


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["read_deny", "delete_child", "create", "file_exec"])
async def test_directory_fix_retains_actual_denies(tmp_path, case):
    protected = tmp_path / "skills"
    protected.mkdir()
    file = protected / "example.py"
    file.write_text("# public skill\n")
    paths = [{"path": str(protected), "read": "deny"}] if case == "read_deny" else []
    engine = engine_for(tmp_path, paths=paths, protected=[protected])
    if case == "create":
        args = [sys.executable, "-c", f"import os; os.mkdir({str(protected / 'new')!r})"]
    else:
        mask = 0x40 if case == "delete_child" else 0x20
        args = [CLIENT, file if case == "file_exec" else protected, str(mask), "dir"]
    code, output, checked = await execute(tmp_path, engine, args)
    assert code != 0 and any(not allowed for _, allowed in checked), (output, checked)
    assert not (protected / "new").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", [False, True])
async def test_certifi_bundle_real_read_and_ssl_load(tmp_path, denied):
    import certifi

    ca = Path(certifi.where()).resolve()
    paths = [{"path": str(ca), "read": "deny"}] if denied else []
    script = (
        "import certifi,ssl; p=certifi.where(); print(len(open(p,'rb').read()),flush=True); "
        "ssl.create_default_context(cafile=p); print('CA_OK')"
    )
    code, output, checked = await execute(
        tmp_path, engine_for(tmp_path, paths=paths), [sys.executable, "-c", script]
    )
    assert (code == 0) is (not denied), (output, checked)
    assert (b"CA_OK" in output[0]) is (not denied)


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["private.pem", "server-key.pem", ".ssh/certificate.pem"])
async def test_private_pem_read_stays_denied(tmp_path, name):
    key = tmp_path / name
    key.parent.mkdir(parents=True, exist_ok=True)
    key.write_text("test credential placeholder")
    code, output, checked = await execute(
        tmp_path, engine_for(tmp_path), [sys.executable, "-c", f"print(open({str(key)!r}).read())"]
    )
    assert code != 0 and any(not allowed for _, allowed in checked), (output, checked)
    assert b"test credential placeholder" not in output[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "::1"])
@pytest.mark.parametrize("denied", [False, True])
async def test_loopback_default_and_explicit_deny_real_process(tmp_path, host, denied):
    received = []

    async def handle(reader, writer):
        received.append(await reader.read(16))
        writer.close()
        await writer.wait_closed()

    bind = "::1" if host == "::1" else "127.0.0.1"
    async with await asyncio.start_server(handle, bind, 0) as server:
        port = server.sockets[0].getsockname()[1]
        script = f"import socket; s=socket.create_connection(({host!r},{port}),2); s.sendall(b'HELLO'); s.close()"
        # Test runtime network enforcement independently of command rules.
        # The package correctly denies inline python -c socket code once the
        # executable's .exe suffix/path can no longer hide its command name.
        probe = tmp_path / "loopback_probe.py"
        probe.write_text(script, encoding="utf-8")
        code, output, checked = await execute(
            tmp_path,
            engine_for(tmp_path, urls={host: "deny"} if denied else {}),
            [sys.executable, str(probe)],
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is (not denied), (output, checked)
    assert received == ([] if denied else [b"HELLO"]), received


@pytest.fixture
def tls_bundle(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "proxy-test")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("allowed.test"), x509.DNSName("denied.test")]
            ),
            False,
        )
        .sign(key, hashes.SHA256())
    )
    ca = tmp_path / "certifi/cacert.pem"
    ca.parent.mkdir()
    ca.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private = tmp_path / "server-key.pem"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(ca, private)
    return ca, tls


@asynccontextmanager
async def http_proxy(tls=None):
    targets, requests = [], []
    writers = set()

    async def handle(reader, writer):
        writers.add(writer)
        try:
            header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            targets.append(header.split(b"\r\n", 1)[0])
            if header.startswith(b"CONNECT ") and tls:
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                await writer.start_tls(tls, ssl_handshake_timeout=3)
                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 5)
            requests.append(header)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            await writer.drain()
        except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), 2)
            except (ConnectionError, ssl.SSLError, TimeoutError):
                pass
            finally:
                writer.transport.abort()
                writers.discard(writer)

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    try:
        yield server.sockets[0].getsockname()[1], targets, requests
    finally:
        server.close()
        for writer in tuple(writers):
            writer.transport.abort()
        await asyncio.wait_for(server.wait_closed(), 5)


@pytest.mark.asyncio
@pytest.mark.parametrize("scheme", ["http", "https"])
@pytest.mark.parametrize("denied", [False, True])
async def test_requests_proxy_remote_domain_deny(tmp_path, tls_bundle, scheme, denied):
    ca, tls = tls_bundle
    host = "denied.test" if denied else "allowed.test"
    engine = engine_for(tmp_path, urls={"denied.test": "deny"})
    async with http_proxy(tls) as (port, targets, requests):
        dropped = {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "no_proxy",
            "requests_ca_bundle",
            "curl_ca_bundle",
        }
        env = {}
        for key, value in os.environ.items():
            if key.lower() not in dropped:
                env[key] = value
        env.update(
            HTTP_PROXY=f"http://127.0.0.1:{port}",
            HTTPS_PROXY=f"http://127.0.0.1:{port}",
            NO_PROXY="",
        )
        script = (
            "import requests; "
            "response = requests.get("
            f"'{scheme}://{host}/file', verify={str(ca)!r}, timeout=3); "
            "print(response.status_code, response.text)"
        )
        code, output, checked = await execute(
            tmp_path, engine, [sys.executable, "-c", script], env=env
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is (not denied), (output, checked, targets)
    assert bool(targets) is (not denied) and bool(requests) is (not denied), (targets, requests)
    assert any(
        subject["kind"] == "url" and host in subject["url"] and allowed is (not denied)
        for subject, allowed in checked
    ), checked


@pytest.mark.asyncio
async def test_proxy_https_retains_certificate_verification(tmp_path, tls_bundle):
    _, tls = tls_bundle
    async with http_proxy(tls) as (port, targets, requests):
        script = (
            f"import requests; requests.get('https://allowed.test/file',"
            f"proxies={{'https':'http://127.0.0.1:{port}'}},timeout=3)"
        )
        code, output, checked = await execute(
            tmp_path, engine_for(tmp_path), [sys.executable, "-c", script]
        )
        assert code != 0 and b"CERTIFICATE_VERIFY_FAILED" in output[1], (output, checked)
        assert targets and not requests


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["vector", "fragmented", "sendmsg"])
@pytest.mark.parametrize("denied", [False, True])
async def test_native_proxy_split_and_scatter_gather_target(tmp_path, api, denied):
    host = "denied.test" if denied else "allowed.test"
    async with http_proxy() as (port, targets, _):
        args = [CLIENT, "127.0.0.1", str(port), "proxy", host, api]
        engine = engine_for(tmp_path, urls={"denied.test": "deny"})
        if api == "sendmsg" and not denied:
            # Some Winsock providers reject WSASendMsg on a connected TCP socket.
            native_code, native_output, _ = await execute(tmp_path, engine, args, guarded=False)
            await asyncio.sleep(0.05)
            native_targets = targets.copy()
            targets.clear()
        code, output, checked = await execute(tmp_path, engine, args)
        await asyncio.sleep(0.05)
    if api == "sendmsg":
        assert ({"kind": "url", "url": f"https://{host}:443/"}, not denied) in checked
        if not denied:
            assert code == native_code and targets == native_targets, (output, native_output)
            if code:
                assert output[0] == native_output[0]
            return
        assert code == 49 and b"ERROR=10013" in output[0], output
    assert (code == 0) is (not denied), (output, checked)
    assert bool(targets) is (not denied), targets


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", [False, True])
async def test_winhttp_proxy_retains_explicit_loopback_deny(tmp_path, denied):
    async with http_proxy() as (port, targets, _):
        engine = engine_for(tmp_path, urls={"127.0.0.1": "deny"} if denied else {})
        code, output, checked = await execute(
            tmp_path,
            engine,
            [CLIENT, "allowed.test", "80", "http", "/file", "named_proxy", f"127.0.0.1:{port}"],
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is (not denied), (output, checked)
    assert bool(targets) is (not denied), targets


@pytest.mark.asyncio
@pytest.mark.parametrize("denied", [False, True])
async def test_winhttp_url_permission_does_not_override_explicit_ip_deny(tmp_path, denied):
    async with http_proxy() as (port, targets, _):
        urls = {"127.0.0.1": "deny", "::1": "deny"} if denied else {}
        code, output, checked = await execute(
            tmp_path,
            engine_for(tmp_path, urls=urls),
            [CLIENT, "localhost", str(port), "http", "/file"],
        )
        await asyncio.sleep(0.05)
    assert (code == 0) is (not denied), (output, checked)
    assert bool(targets) is (not denied), targets
