"""Actual Windows resolver APIs and applications use the existing NetGuard."""

import asyncio
import os
import socket
import sys
from pathlib import Path

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.tests.intercepts.dll_guard.test_dll_guard_resources import (
    CLIENT,
    DLL,
    policy,
    run_client,
)
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not DLL.is_file(), reason="Windows DLL required"
)

RESOLVERS = [
    "gai_a",
    "gai_w",
    "gai_exa",
    "gai_exw",
    "gai_async",
    "hostbyname",
    "lookup_a",
    "lookup_w",
    "lookup_a_all",
    "lookup_w_all",
    "dns_a",
    "dns_w",
    "dns_utf8",
    "dns_ex",
    "dns_async",
]


@pytest.mark.asyncio
@pytest.mark.parametrize("api", RESOLVERS)
@pytest.mark.parametrize("decision", ["allow", "deny", "approve", "reject"])
async def test_actual_resolvers_domain_policy_and_live_approval(
    tmp_path, monkeypatch, api, decision
):
    action = "ask" if decision in {"approve", "reject"} else decision
    engine = policy(
        tmp_path, net={"enabled": True, "defaults": "deny", "urls": {"localhost": action}}
    )
    checked = []
    original = WindowsGuardExecution.check_resource

    async def trace(execution, pid, subject, **kwargs):
        result = await original(execution, pid, subject, **kwargs)
        if subject["kind"] != "file" or not result:
            checked.append((subject, result))
        return result

    monkeypatch.setattr(WindowsGuardExecution, "check_resource", trace)
    code, output, cards = await run_client(
        tmp_path, engine, ["localhost", api, "resolve"], approved=decision == "approve"
    )
    allowed = decision in {"allow", "approve"}
    assert (code == 0) is allowed, (output, cards, checked)
    assert (b"FOUND=1" in output[0]) is allowed, output
    lines = output[0].splitlines()
    assert output[0].count(b"RESOLVE_START") == 1
    assert lines[0].split(b"PID=")[1] == lines[-1].split(b"PID=")[1]
    assert len(cards) == (1 if action == "ask" else 0), cards
    if cards:
        assert cards[0]["resource"]["kind"] == "domain"
        assert cards[0]["resource"]["hostname"] == "localhost"
    if not allowed:
        if api.startswith("lookup_"):
            assert b"RESOLVE_ERROR=10013 FOUND=0" in output[0]
        assert (
            b"CALLBACKS=0" in output[0]
        )  # Synchronous admission failure never queues async completion.


@pytest.mark.asyncio
@pytest.mark.parametrize("address", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("action", ["allow", "deny", "ask"])
async def test_reverse_lookup_uses_address_as_dns_identity(tmp_path, monkeypatch, address, action):
    checked = []
    original = WindowsGuardExecution.check_resource

    async def trace(execution, pid, subject, **kwargs):
        result = await original(execution, pid, subject, **kwargs)
        if subject["kind"] != "file" or not result:
            checked.append((subject, result))
        return result

    monkeypatch.setattr(WindowsGuardExecution, "check_resource", trace)
    # The resolver may also issue a DNS request for the derived PTR name.
    engine = policy(tmp_path, net={"enabled": True, "defaults": "allow", "urls": {address: action}})
    code, output, cards = await run_client(tmp_path, engine, [address, "hostbyaddr", "resolve"])
    if action == "deny":
        assert code != 0 and b"RESOLVE_ERROR=10013 FOUND=0" in output[0], output
    else:
        # A loopback address need not have a PTR record on this machine.
        baseline = await asyncio.create_subprocess_exec(
            CLIENT, address, "hostbyaddr", "resolve", stdout=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(baseline.communicate(), 10)
        expected = stdout.splitlines()[-1].split(b" PID=")[0]
        assert expected.startswith(b"RESOLVE_ERROR=") and b"RESOLVE_ERROR=10013 " not in expected
        assert code == baseline.returncode and expected in output[0], (output, checked)
    assert ({"kind": "domain", "hostname": address}, action != "deny") in checked
    assert {card["resource"]["hostname"] for card in cards} == (
        {address} if action == "ask" else set()
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["gai_a", "gai_w", "gai_exa", "gai_exw", "gai_async"])
async def test_numeric_resolution_does_not_request_domain_approval(tmp_path, api):
    engine = policy(tmp_path, net={"enabled": True, "defaults": "deny"})
    code, output, cards = await run_client(tmp_path, engine, ["127.0.0.1", api, "resolve"])
    assert code == 0 and b"FOUND=1" in output[0] and not cards, (output, cards)


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["dns_a", "dns_w", "dns_utf8", "dns_ex", "dns_async"])
async def test_explicit_dns_queries_are_checked_even_for_numeric_names(tmp_path, api):
    engine = policy(tmp_path, net={"enabled": True, "defaults": "deny"})
    code, output, cards = await run_client(tmp_path, engine, ["127.0.0.1", api, "resolve"])
    assert code != 0 and b"FOUND=0" in output[0] and not cards, (output, cards)


@pytest.mark.asyncio
@pytest.mark.parametrize("application", ["curl", "python", "powershell"])
@pytest.mark.parametrize("denied", [True, False])
async def test_domain_rule_controls_real_app_http_traffic(tmp_path, application, denied):
    """No curl argument inspection: the policy sees the domain reported by the DLL."""
    received, subjects, denials, invalid_paths = [], [], [], []

    async def receive(reader, writer):
        try:
            received.append(await reader.read(4096))
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nDOMAIN")
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    # curl resolves localhost internally without any OS domain API. The local
    # machine name exercises the system resolver and needs no external DNS.
    hostname = socket.gethostname().lower()
    server = await asyncio.start_server(receive, "0.0.0.0", 0)
    url = f"http://{hostname}:{server.sockets[0].getsockname()[1]}/data"
    engine = policy(
        tmp_path,
        net={
            "enabled": True,
            "defaults": "allow",
            "urls": {hostname: "deny" if denied else "allow"},
        },
    )
    if application == "curl":
        # The target comes from a config file; there is no URL in argv.
        config = tmp_path / "curl.conf"
        config.write_text(f'url = "{url}"\nsilent\nshow-error\nmax-time = 5\nnoproxy = "*"\n')
        args = [str(Path(os.environ["SYSTEMROOT"]) / "System32/curl.exe"), "--config", str(config)]
    elif application == "python":
        args = [
            sys.executable,
            "-c",
            (
                "import urllib.request; "
                "opener = urllib.request.build_opener(urllib.request.ProxyHandler({})); "
                f"print(opener.open({url!r}, timeout=5).read().decode())"
            ),
        ]
    else:
        args = [
            str(Path(os.environ["SYSTEMROOT"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"),
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$ErrorActionPreference='Stop'; $c=New-Object Net.WebClient; $c.Proxy=$null; $c.DownloadString('{url}')",
        ]
    try:
        async with WindowsGuardExecution(
            session_id="s",
            tool_call_id="c",
            dll=DLL,
            approvals=RuntimeApprovalRequests(),
            engine=lambda: engine,
            emit=lambda _: None,
            root_command_approved=True,
        ) as execution:
            original = execution.check_resource

            async def trace(pid, subject, **kwargs):
                subjects.append(subject)
                result = await original(pid, subject, **kwargs)
                if not result:
                    denials.append(subject)
                return result

            execution.check_resource = trace
            file_path = execution.file_path

            def trace_path(raw):
                try:
                    return file_path(raw)
                except ValueError:
                    invalid_paths.append(raw)
                    raise

            execution.file_path = trace_path
            process = await execution.launch(
                asyncio.create_subprocess_exec,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            output = await asyncio.wait_for(process.communicate(), 15)
        error = output[1].decode(
            "utf-16-le" if output[1].count(b"\0") > len(output[1]) // 5 else "utf-8",
            errors="replace",
        )
        details = {
            "code": process.returncode,
            "error": error,
            "denials": denials,
            "invalid_paths": invalid_paths,
            "domains": [item for item in subjects if item["kind"] == "domain"],
        }
        assert bool(received) is (not denied), details
        assert (b"DOMAIN" in output[0]) is (not denied), details
        assert any(item == {"kind": "domain", "hostname": hostname} for item in subjects), details
    finally:
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_domain_allow_does_not_allow_resulting_ip_endpoint(tmp_path):
    engine = policy(
        tmp_path, net={"enabled": True, "defaults": "deny", "urls": {"localhost": "allow"}}
    )
    registry = RuntimeApprovalRequests()
    subjects = []
    received = []

    def connected(_reader, writer):
        received.append(True)
        writer.close()

    server = await asyncio.start_server(connected, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        engine=lambda: engine,
        emit=lambda _: None,
        approvals=registry,
        root_command_approved=True,
    ) as execution:
        original = execution.check_resource

        async def trace(pid, subject, **kwargs):
            result = await original(pid, subject, **kwargs)
            subjects.append((subject, result))
            return result

        execution.check_resource = trace
        try:
            code = f"import socket; s=socket.create_connection(('localhost',{port}),timeout=2)"
            process = await execution.launch(
                asyncio.create_subprocess_exec,
                sys.executable,
                "-c",
                code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            output = await asyncio.wait_for(process.communicate(), 10)
            assert process.returncode != 0 and not received, output
        finally:
            server.close()
            await server.wait_closed()
    assert any(item[0].get("kind") == "domain" and item[1] for item in subjects)
    assert any(item[0].get("kind") == "endpoint" and not item[1] for item in subjects)


@pytest.mark.asyncio
async def test_curl_config_taobao_deny_is_reported_by_native_resolver(tmp_path):
    config = tmp_path / "curl.conf"
    config.write_text(
        'url = "https://www.taobao.com"\nsilent\nshow-error\nnoproxy = "*"\nmax-time = 5\n'
    )
    engine = policy(
        tmp_path, net={"enabled": True, "defaults": "allow", "urls": {"www.taobao.com": "deny"}}
    )
    subjects = []
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=lambda _: None,
        root_command_approved=True,
    ) as execution:
        original = execution.check_resource

        async def trace(pid, subject, **kwargs):
            result = await original(pid, subject, **kwargs)
            if subject["kind"] in {"domain", "endpoint"}:
                subjects.append((subject, result))
            return result

        execution.check_resource = trace
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(Path(os.environ["SYSTEMROOT"]) / "System32/curl.exe"),
            "--config",
            str(config),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 10)
    assert process.returncode != 0 and b"200 OK" not in output[0], output
    assert subjects and all(item[0]["kind"] == "domain" and not item[1] for item in subjects), (
        subjects
    )
    assert subjects[0][0]["hostname"] == "www.taobao.com"


@pytest.mark.asyncio
@pytest.mark.parametrize("finish", ["revoke", "timeout", "cancel"])
async def test_live_domain_wait_revoke_timeout_and_cancel(tmp_path, finish):
    engine = policy(
        tmp_path, net={"enabled": True, "defaults": "allow", "urls": {"localhost": "ask"}}
    )
    registry, seen = RuntimeApprovalRequests(), asyncio.Event()

    async def emit(event):
        seen.set()
        if finish == "revoke":
            engine.update_config(
                {**engine.config, "net_guard": {"enabled": True, "defaults": "deny"}}
            )
            registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=True))

    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
        approval_timeout=0.2,
        root_command_approved=True,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            str(CLIENT),
            "localhost",
            "gai_async",
            "resolve",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        await asyncio.wait_for(seen.wait(), 5)
        if finish == "cancel":
            await execution.close()
        output = await asyncio.wait_for(process.communicate(), 5)
        assert process.returncode is not None and b"FOUND=1" not in output[0], output
        if finish != "cancel":
            assert process.returncode != 0, output
        else:
            assert b"RESOLVE_ERROR=" not in output[0]  # Killed while the original call was waiting.
    assert not registry._pending  # pylint: disable=protected-access


@pytest.mark.asyncio
@pytest.mark.parametrize("api", ["gai_w", "dns_utf8"])
async def test_native_idna_domain_uses_canonical_netguard_rule(tmp_path, api):
    engine = policy(
        tmp_path,
        net={"enabled": True, "defaults": "allow", "urls": {"xn--fsqu00a.xn--0zwm56d": "deny"}},
    )
    code, output, cards = await run_client(tmp_path, engine, ["例子.测试", api, "resolve"])
    assert code != 0 and b"FOUND=0" in output[0] and not cards, (output, cards)


@pytest.mark.asyncio
async def test_descendant_process_cannot_resolve_denied_domain(tmp_path):
    engine = policy(
        tmp_path, net={"enabled": True, "defaults": "allow", "urls": {"localhost": "deny"}}
    )
    code = f"import subprocess; raise SystemExit(subprocess.call([{str(CLIENT)!r},'localhost','gai_w','resolve']))"
    async with WindowsGuardExecution(
        session_id="s",
        tool_call_id="c",
        dll=DLL,
        approvals=RuntimeApprovalRequests(),
        engine=lambda: engine,
        emit=lambda _: None,
        root_command_approved=True,
    ) as execution:
        process = await execution.launch(
            asyncio.create_subprocess_exec,
            sys.executable,
            "-c",
            code,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        output = await asyncio.wait_for(process.communicate(), 10)
        assert process.returncode != 0 and b"FOUND=0" in output[0], output
