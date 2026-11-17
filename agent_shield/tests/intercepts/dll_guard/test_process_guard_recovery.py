"""Verify the published SDK and the native JiuwenBox disposition in real processes."""

import asyncio
import os
import shutil
import sys
from pathlib import Path

import pytest

from agent_shield import ProcessGuard
from agent_shield.intercepts.native_call._binary_location import guard_binary_directory
from agent_shield.intercepts.native_call.dll_guard.errors import GuardError

_EVENT_FIELDS = (
    "kind", "path", "status", "phase", "operation_ids", "os_error", "disposition",
)


def _event_brief(event):
    return {key: event.get(key) for key in _EVENT_FIELDS if key in event}


pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or not (guard_binary_directory() / "x64/agent_security_guard.dll").is_file(),
    reason="Requires the native foundation build",
)


class Host:
    def __init__(self, root):
        self.root = root
        self.events = []

    def policy_snapshot(self):
        return {
            "revision": 1, "workspace_root": self.root,
            "config": {"enabled": True, "package_builtin_rules": False, "tools": {"bash": "allow"},
                       "file_guard": {"enabled": False}, "net_guard": {"enabled": False}},
        }

    async def confirm(self, request):
        return {"action": "allow_once"}

    @staticmethod
    def save_grant(grant):
        raise AssertionError("No persistent grant requested")

    def audit(self, event):
        self.events.append(event)


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
@pytest.mark.parametrize("operation", ["close-overwrite", "close-create"])
async def test_sdk_denied_close_delete_never_creates_or_truncates(tmp_path, bits, operation):
    class DenyingHost(Host):
        def policy_snapshot(self):
            snapshot = super().policy_snapshot()
            snapshot["config"]["soft_delete"] = {"batch_delete_threshold": 1}
            return snapshot

        async def confirm(self, request):
            return {"action": "deny"}

    host = DenyingHost(tmp_path)
    target, first = tmp_path / "target", tmp_path / "first"
    if operation == "close-overwrite":
        target.write_bytes(b"original")
    first.write_bytes(b"first")
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    async with ProcessGuard(session_id="denied-open", host=host) as guard:
        proc = await guard.spawn(
            [probe, operation, target, first],
            task_id="task", tool_call_id="call", tool_name="bash",
        )
        assert await proc.wait() == 5
    assert not first.exists()
    if operation == "close-overwrite":
        assert target.read_bytes() == b"original"
    else:
        assert not target.exists()
    results = [e for e in host.events if e.get("kind") == "result"]
    assert len(results) == 2 and [r["status"] for r in results] == ["success", "not_executed"], results
    assert all(r["pid"] == proc.pid and r.get("operation_ids") for r in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,box,expected,operation", [
    ("recover", False, True, "delete"), ("recover", True, False, "delete"), ("permanent", False, True, "delete"),
    ("recover", False, True, "close-delete"),
    ("recover", False, True, "close-protected"),
    ("recover", False, True, "disposition"),
    ("recover", True, False, "close-delete"), ("permanent", False, True, "close-delete"),
    ("recover", False, True, "rename-replace"), ("recover", False, False, "rename-invalid"),
    ("recover", False, True, "replace"), ("recover", False, True, "replace-backup"),
    ("permanent", False, True, "replace"),
    ("recover", True, False, "bash-rm"), ("recover", False, True, "bash-rm"),
    ("recover", True, False, "bash-fork"), ("recover", True, False, "bash-find"),
    ("recover", True, False, "bash-rmdir"), ("recover", False, True, "bash-rmdir"),
    ("recover", False, True, "bash-symlink"), ("recover", False, True, "bash-tree"),
    ("recover", False, True, "delete-save"), ("recover", False, True, "delete-save-fail"),
])
async def test_sdk_returns_actual_result_and_recovers_once(tmp_path, mode, box, expected, operation):
    host = Host(tmp_path)
    source = tmp_path / "target.txt"
    source.write_bytes(b"original")
    if operation.startswith("delete-save"):
        snapshot = host.policy_snapshot()
        snapshot["config"]["file_guard"] = {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{"path": str(source), "write": "ask"}],
        }

        def policy_snapshot():
            return snapshot

        async def confirm(_request):
            return {"action": "allow_permanent"}

        def save_grant(_grant):
            return operation != "delete-save-fail"

        host.policy_snapshot = policy_snapshot
        host.confirm = confirm
        host.save_grant = save_grant
    env = dict(os.environ)
    if box:
        env.update(JIUWENBOX_SOFT_DELETE="1", JIUWENBOX_SOFT_DELETE_RECYCLE_PORT="0")
    replacement = tmp_path / "replacement.txt"
    replacement.write_bytes(b"replacement")
    backup = tmp_path / "backup.txt"
    probe = guard_binary_directory() / "probe.exe"
    actual_operation = "replace" if operation == "replace-backup" else operation
    if operation.startswith("delete-save"):
        actual_operation = "delete"
    args = [str(probe), actual_operation, str(source)]
    if operation.startswith(("rename", "replace")):
        args = [str(probe), actual_operation, str(replacement), str(source)]
    if operation == "replace-backup":
        args.append(str(backup))
    is_bash = operation.startswith("bash-")
    if is_bash:
        env["JIUWENBOX_SOFT_DELETE_ARCHIVE"] = str(tmp_path / "archive")
        env["JIUWENBOX_SOFT_DELETE_TRACE"] = str(tmp_path / "trace.log")
        git = shutil.which("git.exe")
        bash = os.environ.get("GIT_BASH") or ""
        if not bash and git:
            bash = str(Path(git).resolve().parent.parent / "bin/bash.exe")
        if not bash or not Path(bash).is_file():
            pytest.skip("Git Bash executable not found")
        commands = {
            "bash-rm": 'rm -- "$1"',
            "bash-fork": '(rm -- "$1")',
            "bash-find": 'find "$1" -maxdepth 0 -exec rm -- {} +',
            "bash-tree": 'rm -rf -- "$1"',
            "bash-rmdir": 'rmdir -- "$1"',
            "bash-symlink": 'ln -s "$2" "$1"; rm -- "$1"',
        }
        if operation in {"bash-rmdir", "bash-symlink", "bash-tree"}:
            source.unlink()
        if operation in {"bash-rmdir", "bash-tree"}:
            source.mkdir()
        if operation == "bash-tree":
            (source / "nested").mkdir()
            (source / "nested" / "child.txt").write_bytes(b"child")
        command = commands.get(operation)
        if command is None:
            raise KeyError(operation)
        args = [
            bash, "--noprofile", "--norc", "-c", command, "bash",
            source.as_posix(), replacement.as_posix(),
        ]
    async with ProcessGuard(session_id="session", host=host, delete_mode=mode) as guard:
        process = await guard.spawn(args, task_id="task", tool_call_id="call", tool_name="bash", env=env,
                                    stdio={"stderr": asyncio.subprocess.PIPE})
        _, stderr = await asyncio.wait_for(process.communicate(), 15)
        detail = [_event_brief(event) for event in host.events]
        assert (process.returncode == 0) == expected, detail
    if operation.startswith(("rename", "replace")):
        phase = "replace" if operation.startswith("replace") else "rename"
        stages = []
        for event in host.events:
            kind_matches = event.get("kind") == "operation_result"
            if kind_matches and event.get("phase") == phase:
                stages.append(event)
        assert len(stages) == 1, host.events
        assert stages[0]["status"] == ("success" if expected else "failed")
        results = [e for e in host.events if e.get("kind") == "result" and e.get("path") == str(source)]
        assert len(results) == 1 and results[0]["status"] == "success"
        assert results[0]["operation_ids"] == stages[0]["operation_ids"]
        decision_ids = [
            event.get("operation_ids")
            for event in host.events
            if event.get("kind") == "policy_decision"
        ]
        assert results[0].get("operation_ids") in decision_ids
        if operation == "rename-invalid":
            assert not source.exists() and replacement.read_bytes() == b"replacement"
        else:
            assert source.read_bytes() == b"replacement" and not replacement.exists()
        if operation == "replace-backup":
            assert results[0]["disposition"] == "backup" and backup.read_bytes() == b"original"
        return
    assert source.exists() != expected
    if operation == "bash-symlink":
        assert replacement.read_bytes() == b"replacement"
    if source.exists() and source.is_file():
        assert source.read_bytes() == b"original"
    events = [e for e in host.events if e.get("kind") == "result" and e.get("path") == str(source)]
    assert len(events) == 1
    assert events[0]["status"] == ("success" if expected else "failed")
    assert events[0]["operation_ids"] in [e["operation_ids"] for e in host.events if e.get("kind") == "check"]
    if not is_bash:
        assert events[0]["pid"] == process.pid
    decision = None
    operation_ids = events[0].get("operation_ids")
    for event in host.events:
        kind_matches = event.get("kind") == "policy_decision"
        if kind_matches and event.get("operation_ids") == operation_ids:
            decision = event
            break
    if decision is None:
        raise AssertionError("missing policy decision")
    assert (events[0]["pid"], events[0]["process_instance_id"]) == (decision["pid"], decision["process_instance_id"])
    assert events[0]["process"]["pid"] == events[0]["pid"]
    if operation.startswith("delete-save"):
        saved = [e for e in host.events if e.get("kind") == "authorization_saved"]
        assert len(saved) == 1 and saved[0]["operation_ids"] == events[0]["operation_ids"]
        assert saved[0]["persisted"] is (operation != "delete-save-fail")
        assert saved[0]["pid"] == process.pid and saved[0]["process_instance_id"] == events[0]["process_instance_id"]
    if operation in {"close-delete", "disposition", "close-protected"}:
        stages = [e for e in host.events if e.get("kind") == "operation_result"]
        assert len(stages) == (2 if operation == "close-protected" else 1)
        assert all(e["phase"] == "handle_close" and e["operation_ids"] == events[0]["operation_ids"] for e in stages)
        assert stages[-1]["status"] == "success" and stages[-1]["os_error"] == 0
        if operation == "close-protected":
            assert stages[0]["status"] == "failed" and stages[0]["os_error"] != 0
    if mode == "permanent":
        assert events[0]["disposition"] == "permanent"


@pytest.mark.asyncio
async def test_explicit_permanent_conflicts_with_box_recovery(tmp_path):
    async with ProcessGuard(session_id="session", host=Host(tmp_path), delete_mode="permanent") as guard:
        with pytest.raises(GuardError, match="delete_mode_conflict"):
            await guard.spawn(["cmd.exe", "/c", "exit 83"], task_id="task", tool_call_id="call",
                              tool_name="bash", env={"JIUWENBOX_SOFT_DELETE": "1"})


@pytest.mark.asyncio
async def test_quick_exit_83_is_the_root_exit_code(tmp_path):
    async with ProcessGuard(session_id="session", host=Host(tmp_path)) as guard:
        proc = await guard.spawn(["cmd.exe", "/c", "exit 83"], task_id="task", tool_call_id="call",
                                 tool_name="bash")
        assert await proc.wait() == 83


@pytest.mark.asyncio
@pytest.mark.parametrize("deleter", ["python", "bash"])
async def test_jiuwenbox_and_shield_share_loaded_module_and_query_lost_receipt(tmp_path, monkeypatch, deleter):
    from jiuwenbox.supervisor import win_recycle_broker as recycle

    target = tmp_path / "one.txt"
    target.write_bytes(b"recover this once")
    host = Host(tmp_path)
    operations = []
    paths = []
    real_handle = recycle.RecycleBroker.handle_payload

    def record(broker, payload):
        operations.append((payload[0], payload[1:17]))
        parsed = recycle.parse_request(payload)
        paths.append(None if parsed is None else parsed[3])
        return real_handle(broker, payload)

    write = getattr(recycle, "_write_frame")

    def drop_first_ack(connection, result):
        if len(operations) != 1:
            write(connection, result)

    monkeypatch.setattr(recycle.RecycleBroker, "handle_payload", record)
    monkeypatch.setattr(recycle, "_write_frame", drop_first_ack)
    broker = recycle.RecycleBroker()
    port = broker.start()
    try:
        token = broker.register([str(tmp_path)])
        script = (
            "import ctypes,sys,os\n"
            "from jiuwenbox.supervisor.win_softdelete import "
            "install_win_soft_delete, uninstall_win_soft_delete, dll_path\n"
            "k=ctypes.WinDLL('kernel32',use_last_error=True)\n"
            "k.GetModuleHandleW.restype=ctypes.c_void_p\n"
            "h=k.GetModuleHandleW('agent_security_guard.dll')\n"
            "assert h\n"
            "install_win_soft_delete(sys.argv[2])\n"
            "assert k.GetModuleHandleW(str(dll_path()))==h\n"
            "uninstall_win_soft_delete(); os.remove(sys.argv[1])\n"
        )
        if deleter == "bash":
            git = shutil.which("git.exe")
            bash = os.environ.get("GIT_BASH") or ""
            if not bash and git:
                bash = str(Path(git).resolve().parent.parent / "bin/bash.exe")
            if not bash or not Path(bash).is_file():
                pytest.skip("Git Bash executable not found")
            delete = ("import subprocess; subprocess.run([" + repr(bash) +
                      ", '--noprofile','--norc','-c','rm -- \"$1\"','bash',sys.argv[1]],check=True)")
            script = script.replace("os.remove(sys.argv[1])", delete)
        env = dict(os.environ, JIUWENBOX_SOFT_DELETE="1", JIUWENBOX_SOFT_DELETE_RECYCLE_PORT=str(port),
                   JIUWENBOX_SOFT_DELETE_RECYCLE_TOKEN=token,
                   JIUWENBOX_SOFT_DELETE_ARCHIVE=str(tmp_path / "archive"))
        async with ProcessGuard(session_id="session", host=host) as guard:
            proc = await guard.spawn([sys.executable, "-c", script, str(target), str(tmp_path / "archive")],
                                     task_id="task", tool_call_id="call", tool_name="bash", env=env,
                                     stdio={"stderr": asyncio.subprocess.PIPE})
            _, stderr = await asyncio.wait_for(proc.communicate(), 30)
            assert proc.returncode == 0, stderr
        assert not target.exists()
        assert len(operations) == 2, paths
        assert operations == [(1, operations[0][1]), (2, operations[0][1])]
        results = [e for e in host.events if e.get("kind") == "result" and e.get("path") == str(target)]
        assert len(results) == 1
        assert results[0]["disposition"] == "broker"
    finally:
        broker.stop()


@pytest.mark.asyncio
async def test_output_remains_readable_after_job_finishes(tmp_path):
    async with ProcessGuard(session_id="session", host=Host(tmp_path)) as guard:
        proc = await guard.spawn(["cmd.exe", "/d", "/c", "echo complete"], task_id="task",
                                 tool_call_id="call", tool_name="bash",
                                 stdio={"stdout": asyncio.subprocess.PIPE})
        assert await proc.wait() == 0
        await asyncio.sleep(0.2)
        output, _ = await proc.communicate()
        assert output.strip() == b"complete"


@pytest.mark.asyncio
async def test_descendant_keeps_the_bound_recovery_service_after_root_exits(tmp_path):
    source, signal = tmp_path / "original.txt", tmp_path / "outcome.txt"
    source.write_bytes(b"preserve")
    host = Host(tmp_path)
    child = (
        "import os,sys,time; time.sleep(0.5)\n"
        "try: os.remove(sys.argv[1])\n"
        "except PermissionError: open(sys.argv[2],'w').write('denied')\n"
    )
    root = (
        "import os,subprocess,sys; env=dict(os.environ); "
        "env.pop('JIUWENBOX_SOFT_DELETE_RECYCLE_PORT',None); "
        "subprocess.Popen([sys.executable,'-c',sys.argv[1],*sys.argv[2:]],env=env)"
    )
    async with ProcessGuard(session_id="session", host=host) as guard:
        proc = await guard.spawn([sys.executable, "-c", root, child, str(source), str(signal)],
                                 task_id="task", tool_call_id="call", tool_name="bash",
                                 env=dict(
                                     os.environ,
                                     JIUWENBOX_SOFT_DELETE="1",
                                     JIUWENBOX_SOFT_DELETE_RECYCLE_PORT="0",
                                 ))
        assert await proc.wait() == 0
        async with asyncio.timeout(20):
            while not signal.exists() or not signal.stat().st_size:
                await asyncio.sleep(0.05)
        assert signal.read_text() == "denied"
        assert source.read_bytes() == b"preserve"
    assert any(e.get("kind") == "result" and e.get("status") == "failed" for e in host.events)


@pytest.mark.asyncio
@pytest.mark.parametrize("bits", [32, 64])
async def test_lost_recovery_receipt_and_unreachable_query_remains_unknown(tmp_path, monkeypatch, bits):
    from jiuwenbox.supervisor import win_recycle_broker as recycle

    source, archived = tmp_path / "source.txt", tmp_path / "archived.txt"
    source.write_bytes(b"preserved")
    moved = []

    def recover(path):
        os.rename(path, archived)
        moved.append(path)
        return True

    broker = recycle.RecycleBroker(recycler=recover)
    port = broker.start()
    token = broker.register([str(tmp_path)])

    def lose_receipt(connection, result):
        assert result == b"ok"
        broker.stop()

    monkeypatch.setattr(recycle, "_write_frame", lose_receipt)
    host = Host(tmp_path)
    probe = guard_binary_directory() / ("probe_x86.exe" if bits == 32 else "probe.exe")
    try:
        async with ProcessGuard(session_id="session", host=host) as guard:
            process = await guard.spawn(
                [probe, "delete", source], task_id="task", tool_call_id="call", tool_name="bash",
                timeout_s=20,
                env=dict(os.environ, JIUWENBOX_SOFT_DELETE="1",
                         JIUWENBOX_SOFT_DELETE_RECYCLE_PORT=str(port),
                         JIUWENBOX_SOFT_DELETE_RECYCLE_TOKEN=token),
            )
            assert await process.wait() == 5
        assert archived.read_bytes() == b"preserved" and not source.exists()
        assert len(moved) == 1
        results = [e for e in host.events if e.get("kind") == "result"]
        assert len(results) == 1 and results[0]["status"] == "unknown"
    finally:
        broker.stop()


@pytest.mark.asyncio
async def test_wow64_start_releases_its_host_library_reference(tmp_path, monkeypatch):
    from agent_shield.intercepts.native_call.dll_guard import process_guard as sdk

    installed = guard_binary_directory()
    bundle = tmp_path / "bundle"
    for bits in ("x64", "x86"):
        (bundle / bits).mkdir(parents=True)
        for name in ("agent_security_guard.dll", "agent_security_guard.manifest.json"):
            shutil.copyfile(installed / bits / name, bundle / bits / name)
    library = bundle / "x64" / "agent_security_guard.dll"
    monkeypatch.setattr(sdk, "validate_guard_platform", lambda: library)
    source = tmp_path / "read.txt"
    source.write_bytes(b"data")
    async with ProcessGuard(session_id="session", host=Host(tmp_path)) as guard:
        process = await guard.spawn(
            [installed / "probe_x86.exe", "read", source],
            task_id="task", tool_call_id="call", tool_name="bash", timeout_s=15,
        )
        assert await process.wait() == 0
    # Windows refuses renaming a loaded DLL. Closing a session must permit replacement.
    library.rename(library.with_suffix(".replaced"))
