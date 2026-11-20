# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from jiuwenbox.supervisor import win_softdelete


@pytest.mark.skipif(sys.platform != "win32", reason="Windows soft-delete env")
def test_merge_host_log_layout_env_copies_from_process(monkeypatch):
    monkeypatch.setenv("JIUWENSWARM_LOG_DIR", r"C:\host\logs\agent")
    monkeypatch.setenv("JIUWENSWARM_LOG_DATE_ROOT", r"C:\host\logs")
    env: dict[str, str] = {"USERPROFILE": r"C:\Users\jbx-sandbox"}
    win_softdelete.merge_host_log_layout_env(env)
    assert env["JIUWENSWARM_LOG_DIR"] == r"C:\host\logs\agent"
    assert env["JIUWENSWARM_LOG_DATE_ROOT"] == r"C:\host\logs"
    assert env["USERPROFILE"] == r"C:\Users\jbx-sandbox"


def test_merge_soft_delete_env_includes_log_layout(monkeypatch):
    monkeypatch.setenv("JIUWENBOX_SOFT_DELETE", "1")
    monkeypatch.setenv("JIUWENSWARM_LOG_DIR", "/tmp/logs")
    env: dict[str, str] = {}
    win_softdelete.merge_soft_delete_env(env)
    assert env["JIUWENBOX_SOFT_DELETE"] == "1"
    assert env["JIUWENSWARM_LOG_DIR"] == "/tmp/logs"


def _fake_dacl(aces):
    return SimpleNamespace(GetAceCount=lambda: len(aces), GetAce=lambda index: aces[index])


def _fake_win32security(aces, monkeypatch):
    dacl = _fake_dacl(aces)
    sd = SimpleNamespace(GetSecurityDescriptorDacl=lambda: dacl)
    fake = SimpleNamespace(
        ConvertStringSidToSid=lambda sid: sid,
        GetNamedSecurityInfo=lambda *args: sd,
        SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4,
        INHERIT_ONLY_ACE=0x8,
    )
    monkeypatch.setitem(sys.modules, "win32security", fake)


def test_sandbox_can_load_dll_accepts_users_group_rx(monkeypatch):
    """安装器只授 Users:(RX), 沙箱用户靠组成员资格拿到读执行权."""
    from jiuwenbox.supervisor import win_constants as const

    _fake_win32security(
        [((const.ACCESS_ALLOWED_ACE_TYPE, 0), const.ALLOW_READ_EXECUTE_RIGHTS, "S-1-5-32-545")],
        monkeypatch,
    )
    assert win_softdelete.sandbox_can_load_dll(Path("agent_security_guard.dll"), "S-1-5-21-sandbox") is True


def test_sandbox_can_load_dll_rejects_deny(monkeypatch):
    from jiuwenbox.supervisor import win_constants as const

    _fake_win32security(
        [
            ((const.ACCESS_DENIED_ACE_TYPE, 0), const.ALLOW_READ_EXECUTE_RIGHTS, "S-1-5-32-545"),
            ((const.ACCESS_ALLOWED_ACE_TYPE, 0), const.ALLOW_READ_EXECUTE_RIGHTS, "S-1-5-32-545"),
        ],
        monkeypatch,
    )
    assert win_softdelete.sandbox_can_load_dll(Path("agent_security_guard.dll"), "S-1-5-21-sandbox") is False


def test_sandbox_can_load_dll_ignores_inherit_only(monkeypatch):
    from jiuwenbox.supervisor import win_constants as const

    _fake_win32security(
        [((const.ACCESS_ALLOWED_ACE_TYPE, 0x8), const.ALLOW_READ_EXECUTE_RIGHTS, "S-1-5-32-545")],
        monkeypatch,
    )
    assert win_softdelete.sandbox_can_load_dll(Path("agent_security_guard.dll"), "S-1-5-21-sandbox") is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native recovery")
def test_local_hook_preserves_original_when_broker_unavailable(tmp_path):
    import subprocess
    from agent_security_dll import guard_library

    if not guard_library().is_file():
        pytest.skip("Build the foundation DLL first")
    source = tmp_path / "target.txt"
    source.write_bytes(b"original")
    program = "\n".join([
        "import os, sys, ctypes",
        "from jiuwenbox.supervisor import win_softdelete as ws",
        "from jiuwenbox.supervisor.win_softdelete import install_win_soft_delete",
        "os.environ['JIUWENBOX_SOFT_DELETE_RECYCLE_PORT'] = '0'",
        "install_win_soft_delete(sys.argv[2])",
        "del os.environ['JIUWENBOX_SOFT_DELETE_RECYCLE_PORT']",
        "try: os.remove(sys.argv[1])",
        "except PermissionError: pass",
        "else: sys.exit(1)",
        "records = ws.collect_win_soft_delete_results()",
        "failed = [r for r in records if r.get('kind') == 'result']",
        "assert any(r.get('pid') == os.getpid() and r.get('status') == 'failed'",
        " and r.get('path') == sys.argv[1] for r in failed), records",
        "assert all(len(r.get('operation_ids') or []) == 1 for r in records)",
        "assert all('operation_id' not in r for r in records)",
        "assert all('disposition' in r and 'os_error' in r for r in records)",
        "assert not ws.collect_win_soft_delete_results()",
        "import shutil",
        "from pathlib import Path",
        "git = shutil.which('git.exe')",
        "bash = Path(git).resolve().parent.parent / 'bin/bash.exe' if git else None",
        "if bash and bash.is_file():",
        " import subprocess",
        " commands = ['rm -- \"$1\"', '(rm -- \"$1\")']",
        " commands.append('find \"$1\" -maxdepth 0 -exec rm -- {} +')",
        " for command in commands:",
        "  target = Path(sys.argv[1]).as_posix()",
        "  p = subprocess.run([str(bash), '--noprofile', '--norc', '-c',",
        "   command, 'bash', target], capture_output=True, timeout=15)",
        "  assert p.returncode == 1, (p.returncode, p.stderr)",
        "  assert Path(sys.argv[1]).read_bytes() == b'original'",
        "  records = ws.collect_win_soft_delete_results()",
        "  results = [r for r in records if r.get('kind') == 'result']",
        "  assert len(results) == 1 and results[0].get('status') == 'failed'",
        "  assert results[0].get('pid') != os.getpid(), records",
        " probe = ws.dll_path().parents[1] / 'probe_x86.exe'",
        " if probe.is_file():",
        "  fake = Path(sys.argv[1]).parent / 'rm.exe'",
        "  shutil.copyfile(probe, fake)",
        "  p = subprocess.run([str(bash), '--noprofile', '--norc', '-c',",
        "   '\"$1\" delete \"$2\"', 'bash', fake.as_posix(), Path(sys.argv[1]).as_posix()],",
        "   capture_output=True, timeout=15)",
        "  assert p.returncode == 5 and Path(sys.argv[1]).read_bytes() == b'original', (p.returncode, p.stderr)",
        "  results = [r for r in ws.collect_win_soft_delete_results() if r.get('kind') == 'result']",
        "  assert len(results) == 1 and results[0]['status'] == 'failed', results",
        "api, first, k, module = ws._NATIVE",
        "options = ws._GuardOpenConfig(",
        " ctypes.sizeof(ws._GuardOpenConfig), 2, 0, None, sys.argv[2], '0', None)",
        "second = api.guard_open(ctypes.byref(options))",
        "assert second and second != first",
        "assert not api.guard_close(ctypes.c_void_p(12345))",
        "conflict = ws._GuardOpenConfig(",
        " ctypes.sizeof(ws._GuardOpenConfig), 2, 0, None, sys.argv[2] + '-other', None, None)",
        "assert not api.guard_open(ctypes.byref(conflict))",
        "k.LoadLibraryW.argtypes = [ctypes.c_wchar_p]",
        "k.LoadLibraryW.restype = ctypes.c_void_p",
        "assert k.LoadLibraryW(str(ws.dll_path())) == module",
        "ws.uninstall_win_soft_delete()",
        "try: os.remove(sys.argv[1])",
        "except PermissionError: pass",
        "else: sys.exit(2)",
        "assert api.guard_close(second)",
        "marker = sys.argv[1] + '.released'",
        "open(marker, 'w').close()",
        "os.remove(marker)",
        "third = api.guard_open(ctypes.byref(options))",
        "assert third",
        "try: os.remove(sys.argv[1])",
        "except PermissionError: pass",
        "else: sys.exit(3)",
        "assert api.guard_close(third)",
        "assert k.FreeLibrary(module)",
        "k.GetModuleHandleW.argtypes = [ctypes.c_wchar_p]",
        "k.GetModuleHandleW.restype = ctypes.c_void_p",
        "assert not k.GetModuleHandleW(str(ws.dll_path()))",
        "from jiuwenbox.supervisor import win_exec as runner",
        "import socket, json",
        "sender, receiver = socket.socketpair()",
        "receiver.settimeout(2)",
        "runner._log_subscribers.append(sender)",
        "try:",
        " runner._drain_soft_trace()",
        " frame = json.loads(runner.recv_frame(receiver, 1024 * 1024))",
        " record = frame['soft_delete_result']",
        " assert record.get('kind') == 'result'",
        " assert record.get('pid') == os.getpid()",
        " assert record.get('status') == 'failed', frame",
        "finally:",
        " runner._log_subscribers.remove(sender)",
        " sender.close(); receiver.close()",
        "if bash and bash.is_file():",
        " os.environ[ws.ENV_RECYCLE_PORT] = sys.argv[3]",
        " os.environ[ws.ENV_RECYCLE_TOKEN] = sys.argv[4]",
        " install_win_soft_delete(sys.argv[2])",
        " victim = Path(sys.argv[1]).parent / 'recover.txt'",
        " victim.write_bytes(b'recover')",
        " p = subprocess.run([str(bash), '--noprofile', '--norc', '-c',",
        "  'rm -- \"$1\"', 'bash', victim.as_posix()],",
        "  capture_output=True, timeout=15)",
        " assert p.returncode == 0 and not victim.exists(), (p.returncode, p.stderr)",
        " ws.uninstall_win_soft_delete()",
        " records = ws.collect_win_soft_delete_results()",
        " results = [r for r in records if r.get('kind') == 'result'",
        "  and r.get('path') == str(victim)]",
        " assert len(results) == 1",
        " assert results[0].get('status') == 'success'",
        " assert results[0].get('disposition') == 'broker'",
        " assert results[0].get('pid') != os.getpid(), records",
    ])
    from jiuwenbox.supervisor.win_recycle_broker import RecycleBroker
    calls = []

    def recover(path):
        calls.append(path)
        os.rename(path, path + ".recovered")
        return True

    broker = RecycleBroker(recycler=recover)
    port = broker.start()
    try:
        token = broker.register([str(tmp_path)])
        completed = subprocess.run(
            [sys.executable, "-c", program, str(source), str(tmp_path / "archive"), str(port), token],
            capture_output=True, timeout=45,
        )
        assert completed.returncode == 0, completed.stderr
        import shutil
        git = shutil.which("git.exe")
        if git and (Path(git).resolve().parent.parent / "bin/bash.exe").is_file():
            assert (tmp_path / "recover.txt.recovered").read_bytes() == b"recover"
            assert calls == [str(tmp_path / "recover.txt")]
    finally:
        broker.stop()
    assert source.read_bytes() == b"original"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows native recovery")
def test_delete_proxy_keeps_data_on_broker_refusal(tmp_path):
    import subprocess

    pytest.importorskip("win32security")
    from agent_security_dll import guard_library
    from jiuwenbox.supervisor.win_recycle_broker import RecycleBroker

    if not guard_library().is_file():
        pytest.skip("Build the foundation DLL first")
    source = tmp_path / "document.txt"
    source.write_bytes(b"original")
    program = r'''
import ctypes, os, sys
from ctypes import wintypes
import ntsecuritycon, win32api, win32con, win32file, win32security
from jiuwenbox.supervisor import win_softdelete as recovery

target, port, token = sys.argv[1:]
security = win32security
sid = security.GetTokenInformation(security.OpenProcessToken(win32api.GetCurrentProcess(),
                                   win32con.TOKEN_QUERY), security.TokenUser)[0]
get_acl = lambda path: security.GetNamedSecurityInfo(path, security.SE_FILE_OBJECT,
                       security.DACL_SECURITY_INFORMATION).GetSecurityDescriptorDacl()
set_acl = lambda path, acl: security.SetNamedSecurityInfo(path, security.SE_FILE_OBJECT,
                       security.DACL_SECURITY_INFORMATION, None, None, acl, None)
parent = os.path.dirname(target)
original = {path: get_acl(path) for path in (parent, target)}
for path, mask in ((parent, ntsecuritycon.FILE_DELETE_CHILD), (target, ntsecuritycon.DELETE)):
    acl = security.ACL()
    acl.AddAccessDeniedAce(security.ACL_REVISION, mask, sid)
    acl.AddAccessAllowedAce(security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, sid)
    set_acl(path, acl)

os.environ[recovery.ENV_RECYCLE_PORT] = port
os.environ[recovery.ENV_RECYCLE_TOKEN] = token
try:
    recovery.install_win_soft_delete(os.path.join(parent, 'archive'))
    share = win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE | win32con.FILE_SHARE_DELETE
    handle = win32file.CreateFile(target, ntsecuritycon.DELETE | ntsecuritycon.FILE_READ_ATTRIBUTES,
                                  share, None, win32con.OPEN_EXISTING, 0, None)
    try:
        query = ctypes.WinDLL('ntdll').NtQueryObject
        query.argtypes = (wintypes.HANDLE, wintypes.ULONG, ctypes.c_void_p, wintypes.ULONG, ctypes.c_void_p)
        basic = (wintypes.ULONG * 14)()
        assert query(int(handle), 0, ctypes.byref(basic), ctypes.sizeof(basic), None) >= 0
        assert not basic[1] & ntsecuritycon.DELETE
        set_info = ctypes.WinDLL('kernel32', use_last_error=True).SetFileInformationByHandle
        set_info.argtypes = (wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD)
        delete = wintypes.BOOL(True)
        assert not set_info(int(handle), 4, ctypes.byref(delete), ctypes.sizeof(delete))
        assert ctypes.get_last_error() == 5
    finally:
        handle.Close()
finally:
    recovery.uninstall_win_soft_delete()
    for path, acl in original.items():
        set_acl(path, acl)
'''
    calls = []

    def refuse(path):
        calls.append(path)
        return False

    broker = RecycleBroker(recycler=refuse)
    port = broker.start()
    try:
        token = broker.register([str(tmp_path)])
        result = subprocess.run([sys.executable, "-c", program, str(source), str(port), token],
                                capture_output=True, timeout=15)
        assert result.returncode == 0, result.stderr
    finally:
        broker.stop()
    assert calls == [str(source)]
    assert source.read_bytes() == b"original"
