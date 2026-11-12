# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Exercise SDK recovery against temporary NTFS objects and an existing account."""
import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.supervisor import win_acl, win_setup
from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor.win_acl import (
    _acl_entries as acl_entries,
)
from jiuwenbox.supervisor.win_acl import (
    _acl_object_identity as object_identity,
)
from jiuwenbox.supervisor.win_acl import (
    _current_process_user_sid as current_host_sid,
)
from jiuwenbox.supervisor.win_acl import (
    _resolve_sid as resolve_sid,
)
from jiuwenbox.supervisor.win_acl import (
    _set_ace_no_propagate as set_object_ace,
)
from jiuwenbox.supervisor.win_acl import (
    _sid_dedup_key as sid_key,
)
from jiuwenbox.supervisor.win_acl import (
    _write_file_dacl as write_file_dacl,
)

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Windows NTFS and installed sandbox account")


def _descriptor(path):
    import win32security

    flags = win32security.DACL_SECURITY_INFORMATION | win32security.OWNER_SECURITY_INFORMATION
    return win32security.GetFileSecurity(str(path), flags)


def _set_test_dacl(path, acl, *, protected):
    import win32security

    sd = _descriptor(path)
    sd.SetSecurityDescriptorDacl(1, acl, 0)
    sd.SetSecurityDescriptorControl(const.SE_DACL_PROTECTED, const.SE_DACL_PROTECTED if protected else 0)
    win32security.SetFileSecurity(str(path), win32security.DACL_SECURITY_INFORMATION, sd)


def _require_ntfs(path):
    import win32api

    if win32api.GetVolumeInformation(path.drive + "\\")[-1].upper() != "NTFS":
        pytest.skip("directory link-count regression requires NTFS")


def _link_count(path):
    import win32file

    handle = win32file.CreateFile(str(path), 0, 7, None, 3, 0x02200000, None)
    try:
        return win32file.GetFileInformationByHandle(handle)[7]
    finally:
        handle.Close()


def _account_call(security, token, operation):
    def execute():
        security.ImpersonateLoggedOnUser(token)
        try:
            return operation()
        finally:
            security.RevertToSelf()

    with ThreadPoolExecutor(max_workers=1) as worker:
        return worker.submit(execute).result()


def _state(security, path):
    sd = security.GetFileSecurity(str(path), security.DACL_SECURITY_INFORMATION | security.OWNER_SECURITY_INFORMATION)
    return (acl_entries(sd.GetSecurityDescriptorDacl()),
            sid_key(sd.GetSecurityDescriptorOwner()),
            sd.GetSecurityDescriptorControl()[0] & const.SE_DACL_PROTECTED)


def _writable(case, path):
    import win32file

    def open_only():
        try:
            flags = 0x02000000 if path.is_dir() else 0
            handle = win32file.CreateFile(str(path), const.FILE_WRITE_DATA, 7, None, 3, flags, None)
        except Exception as exc:
            if getattr(exc, "winerror", None) != 5:
                raise
            return False
        handle.Close()
        return True

    return _account_call(case.security, case.token, open_only)


@pytest.fixture
def actual_acl(tmp_path, monkeypatch, request):
    security = pytest.importorskip("win32security")
    sid = win_setup.get_sandbox_user_sid()
    password = win_setup.get_sandbox_user_password()
    if not sid or not password:
        pytest.skip("existing sandbox credentials unavailable; no account installation or reset")
    try:
        token = security.LogonUser(const.SANDBOX_USER_NAME, ".", password, 3, 0)
    except Exception as exc:
        if getattr(exc, "winerror", None) != const.ERROR_LOGON_TYPE_NOT_GRANTED:
            raise
        token = security.LogonUser(const.SANDBOX_USER_NAME, ".", password, const.LOGON32_LOGON_INTERACTIVE, 0)
    host = current_host_sid()
    assert sid_key(host) != sid
    sandbox = resolve_sid(sid)
    mode = getattr(request, "param", "file")
    root, shared, other = [tmp_path / name for name in ("workspace", "shared", "other")]
    for path in [root, shared, other]:
        path.mkdir()
    parent = root / "data"
    parent.mkdir()
    target = parent / "legacy"
    directory = mode in {"directory", "unlistable"}
    hidden = target / "existing.txt" if directory else None
    set_object_ace(str(parent), sid, rights=const.ALLOW_WRITE_RIGHTS | const.FILE_GENERIC_READ,
                                mode="ALLOW", inheritable=False)
    marker = shared / "active-sandbox.txt"
    marker.write_bytes(b"existing sandbox access")
    set_object_ace(str(marker), sid, rights=const.ALLOW_WRITE_RIGHTS | const.FILE_GENERIC_READ,
                                mode="ALLOW", inheritable=False)
    monkeypatch.setattr(win_acl, "grant_parent_traverse", Mock())
    monkeypatch.setattr(win_acl, "grant_current_user_write_dac", Mock())
    monkeypatch.setattr(win_acl, "JIUWENBOX_HOME", tmp_path / "absent")

    def set_descriptor(path, *, cleanup=False):
        acl = security.ACL()
        if not cleanup and path == target and mode in {"unlistable", "host-deny"}:
            mask = const.FILE_LIST_DIRECTORY if mode == "unlistable" else const.WRITE_DAC
            acl.AddAccessDeniedAceEx(2, 0, mask, host)
        if not cleanup and path == hidden and mode == "unlistable":
            acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, sandbox)
        acl.AddAccessAllowedAceEx(2, 0, 0x1F01FF, sandbox)
        acl.AddAccessAllowedAceEx(2, 0, 0x1F01FF if cleanup or path == hidden else 0x1301BF, host)
        _set_test_dacl(path, acl, protected=True)

    def seed():
        if directory:
            target.mkdir()
            hidden.write_bytes(b"existing child must survive")
            set_descriptor(hidden)
        else:
            target.write_bytes(b"SDK recovery fixture data")
        set_descriptor(target)

    case = SimpleNamespace(root=root, target=target, hidden=hidden, shared=shared, marker=marker, other=other,
                           security=security, token=token, sid=sid, host=host)
    try:
        _account_call(security, token, seed)
        data_files = [hidden] if directory else [target]
        hashes = {path: hashlib.sha256(path.read_bytes()).hexdigest() for path in data_files}
        case.before = {path: _state(security, path) for path in [root, parent, target, shared, other, marker]}
        if hidden is not None:
            case.before[hidden] = _state(security, hidden)
        descriptor = security.GetFileSecurity(str(target), security.DACL_SECURITY_INFORMATION)
        with pytest.raises(Exception) as denied:
            security.SetFileSecurity(str(target), security.DACL_SECURITY_INFORMATION, descriptor)
        assert getattr(denied.value, "winerror", None) == 5
        assert _writable(case, marker)
        yield case
        assert all(hashlib.sha256(path.read_bytes()).hexdigest() == value for path, value in hashes.items())
    finally:
        def cleanup():
            for path in [hidden, target]:
                if path is not None and path.exists():
                    set_descriptor(path, cleanup=True)
        try:
            _account_call(security, token, cleanup)
        finally:
            token.Close()


def _apply(case, *, deny=True):
    return win_acl.apply_sandbox_acl(
        str(case.root), [str(case.root), str(case.other), str(case.shared)],
        [str(case.target)] if deny else [], sandbox_user_sid=case.sid,
        bounded_roots=[str(case.root), str(case.other), str(case.shared)],
    )


def _management_present(case):
    host = sid_key(case.host)
    return (const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC, host) in _state(
        case.security, case.target,
    )[0]


@pytest.mark.parametrize("actual_acl", ["file", "directory"], indirect=True)
def test_real_recovery_enforces_current_policy_and_preserves_descriptor(actual_acl, monkeypatch):
    case = actual_acl
    from jiuwenbox.supervisor import win_acl_recovery
    manager = Mock(wraps=win_acl_recovery.recover_dacl_management)
    monkeypatch.setattr(win_acl_recovery, "recover_dacl_management", manager)
    assert _writable(case, case.target)
    assert _apply(case)
    assert not _writable(case, case.target)
    assert _management_present(case)
    assert _state(case.security, case.target)[1:] == case.before[case.target][1:]
    assert _apply(case)
    assert manager.call_count == 1


@pytest.mark.parametrize("actual_acl", ["unlistable"], indirect=True)
def test_real_management_repair_does_not_hide_required_enumeration_failure(actual_acl):
    case = actual_acl
    with pytest.raises(PermissionError):
        _apply(case, deny=False)
    assert _management_present(case)
    assert _state(case.security, case.hidden) == case.before[case.hidden]
    assert not _writable(case, case.hidden)
    assert _state(case.security, case.root) == case.before[case.root]


@pytest.mark.parametrize("actual_acl", ["file", "directory"], indirect=True)
def test_real_later_root_failure_restores_policy_and_keeps_old_shared_access(actual_acl, monkeypatch):
    case = actual_acl
    get = case.security.GetFileSecurity
    failure = OSError("later root was denied")

    def fail_root(path, flags):
        if str(path) == str(case.other):
            raise failure
        return get(path, flags)

    monkeypatch.setattr(case.security, "GetFileSecurity", fail_root)
    with pytest.raises(OSError) as caught:
        _apply(case)
    assert caught.value is failure
    monkeypatch.setattr(case.security, "GetFileSecurity", get)
    assert _management_present(case) and _writable(case, case.target)
    for path in [case.root, case.shared, case.other, case.marker]:
        assert _state(case.security, path) == case.before[path]
    assert _writable(case, case.marker)
    assert _state(case.security, case.target)[1:] == case.before[case.target][1:]


@pytest.mark.parametrize("actual_acl", ["host-deny"], indirect=True)
def test_real_failed_management_verification_removes_unverified_ace(actual_acl):
    case = actual_acl
    with pytest.raises(Exception) as caught:
        _apply(case)
    assert getattr(caught.value, "winerror", None) == 5
    assert _state(case.security, case.target) == case.before[case.target]
    assert not _management_present(case)
    assert _state(case.security, case.root) == case.before[case.root]


@pytest.mark.parametrize("failure", ["write", "readback", "written_then_error"])
def test_real_policy_retry_failure_keeps_verified_management_only(actual_acl, monkeypatch, failure):
    case = actual_acl
    write = write_file_dacl

    def fail_retry(path, acl, **kwargs):
        policy_deny = any(kind == const.ACCESS_DENIED_ACE_TYPE and sid == case.sid
                          for kind, _, _, sid in acl_entries(acl))
        if str(path) == str(case.target) and _management_present(case) and policy_deny:
            if failure == "readback":
                return None
            if failure == "written_then_error":
                write(path, acl, **kwargs)
            raise RuntimeError("policy retry failed")
        return write(path, acl, **kwargs)

    monkeypatch.setattr(win_acl, "_write_file_dacl", fail_retry)
    with pytest.raises(RuntimeError):
        _apply(case)
    assert _management_present(case) and _writable(case, case.target)
    assert _state(case.security, case.root) == case.before[case.root]


def test_real_recovery_pins_object_until_policy_retry_finishes(actual_acl, monkeypatch):
    case = actual_acl
    write = write_file_dacl
    attempts = []

    def retry(path, acl, **kwargs):
        if str(path) == str(case.target) and _management_present(case):
            with pytest.raises(OSError):
                case.target.rename(case.target.with_name("replaced"))
            attempts.append(path)
        return write(path, acl, **kwargs)

    monkeypatch.setattr(win_acl, "_write_file_dacl", retry)
    assert _apply(case)
    assert attempts == [str(case.target)]


@pytest.mark.parametrize("access", [0x02000000, const.READ_CONTROL | const.WRITE_DAC],
                         ids=["maximum_allowed_does_not_propagate", "explicit_access_does_propagate"])
def test_real_directory_handle_access_controls_existing_child_inheritance(tmp_path, access):
    security = pytest.importorskip("win32security")
    import win32file

    _require_ntfs(tmp_path)
    parent = tmp_path / "parent"
    parent.mkdir()
    acl = security.ACL()
    acl.AddAccessAllowedAceEx(2, 3, 0x1F01FF, current_host_sid())
    _set_test_dacl(parent, acl, protected=True)
    child = parent / "unprotected.txt"
    child.write_bytes(b"existing child data")
    child_handle = win32file.CreateFile(str(child), const.READ_CONTROL | const.WRITE_DAC,
                                       3, None, 3, 0x02200000, None)
    try:
        unprotected = security.DACL_SECURITY_INFORMATION | security.UNPROTECTED_DACL_SECURITY_INFORMATION
        security.SetSecurityInfo(child_handle, security.SE_FILE_OBJECT, unprotected, None, None,
                                 _descriptor(child).GetSecurityDescriptorDacl(), None)
    finally:
        child_handle.Close()
    before = (_state(security, child), _descriptor(child).GetSecurityDescriptorControl())
    assert not before[0][2]
    assert before[1][0] & security.SE_DACL_AUTO_INHERITED
    # FILE_READ_EA is a harmless marker absent from this child's old DACL.
    acl.AddAccessAllowedAceEx(2, 3, 0x8, resolve_sid("S-1-1-0"))
    _set_test_dacl(parent, acl, protected=True)
    assert (_state(security, child), _descriptor(child).GetSecurityDescriptorControl()) == before
    handle = win32file.CreateFile(str(parent), access, 3, None, 3, 0x02200000, None)
    try:
        protection = security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION
        security.SetSecurityInfo(handle, security.SE_FILE_OBJECT, protection, None, None, acl, None)
    finally:
        handle.Close()
    after = (_state(security, child), _descriptor(child).GetSecurityDescriptorControl())
    inherited_marker = (const.ACCESS_ALLOWED_ACE_TYPE, const.INHERITED_ACE, 0x8, "S-1-1-0")
    assert inherited_marker not in before[0][0]
    if access == 0x02000000:
        assert after == before
    else:
        # The positive control proves the child is susceptible to propagation;
        # it cannot pass merely because the fixture protected its child DACL.
        assert inherited_marker in after[0][0]
    assert child.read_bytes() == b"existing child data"


def _unprotected_nested_children(case):
    _require_ntfs(case.root)
    nested = case.target / "nested"
    nested.mkdir()
    full = case.security.ACL()
    full.AddAccessAllowedAceEx(2, 0, 0x1F01FF, resolve_sid(case.sid))
    full.AddAccessAllowedAceEx(2, 0, 0x1F01FF, case.host)
    _set_test_dacl(nested, full, protected=False)
    grandchild = nested / "grandchild.txt"
    grandchild.write_bytes(b"nested child data")
    children = [case.hidden, nested, grandchild]
    for path in children:
        _set_test_dacl(path, full, protected=False)
        assert not _state(case.security, path)[2]
    parent_acl = _descriptor(case.target).GetSecurityDescriptorDacl()
    parent_acl.AddAccessAllowedAceEx(2, 3, 0x8, resolve_sid("S-1-1-0"))
    _account_call(case.security, case.token, lambda: _set_test_dacl(case.target, parent_acl, protected=True))
    assert all(_link_count(path) == 1 for path in [case.root, case.target, nested])
    return children


@pytest.mark.parametrize("actual_acl", ["directory"], indirect=True)
@pytest.mark.parametrize("fail_verification", [False, True], ids=["success", "undo_unverified_repair"])
def test_real_management_repair_preserves_unprotected_descendants(actual_acl, monkeypatch, fail_verification):
    import win32file

    from jiuwenbox.supervisor.win_acl_recovery import recover_dacl_management

    case = actual_acl
    children = _unprotected_nested_children(case)
    before = {path: (_state(case.security, path), _descriptor(path).GetSecurityDescriptorControl())
              for path in [case.target, *children]}
    data = {path: path.read_bytes() for path in children if path.is_file()}
    create = win32file.CreateFile
    rejected = []

    def reject_verification(path, access, *args):
        if str(path) == str(case.target) and access == const.READ_CONTROL | const.WRITE_DAC:
            rejected.append(path)
            # Exercise undo after a real parent DACL write, rather than failing
            # before the mutation that could propagate to existing children.
            assert _management_present(case)
            error = PermissionError("host verification rejected after management write")
            error.winerror = 5
            raise error
        return create(path, access, *args)

    if fail_verification:
        monkeypatch.setattr(win32file, "CreateFile", reject_verification)
    with recover_dacl_management(str(case.target), str(case.root), case.sid,
                                 object_identity(str(case.target))) as repaired:
        assert (repaired is None) == fail_verification
        for path in children:
            assert (_state(case.security, path), _descriptor(path).GetSecurityDescriptorControl()) == before[path]
    for path in children:
        assert (_state(case.security, path), _descriptor(path).GetSecurityDescriptorControl()) == before[path]
    assert all(path.read_bytes() == content for path, content in data.items())
    if fail_verification:
        assert rejected and _state(case.security, case.target) == before[case.target][0]
    else:
        assert _management_present(case)


@pytest.mark.parametrize("actual_acl", ["directory"], indirect=True)
def test_real_policy_application_recovers_nested_ntfs_directory(actual_acl):
    case = actual_acl
    children = _unprotected_nested_children(case)
    data = {path: path.read_bytes() for path in children if path.is_file()}
    assert _apply(case)
    assert _management_present(case)
    assert all(not _writable(case, path) for path in [case.target, *children])
    assert all(path.read_bytes() == content for path, content in data.items())
