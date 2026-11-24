# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Management repair uses SDK ACL semantics and never hides failed policy work."""
import os
import sys
import threading
from types import SimpleNamespace

import pytest

from jiuwenbox.supervisor import win_acl, win_setup
from jiuwenbox.supervisor import win_acl_recovery as recovery
from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor.win_acl import (
    _acl_entries as acl_entries,
)
from jiuwenbox.supervisor.win_acl import (
    _acl_object_identity as object_identity,
)
from jiuwenbox.supervisor.win_acl import (
    _write_file_dacl as write_file_dacl,
)
from jiuwenbox.supervisor.win_acl_recovery import _descriptor_key as descriptor_key

from .test_required_workspace_acl import _acl, _descriptor
from .test_required_workspace_acl import native as _native_fixture

native = _native_fixture

# 非 Allow/Deny 的 ACE 类型(SYSTEM_AUDIT_ACE_TYPE)。注意它与 ACL revision(=2)无关。
_UNSUPPORTED_ACE_TYPE = 2


def _copy_descriptor(descriptor):
    value = _descriptor()
    value.acl = None if descriptor.acl is None else _acl()
    if value.acl is not None:
        value.acl.aces[:] = descriptor.acl.aces
    value.owner = descriptor.owner
    value.control = descriptor.control

    def owner():
        return value.owner

    value.GetSecurityDescriptorOwner = owner
    return value


@pytest.fixture
def repair_env(tmp_path, monkeypatch, request):
    win32_api = request.getfixturevalue("native")
    root = tmp_path / "workspace"
    root.mkdir()
    target = root / "legacy.txt"
    target.write_bytes(b"SDK legacy data")
    original_get = win32_api.GetFileSecurity

    def read(path, flags=5):
        sd = original_get(str(path), flags)
        if not hasattr(sd, "owner"):
            sd.owner = "sandbox"

            def owner():
                return sd.owner

            sd.GetSecurityDescriptorOwner = owner
        return sd

    monkeypatch.setattr(win32_api, "GetFileSecurity", read)
    sd = read(target)
    sd.acl.aces[:] = []
    sd.acl.AddAccessAllowedAceEx(2, 0, 0x1F01FF, "sandbox")
    sd.acl.AddAccessAllowedAceEx(2, 0, 0x1301BF, "host")
    state = SimpleNamespace(root=root, target=target, api=win32_api, read=read, handles=[], logons=[],
                            reparse=None, links=1, redirect=False, wrong_handle=False, token_sid="sandbox",
                            installed_sid="sandbox", logon_material=os.urandom(8).hex(), owner_open_fails=False,
                            revert_fails=False, host_verify_fails=False, corrupt_verify=False,
                            set_fails=False, set_then_raises=False, external_change=False,
                            management_writes=0, owner_threads=[], setter_threads=[], write_code=5,
                            retry_fails=False, ignore_retry=False, fail_read=False, first_error=None, undo_fails=False)
    local = threading.local()

    def handle(path=None, access=0):
        value = SimpleNamespace(path=path, access=access, closed=False)

        def close():
            value.closed = True

        value.Close = close
        state.handles.append(value)
        return value

    def create(path, access, share, _sa, disposition, flags, _template):
        assert share == 3 and disposition == 3 and flags == 0x02200000
        if access == 0x02000000:
            assert getattr(local, "owner", False)
            state.owner_threads.append(threading.get_ident())
            if state.owner_open_fails:
                raise PermissionError("owner open rejected")
        if access == const.READ_CONTROL | const.WRITE_DAC and state.host_verify_fails:
            raise PermissionError("host access remains denied")
        return handle(path, access)

    def information(value):
        info = os.stat(value.path, follow_symlinks=False)
        ino = info.st_ino + int(state.wrong_handle and value.access == 0x02000000)
        attrs = 0x400 if value.path == state.reparse else 0
        links = state.links if value.path == str(target) else 1
        file_info = (attrs, 0, 0, 0, info.st_dev, 0, 0, links, ino >> 32, ino & 0xFFFFFFFF)
        return file_info

    def get_security(value, _kind, _flags):
        stored = read(value.path)
        if state.external_change and state.management_writes and value.access == const.READ_CONTROL | const.WRITE_DAC:
            stored.acl.AddAccessAllowedAceEx(2, 0, const.FILE_READ_DATA, "external")
            state.external_change = False
        result = _copy_descriptor(stored)
        if state.corrupt_verify and value.access == const.READ_CONTROL | const.WRITE_DAC:
            result.owner = "wrong-readback"
        return result

    def set_security(value, _kind, flags, owner, group, acl, sacl):
        assert not getattr(local, "owner", False)
        assert value.access == 0x02000000 and flags == 0x80000004
        assert owner is group is sacl is None
        state.management_writes += 1
        state.setter_threads.append(threading.get_ident())
        if state.undo_fails and state.management_writes > 1:
            raise OSError("management undo failed")
        if state.set_fails and state.management_writes == 1:
            raise OSError("management write failed")
        stored_acl = _acl()
        stored_acl.aces[:] = acl.aces
        read(value.path).acl = stored_acl
        if state.set_then_raises and state.management_writes == 1:
            raise OSError("management was written before error")

    def impersonate(_token):
        local.owner = True

    def revert():
        if state.revert_fails:
            raise OSError("revert failed")
        local.owner = False

    def logon(_name, _domain, supplied, kind, _provider):
        assert supplied == state.logon_material
        state.logons.append(kind)
        return handle()

    files = SimpleNamespace(CreateFile=create, GetFileInformationByHandle=information,
                            GetFinalPathNameByHandle=lambda value, _flags: str(root / "redirect")
                            if state.redirect else value.path)
    for name, value in {
        "OWNER_SECURITY_INFORMATION": 1, "SE_FILE_OBJECT": 1, "PROTECTED_DACL_SECURITY_INFORMATION": 0x80000000,
        "TokenUser": 1, "GetSecurityInfo": get_security, "SetSecurityInfo": set_security,
        "LogonUser": logon, "GetTokenInformation": lambda _token, _kind: (state.token_sid, 0),
        "ImpersonateLoggedOnUser": impersonate, "RevertToSelf": revert,
    }.items():
        monkeypatch.setattr(win32_api, name, value, raising=False)
    monkeypatch.setitem(sys.modules, "win32file", files)
    monkeypatch.setattr(win_setup, "get_sandbox_user_sid", lambda: state.installed_sid)
    monkeypatch.setattr(win_setup, "get_sandbox_user_password", lambda: state.logon_material)
    monkeypatch.setattr(win_acl, "_current_process_user_sid", lambda: "host")
    original_write = write_file_dacl

    def sdk_read(path, flags):
        if str(path) == str(target) and state.fail_read:
            error = PermissionError("DACL read denied")
            error.winerror = 5
            raise error
        return read(path, flags)

    def sdk_write(path, acl, **kwargs):
        if str(path) == str(target):
            managed = any(sid == "host" and mask & const.WRITE_DAC
                          for kind, _flags, mask, sid in acl_entries(read(path).acl)
                          if kind == const.ACCESS_ALLOWED_ACE_TYPE)
            if not managed:
                state.first_error = PermissionError("host lacks DACL write access")
                state.first_error.winerror = state.write_code
                raise state.first_error
            if state.retry_fails:
                raise RuntimeError("policy retry rejected")
            if state.ignore_retry:
                return None
        return original_write(path, acl, **kwargs)

    monkeypatch.setattr(win32_api, "GetFileSecurity", sdk_read)
    monkeypatch.setattr(win_acl, "_write_file_dacl", sdk_write)
    state.before = descriptor_key(_copy_descriptor(sd))
    state.identity = object_identity(str(target))
    return state


def _repair(state, **kwargs):
    return recovery.recover_dacl_management(str(state.target), str(state.root), "sandbox",
                                           kwargs.get("identity", state.identity))


def _apply(state, **kwargs):
    return win_acl.apply_sandbox_acl(str(state.root), [str(state.root)], [str(state.target)],
                                    bounded_roots=[str(state.root)], sandbox_user_sid=kwargs.get("sid", "sandbox"))


def test_management_context_preserves_policy_and_pins_handles_until_retry_finishes(repair_env):
    state = repair_env
    with _repair(state) as descriptor:
        assert descriptor is not None
        entries, owner, protected = descriptor_key(descriptor)
        assert all(entry in entries for entry in state.before[0])
        assert (const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC, "host") in entries
        assert (owner, protected) == state.before[1:]
        assert all(not value.closed for value in state.handles)
    assert all(value.closed for value in state.handles)
    assert state.owner_threads and state.owner_threads[0] != threading.get_ident()
    assert state.setter_threads == [threading.get_ident()]
    assert state.target.read_bytes() == b"SDK legacy data"


@pytest.mark.parametrize("reason", [
    "outside", "forbidden", "host", "installed", "owner", "unprotected", "null", "reparse",
    "ancestor_reparse", "links", "redirect", "identity", "token", "password",
    "noncanonical", "duplicate", "unusual",
])
def test_ineligible_recovery_never_changes_acl(repair_env, monkeypatch, reason):
    state = repair_env
    identity = state.identity
    if reason == "outside":
        state.root = state.target.parent / "outside"
    elif reason == "forbidden":
        monkeypatch.setattr(win_acl, "_is_acl_forbidden_path", lambda _path: True)
    elif reason == "host":
        monkeypatch.setattr(win_acl, "_current_process_user_sid", lambda: "sandbox")
    elif reason == "installed":
        state.installed_sid = "other"
    elif reason == "owner":
        state.read(state.target).owner = "other"
    elif reason == "unprotected":
        state.read(state.target).control = 0
    elif reason == "null":
        state.read(state.target).acl = None
    elif reason in {"reparse", "ancestor_reparse"}:
        state.reparse = str(state.target if reason == "reparse" else state.root)
    elif reason == "links":
        state.links = 2
    elif reason == "redirect":
        state.redirect = True
    elif reason == "identity":
        identity = (state.identity[0], state.identity[1] + 1)
    elif reason == "token":
        state.token_sid = "other"
    elif reason in {"noncanonical", "duplicate", "unusual"}:
        acl = state.read(state.target).acl
        if reason == "noncanonical":
            acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, "other")
        elif reason == "duplicate":
            acl.aces.append(acl.aces[0])
        else:
            # 无法识别的 ACE 类型会被 _rebuild_acl_with_order 改写成 Allow,
            # 恢复必须拒绝,不能静默改变既有 ACE 语义。
            acl.aces.append(((_UNSUPPORTED_ACE_TYPE, 0), const.FILE_READ_DATA, "other"))
    else:
        state.logon_material = None
    before = descriptor_key(_copy_descriptor(state.read(state.target)))
    with _repair(state, identity=identity) as descriptor:
        assert descriptor is None
    assert state.management_writes == 0
    assert descriptor_key(state.read(state.target)) == before
    assert all(value.closed for value in state.handles)


@pytest.mark.parametrize("reason", ["owner_open_fails", "revert_fails", "wrong_handle", "set_fails",
                                   "set_then_raises", "host_verify_fails", "corrupt_verify"])
def test_failed_repair_removes_its_management_write_without_changing_original_dacl(repair_env, reason):
    state = repair_env
    setattr(state, reason, True)
    with _repair(state) as descriptor:
        assert descriptor is None
    assert descriptor_key(state.read(state.target)) == state.before
    assert all(value.closed for value in state.handles)


def test_failed_verification_preserves_external_descriptor_changes(repair_env, caplog):
    state = repair_env
    state.external_change = True
    with _repair(state) as descriptor:
        assert descriptor is None
    assert any(entry[3] == "external" for entry in acl_entries(state.read(state.target).acl))
    assert "management rollback conflict" in caplog.text


def test_management_undo_failure_cannot_hide_original_policy_failure(repair_env, caplog):
    state = repair_env
    state.host_verify_fails = state.undo_fails = True
    with pytest.raises(PermissionError) as caught:
        _apply(state)
    assert caught.value is state.first_error
    assert "could not be rolled back" in caplog.text
    assert "rollback conflict" in caplog.text
    assert not any(kind == const.ACCESS_DENIED_ACE_TYPE and sid == "sandbox"
                   for kind, _, _, sid in acl_entries(state.read(state.target).acl))
    assert all(value.closed for value in state.handles)


def test_caller_exception_is_not_swallowed_by_recovery_context(repair_env):
    error = RuntimeError("policy caller failed")
    with pytest.raises(RuntimeError) as caught, _repair(repair_env) as descriptor:
        assert descriptor is not None
        raise error
    assert caught.value is error
    assert all(value.closed for value in repair_env.handles)


def test_automatic_recovery_retries_current_policy_and_is_idempotent(repair_env):
    state = repair_env
    assert _apply(state) == [str(state.root)]
    entries = acl_entries(state.read(state.target).acl)
    assert any(kind == const.ACCESS_DENIED_ACE_TYPE and sid == "sandbox" and mask & const.FILE_WRITE_DATA
               for kind, _, mask, sid in entries)
    assert (const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC, "host") in entries
    assert _apply(state)
    assert state.logons == [3]


@pytest.mark.parametrize("failure", ["retry_fails", "ignore_retry"])
def test_failed_policy_rolls_back_to_repaired_management_baseline(repair_env, failure):
    state = repair_env
    setattr(state, failure, True)
    with pytest.raises(RuntimeError):
        _apply(state)
    entries, owner, protected = descriptor_key(state.read(state.target))
    assert all(entry in entries for entry in state.before[0])
    assert (const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC, "host") in entries
    assert (owner, protected) == state.before[1:]
    assert not any(kind == const.ACCESS_DENIED_ACE_TYPE and sid == "sandbox" for kind, _, _, sid in entries)


@pytest.mark.parametrize("reason", ["missing_sid", "other_error", "read_dacl"])
def test_recovery_is_only_entered_for_eligible_policy_write_failure(repair_env, reason):
    state = repair_env
    if reason == "other_error":
        state.write_code = 32
    if reason == "read_dacl":
        state.fail_read = True
    with pytest.raises(PermissionError):
        _apply(state, sid=None if reason == "missing_sid" else "sandbox")
    assert not state.logons and state.management_writes == 0


def test_recovery_then_later_root_failure_keeps_management_and_prior_shared_permissions(repair_env, monkeypatch):
    state = repair_env
    other, shared = state.root.parent / "other", state.root.parent / "shared"
    other.mkdir()
    shared.mkdir()
    state.read(shared).acl.AddAccessAllowedAceEx(2, 0, const.ALLOW_WRITE_RIGHTS, "synthetic")
    before = {path: descriptor_key(_copy_descriptor(state.read(path)))
              for path in [state.root, other, shared]}
    failure = OSError("later root read failed")

    def read(path, flags):
        if str(path) == str(other):
            raise failure
        return state.read(path, flags)

    monkeypatch.setattr(state.api, "GetFileSecurity", read)
    with pytest.raises(OSError) as caught:
        win_acl.apply_sandbox_acl(str(state.root), [str(state.root), str(other), str(shared)], [str(state.target)],
                                 bounded_roots=[str(state.root), str(other), str(shared)], sandbox_user_sid="sandbox")
    assert caught.value is failure
    for path, key in before.items():
        assert descriptor_key(state.read(path)) == key
    entries, owner, protected = descriptor_key(state.read(state.target))
    assert entries == state.before[0] + [(const.ACCESS_ALLOWED_ACE_TYPE, 0,
                                         const.READ_CONTROL | const.WRITE_DAC, "host")]
    assert (owner, protected) == state.before[1:]
    assert state.logons == [3]


def test_repaired_but_unlistable_required_subtree_still_aborts(repair_env, monkeypatch):
    state = repair_env
    state.target.unlink()
    state.target.mkdir()
    hidden = state.target / "hidden.txt"
    hidden.write_bytes(b"keep hidden data")
    state.read(hidden).acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, "sandbox")
    before = descriptor_key(_copy_descriptor(state.read(hidden)))
    failure = PermissionError("directory enumeration remains denied")
    scan = win_acl.os.scandir

    def scan_required(path):
        if str(path) == str(state.target):
            raise failure
        return scan(path)

    monkeypatch.setattr(win_acl.os, "scandir", scan_required)
    with pytest.raises(PermissionError) as caught:
        win_acl.apply_sandbox_acl(str(state.root), [str(state.root)], [], bounded_roots=[str(state.root)],
                                 sandbox_user_sid="sandbox")
    assert caught.value is failure
    assert state.logons == [3]
    assert descriptor_key(state.read(hidden)) == before
    assert hidden.read_bytes() == b"keep hidden data"


@pytest.mark.parametrize("code", [1385, 1326])
def test_only_logon_type_restriction_allows_interactive_fallback(repair_env, monkeypatch, code):
    state = repair_env
    original = state.api.LogonUser
    attempts = []

    def logon(name, domain, password, kind, provider):
        attempts.append(kind)
        if len(attempts) == 1:
            error = OSError("logon was rejected")
            error.winerror = code
            raise error
        return original(name, domain, password, kind, provider)

    monkeypatch.setattr(state.api, "LogonUser", logon)
    with _repair(state) as descriptor:
        assert (descriptor is not None) == (code == 1385)
    assert attempts == ([3, 2] if code == 1385 else [3])
