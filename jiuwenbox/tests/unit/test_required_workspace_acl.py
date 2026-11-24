# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Required workspace grants cannot succeed after partial ACL application."""
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from jiuwenbox.supervisor import win_acl
from jiuwenbox.supervisor import win_constants as const
from jiuwenbox.supervisor.win_acl import _apply_bounded_acl


def _acl():
    aces = []

    def add_allowed(_revision, flags, mask, sid):
        aces.append(((const.ACCESS_ALLOWED_ACE_TYPE, flags), mask, sid))

    def add_denied(_revision, flags, mask, sid):
        aces.append(((const.ACCESS_DENIED_ACE_TYPE, flags), mask, sid))

    return SimpleNamespace(
        aces=aces, GetAceCount=lambda: len(aces), GetAce=aces.__getitem__,
        AddAccessAllowedAceEx=add_allowed, AddAccessDeniedAceEx=add_denied,
    )


def _descriptor():
    acl = _acl()
    acl.AddAccessAllowedAceEx(2, 0, 0x1F01FF, "host")

    def set_dacl(_present, value, _defaulted):
        descriptor.acl = value

    descriptor = SimpleNamespace(
        acl=acl, control=const.SE_DACL_PROTECTED,
        GetSecurityDescriptorDacl=lambda: descriptor.acl, SetSecurityDescriptorDacl=set_dacl,
        GetSecurityDescriptorControl=lambda: (descriptor.control, 1),
    )
    return descriptor


@pytest.fixture
def native(monkeypatch, tmp_path):
    descriptors, writes = {}, []

    def get(path, _flags):
        return descriptors.setdefault(str(path), _descriptor())

    def write(path, _flags, descriptor):
        descriptors[str(path)] = descriptor
        writes.append(str(path))

    api = SimpleNamespace(ACL=_acl, DACL_SECURITY_INFORMATION=4, GetFileSecurity=get,
                          SetFileSecurity=write, descriptors=descriptors, writes=writes)
    monkeypatch.setattr(win_acl, "_require_windows", lambda: None)
    monkeypatch.setattr(win_acl, "_ensure_pywin32", lambda: (api, None, None))
    monkeypatch.setattr(win_acl, "_resolve_sid", lambda sid: sid)
    monkeypatch.setattr(win_acl, "_sid_dedup_key", lambda sid: sid)
    monkeypatch.setattr(win_acl, "get_synthetic_write_sid", lambda: "synthetic")
    monkeypatch.setattr(win_acl, "grant_parent_traverse", Mock())
    monkeypatch.setattr(win_acl, "grant_current_user_write_dac", Mock())
    monkeypatch.setattr(win_acl, "JIUWENBOX_HOME", tmp_path / "absent")
    return api


@pytest.mark.parametrize("operation", ["read", "write", "scan"])
@pytest.mark.parametrize("error", [PermissionError("denied"), OSError("native failure")])
def test_required_writable_acl_failure_raises_without_broad_revoke(tmp_path, monkeypatch, native, operation, error):
    child = tmp_path / "child"
    child.mkdir()
    (child / "file").write_text("data", encoding="utf-8")
    revoke = Mock()
    monkeypatch.setattr(win_acl, "revoke_sandbox_acl", revoke)

    def fail(*_args, **_kwargs):
        raise error

    if operation == "read":
        monkeypatch.setattr(native, "GetFileSecurity", fail)
    elif operation == "write":
        monkeypatch.setattr(win_acl, "_write_file_dacl", fail)
    else:
        scan = win_acl.os.scandir
        monkeypatch.setattr(win_acl.os, "scandir", lambda path: fail() if str(path) == str(tmp_path) else scan(path))
    with pytest.raises(type(error)) as raised:
        win_acl.apply_sandbox_acl(str(tmp_path), [str(tmp_path)], [], bounded_roots=[str(tmp_path)])
    assert raised.value is error
    revoke.assert_not_called()


def test_optional_read_only_acl_failure_keeps_best_effort(tmp_path, monkeypatch, native):
    monkeypatch.setattr(native, "GetFileSecurity", Mock(side_effect=PermissionError("read-only path")))
    policy = {"allow_read": [str(tmp_path)], "allow_write": [], "deny_read": [], "deny_write": []}
    assert _apply_bounded_acl(str(tmp_path), ["sandbox"], policy) == [str(tmp_path)]


def test_missing_writable_bind_root_is_created_before_bounded_apply(tmp_path, monkeypatch, native):
    root = tmp_path / "new-project"
    monkeypatch.setattr(win_acl, "grant_ace", Mock(side_effect=AssertionError("must use bounded ACL")))
    assert win_acl.apply_sandbox_acl(str(root), [str(root)], [], bounded_roots=[str(root)]) == [str(root)]
    assert root.is_dir()


def _snapshot(api, paths):
    return {str(path): (win_acl_entries(api.GetFileSecurity(str(path), 4).GetSecurityDescriptorDacl()),
                       api.GetFileSecurity(str(path), 4).GetSecurityDescriptorControl()) for path in paths}


def win_acl_entries(acl):
    return [acl.GetAce(index) for index in range(acl.GetAceCount())]


def test_failure_does_not_modify_unvisited_shared_root(tmp_path, monkeypatch, native):
    first, shared = tmp_path / "first", tmp_path / "shared"
    first.mkdir()
    shared.mkdir()
    descriptor = native.GetFileSecurity(str(shared), 4)
    descriptor.acl.AddAccessAllowedAceEx(2, 0, const.ALLOW_WRITE_RIGHTS, "synthetic")
    descriptor.acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, "sandbox")
    before = _snapshot(native, [shared])
    get = native.GetFileSecurity

    def fail(path, flags):
        if str(path) == str(first):
            raise PermissionError("first root failed")
        return get(path, flags)

    monkeypatch.setattr(native, "GetFileSecurity", fail)
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(first), [str(first), str(shared)], [],
                                 sandbox_user_sid="sandbox", bounded_roots=[str(first), str(shared)])
    assert _snapshot(native, [shared]) == before
    assert str(shared) not in native.writes


@pytest.mark.parametrize("write_then_raise", [False, True])
def test_failure_restores_completed_and_partially_written_roots(tmp_path, monkeypatch, native, write_then_raise):
    shared, failing = tmp_path / "shared", tmp_path / "failing"
    shared.mkdir()
    failing.mkdir()
    child = failing / "child"
    child.write_text("preserve", encoding="utf-8")
    descriptor = native.GetFileSecurity(str(shared), 4)
    descriptor.acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, "sandbox")
    descriptor.acl.AddAccessAllowedAceEx(2, 0, const.ALLOW_WRITE_RIGHTS, "synthetic")
    paths = [shared, failing, child]
    before = _snapshot(native, paths)
    original = native.SetFileSecurity
    attempted = False

    def fail(path, flags, sd):
        nonlocal attempted
        if str(path) == str(child) and not attempted:
            attempted = True
            if write_then_raise:
                original(path, flags, sd)
            raise PermissionError("partial application")
        original(path, flags, sd)

    monkeypatch.setattr(native, "SetFileSecurity", fail)
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(failing), [str(shared), str(failing)], [],
                                 sandbox_user_sid="sandbox", bounded_roots=[str(shared), str(failing)])
    assert _snapshot(native, paths) == before
    assert child.read_text(encoding="utf-8") == "preserve"


def test_rollback_does_not_overwrite_a_concurrently_changed_acl(tmp_path, monkeypatch, native, caplog):
    first, failing = tmp_path / "first", tmp_path / "failing"
    first.mkdir()
    failing.mkdir()
    get = native.GetFileSecurity

    def fail(path, flags):
        if str(path) == str(failing):
            get(str(first), 4).acl.AddAccessAllowedAceEx(2, 0, const.FILE_READ_DATA, "another-owner")
            raise PermissionError("second root failed")
        return get(path, flags)

    monkeypatch.setattr(native, "GetFileSecurity", fail)
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(first), [str(first), str(failing)], [],
                                 bounded_roots=[str(first), str(failing)])
    assert any(ace[2] == "another-owner" for ace in get(str(first), 4).acl.aces)
    assert "rollback conflict" in caplog.text


def test_optional_read_only_subtree_enumeration_failure_does_not_abort_required_sibling(
    tmp_path, monkeypatch, native,
):
    required, optional = tmp_path / "required", tmp_path / "optional"
    required.mkdir()
    optional.mkdir()
    scan = win_acl.os.scandir

    def scan_optional(path):
        if str(path) == str(optional):
            raise PermissionError("optional subtree cannot be listed")
        return scan(path)

    monkeypatch.setattr(win_acl.os, "scandir", scan_optional)
    applied = win_acl.apply_sandbox_acl(str(tmp_path), [str(required)], [],
                                       allow_read=[str(tmp_path)], bounded_roots=[str(tmp_path)])
    assert applied == [str(tmp_path)]
    assert str(required) in native.writes


def test_deny_subtree_enumeration_failure_still_aborts(tmp_path, monkeypatch, native):
    denied = tmp_path / "denied"
    denied.mkdir()
    scan = win_acl.os.scandir
    monkeypatch.setattr(win_acl.os, "scandir", lambda path: (_ for _ in ()).throw(PermissionError("deny incomplete"))
                        if str(path) == str(denied) else scan(path))
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(tmp_path), [str(tmp_path)], [str(denied)], bounded_roots=[str(tmp_path)])


@pytest.mark.parametrize("error_type", [PermissionError, OSError])
def test_unlistable_required_write_child_restores_acl_without_revoking_shared_root(
    tmp_path, monkeypatch, native, error_type,
):
    workspace, shared = tmp_path / "workspace", tmp_path / "shared"
    child = workspace / "node_modules"
    child.mkdir(parents=True)
    shared.mkdir()
    hidden = child / "protected-file"
    hidden.write_text("data", encoding="utf-8")
    for path in [child, shared]:
        native.GetFileSecurity(str(path), 4).acl.AddAccessAllowedAceEx(
            2, 0, const.ALLOW_WRITE_RIGHTS, "synthetic",
        )
    paths = [workspace, child, hidden, shared]
    before = _snapshot(native, paths)
    revoke = Mock()
    monkeypatch.setattr(win_acl, "revoke_sandbox_acl", revoke)
    scan = win_acl.os.scandir
    failure = error_type("required write subtree cannot be listed")

    def scan_child(path):
        if str(path) == str(child):
            raise failure
        return scan(path)

    monkeypatch.setattr(win_acl.os, "scandir", scan_child)
    with pytest.raises(error_type) as raised:
        win_acl.apply_sandbox_acl(str(workspace), [str(workspace), str(shared)], [],
                                 bounded_roots=[str(workspace), str(shared)])
    assert raised.value is failure
    assert _snapshot(native, paths) == before
    assert str(child) in native.writes
    assert str(hidden) not in native.writes
    assert str(shared) not in native.writes
    assert hidden.read_text(encoding="utf-8") == "data"
    revoke.assert_not_called()


@pytest.mark.parametrize("writable", [True, False])
def test_child_metadata_failure_obeys_required_write_policy(tmp_path, monkeypatch, native, writable):
    child = tmp_path / "child"
    child.mkdir()
    required = tmp_path / "required"
    required.mkdir()
    before = _snapshot(native, [tmp_path, child, required])
    stat = win_acl.os.stat

    def stat_child(path, *args, **kwargs):
        if str(path) == str(child) and kwargs.get("follow_symlinks") is False:
            raise PermissionError("child metadata cannot be read")
        return stat(path, *args, **kwargs)

    monkeypatch.setattr(win_acl.os, "stat", stat_child)
    write = [str(tmp_path)] if writable else [str(required)]
    if writable:
        with pytest.raises(PermissionError):
            win_acl.apply_sandbox_acl(str(tmp_path), write, [], bounded_roots=[str(tmp_path)])
        assert _snapshot(native, [tmp_path, child, required]) == before
    else:
        assert win_acl.apply_sandbox_acl(str(tmp_path), write, [], bounded_roots=[str(tmp_path)]) == [str(tmp_path)]
        assert str(required) in native.writes


@pytest.mark.parametrize("rule", ["write", "deny_read", "deny_write"])
def test_unlistable_ancestor_of_explicit_target_still_aborts(tmp_path, monkeypatch, native, rule):
    child = tmp_path / "child"
    child.mkdir()
    target = child / "target"
    target.mkdir()
    before = _snapshot(native, [tmp_path, child, target])
    scan = win_acl.os.scandir

    def scan_child(path):
        if str(path) == str(child):
            raise PermissionError("explicit target is unreachable")
        return scan(path)

    monkeypatch.setattr(win_acl.os, "scandir", scan_child)
    write = [str(tmp_path), str(target)] if rule == "write" else [str(tmp_path)]
    deny_write = [str(target)] if rule == "deny_write" else []
    deny_read = [str(target)] if rule == "deny_read" else []
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(tmp_path), write, deny_write, deny_read=deny_read, bounded_roots=[str(tmp_path)])
    assert _snapshot(native, [tmp_path, child, target]) == before


@pytest.mark.parametrize("is_file", [False, True])
def test_nonbounded_explicit_write_failure_aborts_and_restores_workspace(tmp_path, monkeypatch, native, is_file):
    workspace, extra = tmp_path / "workspace", tmp_path / "extra"
    workspace.mkdir()
    if is_file:
        extra.write_text("data", encoding="utf-8")
    else:
        extra.mkdir()
    before = _snapshot(native, [workspace, extra])
    writer = native.SetFileSecurity

    def fail(path, flags, sd):
        if str(path) == str(extra):
            raise PermissionError("explicit writable path failed")
        writer(path, flags, sd)

    monkeypatch.setattr(native, "SetFileSecurity", fail)
    monkeypatch.setattr(win_acl, "grant_ace", Mock(side_effect=PermissionError("legacy grant failed")))
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(workspace), [str(workspace), str(extra)], [], bounded_roots=[str(workspace)])
    assert _snapshot(native, [workspace, extra]) == before


def test_nonrecursive_write_does_not_walk_existing_children(tmp_path, native):
    child = tmp_path / "child"
    child.write_text("data", encoding="utf-8")
    win_acl.apply_sandbox_acl(str(tmp_path), [str(tmp_path)], [], recursive=False)
    assert str(child) not in native.descriptors
    assert all(ace[0][1] == 0 for ace in native.descriptors[str(tmp_path)].acl.aces)


def test_rollback_preserves_replaced_object(tmp_path, monkeypatch, native, caplog):
    first, failing = tmp_path / "first", tmp_path / "failing"
    first.mkdir()
    failing.mkdir()
    getter = native.GetFileSecurity

    def fail(path, flags):
        if str(path) == str(failing):
            first.rename(tmp_path / "previous-object")
            first.mkdir()
            replacement = _descriptor()
            replacement.acl.AddAccessAllowedAceEx(2, 0, const.ALLOW_WRITE_RIGHTS, "synthetic")
            native.descriptors[str(first)] = replacement
            raise PermissionError("later root failed")
        return getter(path, flags)

    monkeypatch.setattr(native, "GetFileSecurity", fail)
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(first), [str(first), str(failing)], [],
                                 bounded_roots=[str(first), str(failing)])
    assert native.writes.count(str(first)) == 1
    assert "rollback conflict: object changed" in caplog.text


def test_rollback_error_does_not_mask_original_failure_or_stop_other_restores(tmp_path, monkeypatch, native, caplog):
    first, second, failing = [tmp_path / name for name in ("first", "second", "failing")]
    for root in (first, second, failing):
        root.mkdir()
    before = _snapshot(native, [first])
    writer, getter = native.SetFileSecurity, native.GetFileSecurity
    failed = False
    original = PermissionError("original create failure")

    def get(path, flags):
        nonlocal failed
        if str(path) == str(failing):
            failed = True
            raise original
        return getter(path, flags)

    def write(path, flags, sd):
        if failed and str(path) == str(second):
            raise OSError("cannot restore this object")
        writer(path, flags, sd)

    monkeypatch.setattr(native, "GetFileSecurity", get)
    monkeypatch.setattr(native, "SetFileSecurity", write)
    with pytest.raises(PermissionError) as raised:
        win_acl.apply_sandbox_acl(str(first), [str(first), str(second), str(failing)], [],
                                 bounded_roots=[str(first), str(second), str(failing)])
    assert raised.value is original
    assert _snapshot(native, [first]) == before
    assert "rollback failed" in caplog.text


@pytest.mark.skipif(sys.platform != "win32", reason="real temporary Windows DACLs")
def test_native_failed_apply_restores_prior_dacls_and_protection(tmp_path, monkeypatch):
    security = pytest.importorskip("win32security")
    first, failing = tmp_path / "first", tmp_path / "failing"
    first.mkdir()
    failing.mkdir()
    victim = failing / "victim"
    victim.write_text("original data", encoding="utf-8")
    synthetic = win_acl.get_synthetic_write_sid()
    descriptor = security.GetFileSecurity(str(first), security.DACL_SECURITY_INFORMATION)
    acl = descriptor.GetSecurityDescriptorDacl()
    acl.AddAccessDeniedAceEx(2, 0, const.FILE_WRITE_DATA, security.ConvertStringSidToSid(synthetic))
    descriptor.SetSecurityDescriptorDacl(1, acl, 0)
    descriptor.SetSecurityDescriptorControl(const.SE_DACL_PROTECTED, const.SE_DACL_PROTECTED)
    security.SetFileSecurity(str(first), security.DACL_SECURITY_INFORMATION, descriptor)
    paths = [first, failing, victim]

    def snapshots():
        return {str(path): (
            win_acl_entries(security.GetFileSecurity(str(path), 4).GetSecurityDescriptorDacl()),
            security.GetFileSecurity(str(path), 4).GetSecurityDescriptorControl()[0] & const.SE_DACL_PROTECTED,
        ) for path in paths}

    before = snapshots()
    writer = security.SetFileSecurity
    failed = False

    def fail(path, flags, sd):
        nonlocal failed
        writer(path, flags, sd)
        if str(path) == str(victim) and not failed:
            failed = True
            raise PermissionError("native write completed before failure")

    monkeypatch.setattr(security, "SetFileSecurity", fail)
    monkeypatch.setattr(win_acl, "JIUWENBOX_HOME", tmp_path / "absent")
    with pytest.raises(PermissionError):
        win_acl.apply_sandbox_acl(str(first), [str(first), str(failing)], [], bounded_roots=[str(first), str(failing)])
    assert snapshots() == before
    assert victim.read_text(encoding="utf-8") == "original data"
