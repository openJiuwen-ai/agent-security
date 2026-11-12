# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Temporary owner authority for repairing the host's DACL management access.

The context keeps the checked path pinned through the caller's policy retry.
It neither applies sandbox policy nor decides which changes should be rolled back.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from pathlib import Path

from jiuwenbox.supervisor import win_constants as const

logger = logging.getLogger(__name__)
_PIN_FLAGS = 0x02200000  # BACKUP_SEMANTICS | OPEN_REPARSE_POINT
_OWNER_ACCESS = 0x02000000  # MAXIMUM_ALLOWED also suppresses existing-child propagation.
_SHARE_CONTENT = 3  # SHARE_READ | SHARE_WRITE, deliberately without SHARE_DELETE.
_NETWORK_LOGON = 3


def _close_handle(handle) -> None:
    try:
        handle.Close()
    except Exception:
        logger.warning("[ACL] recovery handle close failed", exc_info=True)


def _file_key(files, handle, expected_path: Path) -> tuple[int, int, int]:
    info = files.GetFileInformationByHandle(handle)
    if info[0] & 0x400 or info[7] != 1:
        raise ValueError("Recovery requires a non-reparse object with one link")
    actual = files.GetFinalPathNameByHandle(handle, 0)
    if actual.startswith("\\\\?\\UNC\\"):
        actual = os.path.join("\\\\", actual[8:])
    elif actual.startswith("\\\\?\\"):
        actual = actual[4:]
    if os.path.normcase(os.path.normpath(actual)) != os.path.normcase(str(expected_path)):
        raise ValueError("Recovery handle does not name the checked path")
    return info[4], info[8], info[9]


def _pin_path(stack: ExitStack, files, root: Path, target: Path):
    current = root
    for part in (None, *target.relative_to(root).parts):
        if part is not None:
            current /= part
        access = const.READ_CONTROL if current == target else 0
        handle = files.CreateFile(str(current), access, _SHARE_CONTENT, None, 3, _PIN_FLAGS, None)
        stack.callback(_close_handle, handle)
        key = _file_key(files, handle, current)
    return handle, key


def _owner_open(files, security, token, path: Path):
    """Use a one-shot thread; a failed revert cannot contaminate an ACL worker."""
    def acquire():
        handle = None
        reverted = False
        try:
            security.ImpersonateLoggedOnUser(token)
            try:
                handle = files.CreateFile(str(path), _OWNER_ACCESS, _SHARE_CONTENT, None, 3, _PIN_FLAGS, None)
            finally:
                security.RevertToSelf()
                reverted = True
        finally:
            if handle is not None and not reverted:
                _close_handle(handle)
        return handle

    # A new executor for one operation guarantees shutdown even if reverting
    # identity fails; the thread is never returned to a reusable host pool.
    with ThreadPoolExecutor(max_workers=1, thread_name_prefix="acl-management-open") as worker:
        return worker.submit(acquire).result()


def _descriptor_key(descriptor):
    from jiuwenbox.supervisor.win_acl import _acl_entries, _sid_dedup_key

    return (_acl_entries(descriptor.GetSecurityDescriptorDacl()),
            _sid_dedup_key(descriptor.GetSecurityDescriptorOwner()),
            descriptor.GetSecurityDescriptorControl()[0] & const.SE_DACL_PROTECTED)


def _undo_management_write(security, handle, original, expected_key) -> None:
    """Undo an unverified repair only while its exact descriptor is still ours."""
    flags = security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
    current = security.GetSecurityInfo(handle, security.SE_FILE_OBJECT, flags)
    if _descriptor_key(current) == _descriptor_key(original):
        return
    if _descriptor_key(current) != expected_key:
        logger.warning("[ACL] management rollback conflict: descriptor changed")
        return
    security.SetSecurityInfo(handle, security.SE_FILE_OBJECT,
                             security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION,
                             None, None, original.GetSecurityDescriptorDacl(), None)
    restored = security.GetSecurityInfo(handle, security.SE_FILE_OBJECT, flags)
    if _descriptor_key(restored) != _descriptor_key(original):
        raise RuntimeError("Management rollback readback mismatch")


@contextmanager
def recover_dacl_management(
    path: str, root: str, sandbox_sid: str, expected_identity: tuple[int, int],
) -> Iterator[object | None]:
    """Yield a verified repaired descriptor, or None; never grant sandbox rights.

    Verified host management survives later policy failure. A failed verification
    instead attempts to undo this repair without overwriting concurrent changes.
    Caller exceptions leave this context unchanged and release all pinned handles.
    """
    from jiuwenbox.supervisor import win_setup
    from jiuwenbox.supervisor.win_acl import (
        _acl_entries,
        _acl_object_identity,
        _current_process_user_sid,
        _ensure_pywin32,
        _is_acl_forbidden_path,
        _rebuild_acl_with_order,
        _require_windows,
        _sid_dedup_key,
    )

    _require_windows()
    repaired = None
    operation = "eligibility"
    with ExitStack() as stack:
        try:
            target, boundary = Path(os.path.abspath(path)), Path(os.path.abspath(root))
            if not target.is_relative_to(boundary) or _is_acl_forbidden_path(str(boundary)):
                raise ValueError("Recovery target is outside an eligible bounded root")
            if not sandbox_sid or win_setup.get_sandbox_user_sid() != sandbox_sid:
                raise ValueError("Recovery requires the installed sandbox identity")
            security, _, _ = _ensure_pywin32()
            import win32file

            host = _current_process_user_sid()
            if _sid_dedup_key(host) == sandbox_sid:
                raise ValueError("Recovery must restore a distinct host identity")
            operation = "pin_object"
            checked, key = _pin_path(stack, win32file, boundary, target)
            if _acl_object_identity(path) != expected_identity:
                raise ValueError("Recovery object identity changed")
            flags = security.OWNER_SECURITY_INFORMATION | security.DACL_SECURITY_INFORMATION
            original = security.GetSecurityInfo(checked, security.SE_FILE_OBJECT, flags)
            _, owner, protected = _descriptor_key(original)
            if owner != sandbox_sid or not protected or original.GetSecurityDescriptorDacl() is None:
                raise ValueError("Recovery requires a sandbox-owned protected non-null DACL")
            operation = "owner_logon"
            password = win_setup.get_sandbox_user_password()
            if not password:
                raise ValueError("Saved sandbox credentials unavailable")
            try:
                token = security.LogonUser(const.SANDBOX_USER_NAME, ".", password,
                                           _NETWORK_LOGON, const.LOGON32_PROVIDER_DEFAULT)
            except Exception as exc:
                if getattr(exc, "winerror", None) != const.ERROR_LOGON_TYPE_NOT_GRANTED:
                    raise
                token = security.LogonUser(const.SANDBOX_USER_NAME, ".", password,
                                           const.LOGON32_LOGON_INTERACTIVE, const.LOGON32_PROVIDER_DEFAULT)
            stack.callback(_close_handle, token)
            if _sid_dedup_key(security.GetTokenInformation(token, security.TokenUser)[0]) != sandbox_sid:
                raise ValueError("Logged-on identity does not match the sandbox")
            operation = "owner_open"
            owned = _owner_open(win32file, security, token, target)
            stack.callback(_close_handle, owned)
            if _file_key(win32file, owned, target) != key or _acl_object_identity(path) != expected_identity:
                raise ValueError("Owner handle points to a replaced object")
            current = security.GetSecurityInfo(owned, security.SE_FILE_OBJECT, flags)
            if _descriptor_key(current) != _descriptor_key(original):
                raise ValueError("DACL changed before management repair")
            expected_acl = _rebuild_acl_with_order(current.GetSecurityDescriptorDacl(), [(
                const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC, host,
            )])
            before_entries = _acl_entries(current.GetSecurityDescriptorDacl())
            expected_entries = _acl_entries(expected_acl)
            management_entry = (const.ACCESS_ALLOWED_ACE_TYPE, 0, const.READ_CONTROL | const.WRITE_DAC,
                                _sid_dedup_key(host))
            # The shared builder canonicalizes and deduplicates. Management
            # recovery must not silently reorder or discard legacy ACEs.
            if expected_entries != before_entries + [management_entry] and not (
                management_entry in before_entries and expected_entries == before_entries
            ):
                raise ValueError("Management recovery would alter existing ACEs")
            operation = "restore_management"
            try:
                protection = security.DACL_SECURITY_INFORMATION | security.PROTECTED_DACL_SECURITY_INFORMATION
                security.SetSecurityInfo(owned, security.SE_FILE_OBJECT, protection, None, None, expected_acl, None)
                operation = "verify_management"
                access = const.READ_CONTROL | const.WRITE_DAC
                verified = win32file.CreateFile(str(target), access, _SHARE_CONTENT, None, 3, _PIN_FLAGS, None)
                stack.callback(_close_handle, verified)
                if _file_key(win32file, verified, target) != key:
                    raise ValueError("Management verification object changed")
                after = security.GetSecurityInfo(verified, security.SE_FILE_OBJECT, flags)
                if _descriptor_key(after) != (_acl_entries(expected_acl), owner, protected):
                    raise RuntimeError("Management repair readback mismatch")
                repaired = after
            except Exception:
                try:
                    _undo_management_write(security, owned, original,
                                           (_acl_entries(expected_acl), owner, protected))
                except Exception:
                    logger.warning("[ACL] failed management repair could not be rolled back path=%s",
                                   path, exc_info=True)
                raise
            logger.info("[ACL] host DACL management restored root=%s path=%s", root, path)
        except Exception as exc:
            logger.warning("[ACL] management recovery failed root=%s path=%s operation=%s error=%s",
                           root, path, operation, exc)
            known_failure = isinstance(exc, (OSError, ValueError, RuntimeError, ImportError))
            if not known_failure and getattr(exc, "winerror", None) is None:
                raise
        yield repaired
