"""The error envelope and the single-instance guard.

The Go counterpart lives in ``internal/platform``.
"""

from __future__ import annotations

import os
import time

import pytest
from security_gateway.platform.errs import (
    Code,
    code_of,
    http_status,
    new,
    wrap,
)
from security_gateway.platform.singleinstance import (
    SingleInstanceError,
    acquire_single_instance_lock,
    open_lock_file,
    write_pid_file,
)

# --- the envelope -----------------------------------------------------------


def test_a_new_error_carries_its_code_and_operation():
    err = new(Code.NOT_FOUND, "CredentialStore.Get", "no such credential")
    assert err.code == Code.NOT_FOUND
    assert err.op == "CredentialStore.Get"
    assert "CredentialStore.Get" in str(err)
    assert "no such credential" in str(err)


def test_a_wrapped_error_keeps_its_cause():
    cause = ValueError("the underlying reason")
    err = wrap(Code.INTERNAL, "Vault.Put", "could not write", cause)
    assert err.cause is cause
    assert "the underlying reason" in str(err)


def test_the_outermost_code_wins():
    """Go's errors.As finds the outermost matching error, and so do we.

    A handler that wants a conflict to reach the client as 409 must
    therefore build the error with that code rather than wrapping a
    conflict inside an "internal" one.
    """
    cause = new(Code.CONFLICT, "Store.Update", "the version moved")
    err = wrap(Code.INTERNAL, "Admin.Put", "could not update", cause)
    assert code_of(err) == Code.INTERNAL
    assert code_of(cause) == Code.CONFLICT


def test_an_error_that_is_not_ours_has_no_code():
    assert code_of(ValueError("plain")) == ""
    assert code_of(None) == ""


@pytest.mark.parametrize(
    "code,status",
    [
        (Code.BAD_REQUEST, 400),
        (Code.UNSUPPORTED_CIPHER_FORMAT, 400),
        (Code.UNAUTHORIZED, 401),
        (Code.NOT_FOUND, 404),
        (Code.CONFLICT, 409),
        (Code.ROTATION_IN_PROGRESS, 409),
        (Code.NESTED_ROTATION, 409),
        (Code.NO_ROTATION_IN_PROGRESS, 409),
        (Code.PAYLOAD_TOO_LARGE, 413),
        (Code.BACKUP_FAILED, 500),
        (Code.INTERNAL, 500),
        (Code.BAD_GATEWAY, 502),
        (Code.SERVICE_UNAVAILABLE, 503),
        (Code.GATEWAY_TIMEOUT, 504),
    ],
)
def test_each_code_maps_to_its_http_status(code, status):
    assert http_status(code) == status


def test_an_unknown_code_is_a_server_error():
    assert http_status("something-else") == 500


# --- the single-instance guard ----------------------------------------------


def test_the_lock_file_is_created_with_a_private_mode(tmp_path):
    path = tmp_path / ".lock"
    f = open_lock_file(path)
    try:
        assert path.exists()
        assert os.stat(path).st_mode & 0o777 == 0o600
    finally:
        f.close()


def test_the_lock_is_taken_when_nothing_else_holds_it(tmp_path):
    f = open_lock_file(tmp_path / ".lock")
    try:
        acquire_single_instance_lock(f)
    finally:
        f.close()


def test_a_second_holder_is_refused(tmp_path):
    first = open_lock_file(tmp_path / ".lock")
    second = open_lock_file(tmp_path / ".lock")
    try:
        acquire_single_instance_lock(first)
        with pytest.raises(SingleInstanceError):
            acquire_single_instance_lock(second)
    finally:
        first.close()
        second.close()


def test_a_stale_lock_from_a_dead_process_is_reaped(tmp_path):
    """A lock left behind by a process that is gone must not block a start."""
    lock = open_lock_file(tmp_path / ".lock")
    try:
        acquire_single_instance_lock(lock)
    finally:
        lock.close()

    # A pid that cannot be running: the kernel's maximum pid plus one.
    write_pid_file(tmp_path / "router.pid", pid=2**22)

    again = open_lock_file(tmp_path / ".lock")
    try:
        acquire_single_instance_lock(again)
    finally:
        again.close()


def test_a_lock_from_a_live_process_is_not_reaped(tmp_path):
    """The pidfile must not unlock a lock a live process still holds."""
    first = open_lock_file(tmp_path / ".lock")
    second = open_lock_file(tmp_path / ".lock")
    try:
        acquire_single_instance_lock(first)
        write_pid_file(tmp_path / "router.pid", pid=os.getpid())
        with pytest.raises(SingleInstanceError):
            acquire_single_instance_lock(second)
    finally:
        first.close()
        second.close()


def test_the_pidfile_carries_the_pid_and_the_time(tmp_path):
    path = tmp_path / "router.pid"
    write_pid_file(path, pid=4242)
    body = path.read_text()
    assert body.startswith("4242:")
    assert body.endswith("\n")
    pid, _, seconds = body.strip().partition(":")
    assert pid == "4242"
    assert int(seconds) <= int(time.time())
