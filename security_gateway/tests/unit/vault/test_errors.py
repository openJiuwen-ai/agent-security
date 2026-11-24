"""The vault's error messages, pinned.

The Go's counterpart is ``pkg/vault/errors_test.go``.  The two files pin
the **same strings**: the operator reads one side's log and then the
other's, and the two lines have to read the same.  A diff of the two files
is the check that they still agree.

The mechanism the Python uses to get there is the one the spec describes
(``docs/vault-multi-process.md`` §14.1, 「消息的对称性怎么落地」): the
exception class carries the Go's sentinel text, the raise site passes the
bare detail, and a detail that is already a whole message is used as it is.
"""

from __future__ import annotations

import sqlite3

import pytest

from security_gateway.vault import store as store_module
from security_gateway.vault.errors import (
    ClosedError,
    ConflictError,
    InvalidRecordError,
    InvalidSchemaError,
    KeyMismatchError,
    NotFoundError,
    RotationInProgressError,
    SchemaMismatchError,
    StaleGenerationError,
    UndecryptableError,
    UnsupportedError,
    VaultError,
)
from security_gateway.vault.store import BUSY_WAIT_BUDGET_SECONDS, format_duration


def test_the_sentinel_texts_are_pinned():
    """Every sentinel's text is the one the Go prints."""
    cases = [
        (NotFoundError, "vault: record not found"),
        (ConflictError, "vault: conflict"),
        (SchemaMismatchError, "vault: schema mismatch"),
        (KeyMismatchError, "vault: key material does not match this store"),
        (UndecryptableError, "vault: record exists but cannot be decrypted"),
        (
            StaleGenerationError,
            "vault: record is under a generation this store does not hold",
        ),
        (RotationInProgressError, "vault: rotation already in progress"),
        (ClosedError, "vault: closed"),
        (InvalidSchemaError, "vault: invalid schema"),
        (UnsupportedError, "vault: operation not supported by this store"),
        (InvalidRecordError, "vault: invalid record"),
    ]
    for cls, want in cases:
        assert str(cls()) == want, f"{cls.__name__}'s text is not the Go's"


def test_the_composed_messages_are_pinned():
    """The lines an operator reads are the lines the Go prints.

    The quoting matters as much as the words: the Go's ``%q`` writes
    ``"cred-1"``, and this side has to write the same thing rather than
    Python's own ``'cred-1'``.
    """
    cases = [
        (
            NotFoundError('"cred-1"'),
            'vault: record not found: "cred-1"',
        ),
        (
            ConflictError('writing record "cred-1" affected no rows'),
            'vault: conflict: writing record "cred-1" affected no rows',
        ),
        (
            SchemaMismatchError(
                'record "cred-1" was written with schema v1, '
                "which this store does not know"
            ),
            'vault: schema mismatch: record "cred-1" was written with schema v1, '
            "which this store does not know",
        ),
        (
            KeyMismatchError("the store has no key metadata"),
            "vault: key material does not match this store: "
            "the store has no key metadata",
        ),
        (
            UndecryptableError('record "cred-1" field "api_key": bad'),
            "vault: record exists but cannot be decrypted: "
            'record "cred-1" field "api_key": bad',
        ),
        (
            StaleGenerationError(
                'record "cred-1" is under generation 3, which this store does '
                "not hold (it holds [1 2])"
            ),
            "vault: record is under a generation this store does not hold: "
            'record "cred-1" is under generation 3, which this store does not '
            "hold (it holds [1 2])",
        ),
        (
            RotationInProgressError("a rotation to v3 is already in progress"),
            "vault: rotation already in progress: "
            "a rotation to v3 is already in progress",
        ),
        (
            ClosedError("the store has no key"),
            "vault: closed: the store has no key",
        ),
        (
            InvalidSchemaError('field "api_key": duplicate name'),
            'vault: invalid schema: field "api_key": duplicate name',
        ),
        (
            InvalidRecordError("id is empty"),
            "vault: invalid record: id is empty",
        ),
        (
            UnsupportedError("the takeover applies to a local store"),
            "vault: operation not supported by this store: "
            "the takeover applies to a local store",
        ),
    ]
    for exc, want in cases:
        assert str(exc) == want, f"{type(exc).__name__}'s message is not the Go's"


def test_the_go_s_own_plain_errors_are_copied_verbatim():
    """The Go's plain errors carry no sentinel, so their text is the whole.

    Five of them do not even carry the ``vault: `` prefix.  The class is
    still the one the site uses — it carries the wire code — but the text
    is not rewritten, and ``whole=True`` is what says so.
    """
    exc = UndecryptableError(
        "the ciphertext does not open with the key for generation 3: boom",
        whole=True,
    )
    assert (
        str(exc) == "the ciphertext does not open with the key for generation 3: boom"
    )

    exc = ClosedError("the store has no key", whole=True)
    assert str(exc) == "the store has no key"


def test_a_detail_that_is_already_a_whole_message_is_used_as_it_is():
    """A detail that starts with ``vault: `` is a whole message.

    That is where the Go raises a plain error: it has no sentinel to wrap,
    so the text it prints is the text it wrote.
    """
    exc = KeyMismatchError('vault: unknown crypto mode "sm4"')
    assert str(exc) == 'vault: unknown crypto mode "sm4"'


def test_the_busy_wait_names_its_budget_the_go_way(monkeypatch):
    """The Go's ``time.Duration`` prints as ``30s`` under ``%s``.

    A budget that reads ``30.0s`` on one side and ``30s`` on the other is
    two different looking lines for the same event.
    """
    assert format_duration(BUSY_WAIT_BUDGET_SECONDS) == "30s"

    monkeypatch.setattr(store_module, "BUSY_WAIT_BUDGET_SECONDS", 0.01)

    def busy():
        raise sqlite3.OperationalError("database is locked")

    with pytest.raises(VaultError) as excinfo:
        store_module.run_with_busy_retry(busy)

    assert "the store stayed busy for 10ms: database is locked" in str(excinfo.value)


def test_the_busy_wait_can_be_called_off(monkeypatch):
    """The wait is cancellable, like the Go's context.

    The Go's ``runWithBusyRetry(ctx, …)`` gives up as soon as the context
    is done.  The Python's equivalent is a callable that returns the error
    to raise, and a rotation that has to stop does not have to wait out
    the whole budget.
    """
    monkeypatch.setattr(store_module, "BUSY_WAIT_BUDGET_SECONDS", 30.0)

    calls = {"n": 0}

    def busy():
        calls["n"] += 1
        raise sqlite3.OperationalError("database is locked")

    def cancel():
        return VaultError("vault: the rotation was cancelled")

    with pytest.raises(VaultError) as excinfo:
        store_module.run_with_busy_retry(busy, cancel)

    assert str(excinfo.value) == "vault: the rotation was cancelled"
    assert calls["n"] == 1, "the wait kept going after it was called off"
