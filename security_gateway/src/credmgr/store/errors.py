"""The errors this package raises.

The distinction is load-bearing: the admin layer turns these into HTTP
status codes, and a caller that cannot tell "absent" from "lost a race"
cannot decide whether to retry, re-read, or give up.

The hierarchy is rooted at :class:`StoreError` and carries a
:class:`~security_gateway.platform.errs.Code`, so the service-wide
``code_of(exc)`` reads the right code off a store error.
"""

from __future__ import annotations

import sqlite3

from security_gateway.platform.errs import Code, ServiceError

__all__ = [
    "ClosedError",
    "ConflictError",
    "InvalidError",
    "KeyMetadataEmptyError",
    "NotFoundError",
    "PhaseADecryptError",
    "SourceIdentityConflictError",
    "StoreError",
    "SyncStateEmptyError",
    "UniquenessConflictError",
    "is_uniqueness_constraint_for",
]


class StoreError(ServiceError):
    """The base of every error this package raises.

    It is a :class:`~security_gateway.platform.errs.ServiceError` so that the
    service-wide ``code_of`` helper reads a store error's code.
    """

    def __init__(
        self,
        message: str,
        *,
        op: str = "store",
        code: Code = Code.INTERNAL,
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(code, op, message, cause)


class NotFoundError(StoreError):
    """No row matches.

    It never means "the row exists but cannot be read" — that condition
    has its own type further up the stack.
    """

    def __init__(self, message: str, **kw: object) -> None:
        kw.setdefault("code", Code.NOT_FOUND)
        super().__init__(message, **kw)  # type: ignore[arg-type]


class ConflictError(StoreError):
    """A write collides with the state already stored.

    Either the optimistic ``row_version`` guard rejected the write, or a
    uniqueness constraint rejected it.
    """

    def __init__(self, message: str, **kw: object) -> None:
        kw.setdefault("code", Code.CONFLICT)
        super().__init__(message, **kw)  # type: ignore[arg-type]


class UniquenessConflictError(ConflictError):
    """A uniqueness constraint rejected the write.

    The ``column`` attribute names the constraint that fired. The
    credentials table has two uniqueness dimensions — the ``(user_id,
    api_base, key_tag)`` triple and ``proxy_key`` — and the callers need
    to tell them apart: a ``proxy_key`` collision is transient, a triple
    collision is a genuine duplicate.
    """

    def __init__(self, message: str, column: str = "", **kw: object) -> None:
        super().__init__(message, **kw)
        self.column = column


class InvalidError(StoreError):
    """The request, the argument or the stored bytes are not valid.

    Nothing about the stored state can be fixed by retrying; the caller
    has to change what it sent.
    """

    def __init__(self, message: str, **kw: object) -> None:
        kw.setdefault("code", Code.BAD_REQUEST)
        super().__init__(message, **kw)  # type: ignore[arg-type]


class ClosedError(StoreError):
    """The store has been closed.

    Distinct from a failed read: there is nothing left to read from, and
    the caller has to reopen the store rather than retry the query.
    """

    def __init__(self, message: str = "the store is closed", **kw: object) -> None:
        super().__init__(message, **kw)


class PhaseADecryptError(StoreError):
    """A row's ciphertext could not be decrypted during Phase A.

    This means either data corruption on disk or a DEK that has been
    rolled forward past this row's ciphertext version. Neither is
    recoverable in-process: the caller must log the error and exit.
    """


class KeyMetadataEmptyError(NotFoundError):
    """The ``key_metadata`` table holds no row.

    Its own type so that "this store has never been initialised" can be
    told apart from "that credential does not exist".
    """


class SyncStateEmptyError(NotFoundError):
    """The ``sync_state`` singleton row is absent.

    The schema bootstrap seeds it, so this only fires on a database
    created before ``sync_state`` existed.
    """


class SourceIdentityConflictError(StoreError):
    """Two source rows claimed the same ``(user_id, api_base, key_tag)``.

    The authority is inconsistent — the admin API has always refused to
    create that pair — so the error says so.
    """

    def __init__(self, message: str, **kw: object) -> None:
        kw.setdefault("code", Code.CONFLICT)
        super().__init__(message, **kw)  # type: ignore[arg-type]


def is_uniqueness_constraint_for(exc: BaseException, column: str) -> bool:
    """Report whether ``exc`` is a uniqueness violation on ``column``."""
    if not isinstance(exc, sqlite3.IntegrityError):
        return False
    message = str(exc)
    if "UNIQUE constraint failed" not in message and "PRIMARY KEY" not in message:
        return False
    return column in message
