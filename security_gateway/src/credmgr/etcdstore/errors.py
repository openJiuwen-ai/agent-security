"""The errors this package raises.

The package owns its own sentinels rather than reusing the local store's
``ConflictError`` / ``NotFoundError`` because the wire-level semantics of
etcd are not the same as the local ones. The local store's conflict is a
``row_version`` guard in SQLite; this one is a ModRevision compare in etcd,
and the local ``NotFoundError`` means "no row matches" while this one also
covers "the delete did nothing" — a distinction the operator needs when
asking whether a credential was really removed.

The translation into HTTP status codes belongs to the admin handler, not
here, so that this package's contract does not leak into the transport.

Every sentinel carries a :class:`~security_gateway.platform.errs.Code` so the
service-wide ``code_of`` helper reads the right code off it without this
package knowing anything about HTTP.
"""

from __future__ import annotations

from security_gateway.platform.errs import Code, ServiceError

__all__ = [
    "CompactedError",
    "ConflictError",
    "EtcdStoreError",
    "InvalidValueError",
    "NotFoundError",
    "RotationHeldError",
    "remap_compacted",
]


class EtcdStoreError(ServiceError):
    """The base of every error this package raises.

    It is a :class:`~security_gateway.platform.errs.ServiceError` so that
    ``code_of`` reads a code off it, but rooted here rather than on the
    local store's error hierarchy: the two layers disagree about what
    "conflict" means.
    """

    #: The code the admin layer maps onto an HTTP status.
    default_code: Code = Code.INTERNAL

    def __init__(
        self,
        message: str,
        *,
        op: str = "etcdstore",
        cause: BaseException | None = None,
    ) -> None:
        super().__init__(self.default_code, op, message, cause)


class ConflictError(EtcdStoreError):
    """``ErrConflict`` — a compare-and-swap comparison did not hold.

    This is *not* a transport failure. It means the comparison in the
    transaction was false, so the value was **not** written, and the
    caller is expected to re-read, merge, and retry.
    """

    default_code = Code.CONFLICT

    def __init__(
        self,
        message: str = "etcdstore: CAS conflict",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class NotFoundError(EtcdStoreError):
    """``ErrNotFound`` — the requested key does not exist.

    ``delete_entry_cas`` on a key that is already gone raises this
    rather than reporting success: a delete that did nothing must not
    report that it deleted something.
    """

    default_code = Code.NOT_FOUND

    def __init__(
        self,
        message: str = "etcdstore: not found",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class CompactedError(EtcdStoreError):
    """``ErrCompacted`` — the requested revision has been compacted away.

    The sentinel must be detectable so the watcher can do a full re-LIST
    instead of waiting for events that no longer exist in the log. Never
    swallow it in error translation: the code it carries is a generic
    one, but the *type* is what callers detect, and a remap onto a
    generic error would throw that away.
    """

    default_code = Code.INTERNAL

    def __init__(
        self,
        message: str = "etcdstore: requested revision is compacted",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class RotationHeldError(EtcdStoreError):
    """``ErrRotationHeld`` — another node already holds the rotation lock.

    It is distinct from :class:`ConflictError` so that callers can map
    "lock contended, retry later" without conflating it with "credential
    CAS conflict, re-read and merge". The current holder and TTL are
    obtained by a follow-up read of the rotation key.
    """

    default_code = Code.CONFLICT

    def __init__(
        self,
        message: str = "etcdstore: rotation lock held by another holder",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


class InvalidValueError(EtcdStoreError):
    """``ErrInvalidValue`` — a stored value does not fit the typed model.

    An empty value, malformed JSON, or a field of the wrong type. It indicates a wire-contract mistake rather than a
    runtime or CAS condition, and no amount of retrying fixes it.
    """

    default_code = Code.INTERNAL

    def __init__(
        self,
        message: str = "etcdstore: invalid stored value",
        **kw: object,
    ) -> None:
        super().__init__(message, **kw)  # type: ignore[arg-type]


def _looks_compacted(exc: BaseException) -> bool:
    """Report whether ``exc`` is etcd's "revision has been compacted" error.

    The client's own exception is recognised by its name, which is the
    only reliable signal. The message is only a fallback, and it is
    looked for as a whole word: "compact" on its own also turns up in
    messages that have nothing to do with a revision being dropped.
    """
    for klass in type(exc).__mro__:
        if "compact" in klass.__name__.lower():
            return True
    text = str(exc).lower()
    return "compacted" in text


def remap_compacted(exc: BaseException) -> BaseException:
    """Return ``exc`` remapped onto :class:`CompactedError` when it is one."""
    if isinstance(exc, CompactedError):
        return exc
    if _looks_compacted(exc):
        return CompactedError("etcdstore: requested revision is compacted", cause=exc)
    return exc
