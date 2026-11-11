"""The seam between the store and whatever holds the records.

``KV`` and ``Lease`` are the two protocols the store is written against.
The value types — ``KVValue``, ``Compare``, ``PutOp``, ``DeleteOp`` and
``TxnResult`` — are what travels across that seam, so both sides agree
on them by construction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, Sequence, runtime_checkable


@dataclass(frozen=True)
class KVValue:
    """One key-value pair as etcd reports it.

    The revisions are the metadata etcd keeps beside the value: the
    create revision is 0 for a key that does not exist, and the mod
    revision is the token every compare-and-swap compares against.
    """

    key: bytes = b""
    value: bytes = b""
    mod_revision: int = 0
    create_revision: int = 0
    version: int = 0
    lease: int = 0


@dataclass(frozen=True)
class Compare:
    """One condition of a transaction.

    The targets are the four etcd compares:
    """

    target: str
    key: str
    op: str = "=="
    value: int | bytes = 0


@dataclass(frozen=True)
class PutOp:
    """A write inside a transaction."""

    key: str
    value: bytes


@dataclass(frozen=True)
class DeleteOp:
    """A delete inside a transaction."""

    key: str


Operation = PutOp | DeleteOp


@dataclass(frozen=True)
class TxnResult:
    """The verdict of a transaction.

    ``succeeded`` is the verdict and nothing else is: it is ``False``
    when the comparison did not hold, and in that case **nothing was
    written**. ``revision`` is the response header revision of the
    committed transaction, which is the new ModRevision of a key the
    transaction wrote.
    """

    succeeded: bool
    revision: int = 0


@runtime_checkable
class KV(Protocol):
    """The key-value seam the package is written against.

    The shape follows the ``etcd3`` client: the Python client takes the
    whole transaction as arguments and returns the verdict, which is
    exactly what :meth:`transaction` does here.
    """

    def get(self, key: str) -> KVValue | None:
        """Read one key, or ``None`` when it does not exist."""
        ...

    def get_range(
        self,
        range_start: str,
        range_end: str | None,
        limit: int = 0,
    ) -> tuple[int, list[KVValue]]:
        """Read a range of keys."""
        ...

    def put(self, key: str, value: bytes, lease: int = 0) -> int:
        """Write a key and return the revision the write landed at."""
        ...

    def delete(self, key: str) -> int:
        """Delete a key and return the revision the delete landed at."""
        ...

    def transaction(
        self,
        compare: Sequence[Compare],
        success: Sequence[Operation],
        failure: Sequence[Operation] = (),
    ) -> TxnResult:
        """Run a transaction and report its verdict.

        When the comparison does not hold, nothing is written and the
        result's ``succeeded`` is ``False``. That is not an error and it
        must not be reported as one.

        The failure branch is part of the seam because the client walks
        it unconditionally: it is passed as an empty list, never as
        ``None``.
        """
        ...


@runtime_checkable
class Lease(Protocol):
    """The lease seam.

    Three verbs: ``grant``, ``revoke`` and ``keepalive`` — ``keepalive``
    sends exactly one keepalive and returns the granted TTL.
    """

    @property
    def lease_id(self) -> int:
        """The lease id."""
        ...

    def grant(self) -> int:
        """Create the lease and return its id."""
        ...

    def revoke(self) -> Any:
        """Revoke the lease."""
        ...

    def keepalive(self) -> Any:
        """Send one keepalive and return the granted TTL."""
        ...


def compare_create(key: str) -> Compare:
    """Succeeds only when the key has never been written."""
    return Compare(target="create", key=key, op="==", value=0)


def compare_mod(key: str, revision: int) -> Compare:
    """Succeeds only when the key's modification revision is ``revision``."""
    return Compare(target="mod", key=key, op="==", value=int(revision))


def compare_value(key: str, value: bytes) -> Compare:
    """Succeeds only when the stored bytes equal ``value``."""
    return Compare(target="value", key=key, op="==", value=bytes(value))


def compare_version(key: str, version: int) -> Compare:
    """Succeeds only when the key's creation version is ``version``."""
    return Compare(target="version", key=key, op="==", value=int(version))
