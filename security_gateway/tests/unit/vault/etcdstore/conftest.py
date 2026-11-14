"""The fake etcd the store's unit tests run against.

A real etcd is reachable — ``docs/ETCD_CLIENT_CONTRACT.md`` says how —
but these tests run against the fake below, which implements the same
seam as the real client and — the part that matters — reproduces etcd's
compare-and-swap semantics faithfully:

* a write under ``mod(key) == N`` succeeds only when the stored
  modification revision is ``N``;
* it leaves the stored value **untouched** when the comparison fails and
  reports ``succeeded=False``;
* a ``create(key) == 0`` comparison succeeds only when the key is absent.

That last behaviour is the one the cluster's handover depends on, and it
is the one a hand-written fake is most likely to get wrong: a fake that
answers "the comparison holds" for every comparison turns every
optimistic lock in the system off, and the tests that are supposed to
catch that pass anyway.
"""

from __future__ import annotations

from typing import Callable, Sequence

import pytest
from security_gateway.vault.etcdstore.store import (
    Compare,
    DeleteOp,
    KVValue,
    Operation,
    PutOp,
    Store,
    TxnResult,
)


def _compare_holds(actual: int | bytes, op: str, expected: int | bytes) -> bool:
    """Evaluate one comparison the way etcd does."""
    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == ">":
        return actual > expected
    if op == "<":
        return actual < expected
    if op == ">=":
        return actual >= expected
    if op == "<=":
        return actual <= expected
    raise ValueError(f"unknown comparison operator {op!r}")


def _encode(key: str) -> bytes:
    return key.encode("utf-8", "surrogateescape")


class FakeKV:
    """An in-memory etcd with real compare-and-swap semantics."""

    def __init__(self) -> None:
        self._values: dict[str, bytes] = {}
        self._mod: dict[str, int] = {}
        self._create: dict[str, int] = {}
        self._version: dict[str, int] = {}
        self._revision = 0
        #: Every write that went through the seam, for assertions.
        self.puts: list[tuple[str, bytes]] = []
        #: Every delete that went through the seam, for assertions.
        self.deletes: list[str] = []
        #: Every transaction that went through the seam, for assertions.
        self.transactions: list[tuple[list[Compare], list[Operation]]] = []

    # -- what a test needs to arrange ------------------------------------

    @property
    def revision(self) -> int:
        """The current cluster revision."""
        return self._revision

    def seed(self, key: str, value: bytes) -> int:
        """Write a value the way an earlier writer would have.

        It is how a test arranges "somebody else got there first" without
        going through the seam under test.
        """
        return self._write(key, value)

    def stored(self, key: str) -> bytes | None:
        """The value currently stored under ``key``."""
        return self._values.get(key)

    def stored_revision(self, key: str) -> int:
        """The modification revision currently stored under ``key``."""
        return self._mod.get(key, 0)

    # -- the seam ---------------------------------------------------------

    def get(self, key: str) -> KVValue | None:
        """Get."""
        if key not in self._values:
            return None
        return self._value_of(key)

    def get_range(
        self,
        range_start: str,
        range_end: str | None,
        limit: int = 0,
    ) -> tuple[int, list[KVValue]]:
        """Get range."""
        start = _encode(range_start)
        end = _encode(range_end) if range_end is not None else None
        keys = sorted(
            key
            for key in self._values
            if _encode(key) >= start and (end is None or _encode(key) < end)
        )
        out: list[KVValue] = []
        for key in keys:
            out.append(self._value_of(key))
            if limit > 0 and len(out) >= limit:
                break
        return self._revision, out

    def put(self, key: str, value: bytes) -> int:
        """Put."""
        self.puts.append((key, value))
        return self._write(key, value)

    def delete(self, key: str) -> int:
        """Delete."""
        self.deletes.append(key)
        self._revision += 1
        self._values.pop(key, None)
        self._mod.pop(key, None)
        self._create.pop(key, None)
        self._version.pop(key, None)
        return self._revision

    def transaction(
        self,
        compare: Sequence[Compare],
        success: Sequence[Operation],
        failure: Sequence[Operation] = (),
    ) -> TxnResult:
        """Transaction."""
        self.transactions.append((list(compare), list(success)))
        if not all(self._holds(c) for c in compare):
            # The comparison did not hold: nothing is written, and the
            # caller is told so by the verdict. The revision does not
            # move either.
            return TxnResult(succeeded=False, revision=self._revision)
        for op in success:
            if isinstance(op, PutOp):
                self._write(op.key, op.value)
            elif isinstance(op, DeleteOp):
                self.delete(op.key)
            else:  # pragma: no cover - the seam has no other operation
                raise TypeError(f"unknown operation {type(op).__name__}")
        return TxnResult(succeeded=True, revision=self._revision)

    # -- internals --------------------------------------------------------

    def _write(self, key: str, value: bytes) -> int:
        self._revision += 1
        self._values[key] = value
        self._mod[key] = self._revision
        if key not in self._create:
            self._create[key] = self._revision
        self._version[key] = self._version.get(key, 0) + 1
        return self._revision

    def _value_of(self, key: str) -> KVValue:
        return KVValue(
            key=_encode(key),
            value=self._values[key],
            mod_revision=self._mod.get(key, 0),
            create_revision=self._create.get(key, 0),
            version=self._version.get(key, 0),
            lease=0,
        )

    def _holds(self, compare: Compare) -> bool:
        if compare.target == "create":
            return _compare_holds(
                self._create.get(compare.key, 0), compare.op, int(compare.value)
            )
        if compare.target == "mod":
            return _compare_holds(
                self._mod.get(compare.key, 0), compare.op, int(compare.value)
            )
        if compare.target == "version":
            return _compare_holds(
                self._version.get(compare.key, 0), compare.op, int(compare.value)
            )
        if compare.target == "value":
            actual = self._values.get(compare.key, b"")
            expected = compare.value
            if isinstance(expected, str):
                expected = expected.encode("utf-8")
            return _compare_holds(actual, compare.op, bytes(expected))
        raise ValueError(f"unknown compare target {compare.target!r}")


@pytest.fixture
def fake_kv() -> FakeKV:
    """An empty etcd."""
    return FakeKV()


@pytest.fixture
def make_fake_kv() -> Callable[[], FakeKV]:
    """A factory for extra fakes, for tests that need two."""

    def _make() -> FakeKV:
        return FakeKV()

    return _make


@pytest.fixture
def ns() -> str:
    """The namespace the tests use."""
    return "prod"


@pytest.fixture
def store(fake_kv: FakeKV, ns: str) -> Store:
    """A store over the fake."""
    return Store(kv=fake_kv, ns=ns)
