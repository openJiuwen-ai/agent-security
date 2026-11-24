"""The revision a transaction reports is unwrapped from the client response."""

from __future__ import annotations

from security_gateway.vault.etcdstore.etcd3 import transaction_revision


class Header:
    """The metadata a protobuf response carries."""

    def __init__(self, revision: int) -> None:
        self.revision = revision


class PutResponse:
    """A put response: the shape the client nests inside an operation."""

    def __init__(self, revision: int) -> None:
        self.header = Header(revision)


class ResponseOp:
    """One operation's response; the oneof member is ``response_put``."""

    def __init__(self, revision: int) -> None:
        self.response_put = PutResponse(revision)


class TxnResponse:
    """A committed transaction: a list of operation responses."""

    def __init__(self, revision: int) -> None:
        self.responses = [ResponseOp(revision)]


def test_the_revision_is_read_from_the_operation_response() -> None:
    """The outer response has no header of its own."""
    assert transaction_revision(TxnResponse(42)) == 42


def test_a_transaction_without_operations_reports_zero() -> None:
    """Nothing ran, so there is no revision to report."""

    class Empty:
        """A transaction that matched nothing."""

        responses: list[object] = []

    assert transaction_revision(Empty()) == 0


class _EmptyRangeClient:
    """A client whose range is empty but whose header has a revision."""

    @staticmethod
    def get_range(start: str, end: str) -> list[object]:
        """The keys in the range: none."""
        return []

    @staticmethod
    def get_range_response(start: str, end: str) -> PutResponse:
        """The range response, whose header carries the snapshot revision."""
        return PutResponse(17)


def test_an_empty_range_reports_the_snapshot_revision() -> None:
    """A list that found nothing still has a revision to watch from."""
    from security_gateway.vault.etcdstore.etcd3 import Etcd3KV

    revision, values = Etcd3KV(_EmptyRangeClient()).get_range("a", "b")

    assert values == []
    assert revision == 17


class _IntTtlClient:
    """A client whose keepalive answers an integer TTL."""

    @staticmethod
    def refresh_lease(lease_id: int):
        """Answer one keepalive."""
        yield 30


def test_a_keepalive_accepts_an_integer_ttl() -> None:
    """Some clients spell the TTL as a bare integer."""
    from security_gateway.vault.etcdstore.etcd3 import Etcd3Lease

    assert Etcd3Lease(_IntTtlClient(), 30, 5).keepalive() == 30
