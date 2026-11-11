"""The real etcd3 client behind the store's seam.

Everything here speaks the etcd3 protocol and nothing else speaks it.
The store is written against :mod:`security_gateway.vault.etcdstore.protocol`,
so the etcd3 client can be swapped for a fake without the store noticing.
"""

from __future__ import annotations

import threading
from typing import Any, Iterator, Sequence

from .protocol import Compare, DeleteOp, KVValue, Lease, Operation, PutOp, TxnResult


def split_endpoint(endpoint: str, default_port: int = 2379) -> tuple[str, int]:
    """The host and the port of an etcd endpoint.

    Two spellings are in use, and both have to work:

    * ``host:port`` — the form the client library takes, and the form the
      vault's own API takes;
    * ``http(s)://host:port`` — the form the operator's configuration file
      demands, because the configuration layer validates it as a URL.

    The dialer used to split on the first colon, which turned
    ``http://127.0.0.1:32379`` into the host ``http`` and the port
    ``//127.0.0.1:32379`` — a ``ValueError`` at start-up for every
    deployment that configured an endpoint the way its configuration file
    says to.
    """
    text = (endpoint or "").strip()
    for scheme in ("http://", "https://"):
        if text.startswith(scheme):
            scheme_length = len(scheme)
            text = text[scheme_length:]
            break
    # A path is not part of an endpoint; a URL that carries one is a URL
    # the client library would not take either.
    text = text.split("/", 1)[0]
    host, _separator, port = text.rpartition(":")
    if not host:
        # No colon at all: the whole thing is the host.
        host, port = text, ""
    number = default_port
    if port:
        try:
            number = int(port)
        except ValueError as exc:
            raise ValueError(
                f"etcdstore: {endpoint!r} is not a host and a port"
            ) from exc
    if not host:
        raise ValueError(f"etcdstore: {endpoint!r} has no host")
    return host, number


def tls_client_kwargs(ca_file: str, cert_file: str, key_file: str) -> dict[str, Any]:
    """The keyword arguments the etcd client takes for its TLS material."""
    return {
        "ca_cert": ca_file,
        "cert_cert": cert_file,
        "cert_key": key_file,
    }


def build_etcd_client(
    host: str = "127.0.0.1",
    port: int = 2379,
    *,
    timeout: float = 5.0,
    **kwargs: Any,
) -> Any:
    """Build the real etcd client."""
    try:
        import etcd3  # noqa: PLC0415 - the etcd extra is optional
    except ImportError as exc:
        raise ImportError(
            "the etcd client is an optional extra; install it with 'pip install security_gateway[etcd]'"
        ) from exc
    return etcd3.Etcd3Client(host=host, port=port, timeout=timeout, **kwargs)


def _header_revision(response: object) -> int:
    """The revision a put or delete response landed at."""
    header = getattr(response, "header", None)
    revision = getattr(header, "revision", None)
    if isinstance(revision, int):
        return revision
    revision = getattr(response, "revision", None)
    if isinstance(revision, int):
        return revision
    return 0


def transaction_revision(response: object) -> int:
    """The revision a committed transaction landed at.

    The client answers a transaction with one ``TxnResponse``: the header
    carries the revision, and so does the response of each operation it
    ran. The operation entries are ``ResponseOp`` messages whose oneof is
    named ``response_put`` / ``response_range`` / ``response_delete`` /
    ``response_txn``, so each spelling is tried. A revision that reads
    back as ``0`` would be handed to the caller as a compare-and-swap
    token that can never match, which turns every later write into a
    permanent conflict.
    """
    revision = _header_revision(response)
    if revision:
        return revision
    inner = getattr(response, "response", None)
    if inner is not None:
        revision = _header_revision(inner)
        if revision:
            return revision
    # The client answers ``(succeeded, responses)``: the second half is a
    # list of ``ResponseOp``, not a transaction message of its own.
    if isinstance(response, (list, tuple)):
        items = response
    else:
        items = getattr(response, "responses", ()) or ()
    for item in items:
        candidates = [item, getattr(item, "response", None)]
        for candidate in candidates:
            if candidate is None:
                continue
            revision = _header_revision(candidate)
            if revision:
                return revision
            for name in (
                "response_put",
                "response_range",
                "response_delete",
                "response_txn",
                "put_response",
                "delete_response",
                "range_response",
            ):
                operation = getattr(candidate, name, None)
                if operation is None:
                    continue
                revision = _header_revision(operation)
                if revision:
                    return revision
    return 0


def _to_key_value(meta: object, value: bytes | None = None) -> KVValue:
    """Build a :class:`KVValue` from the client's metadata object."""
    raw_key = getattr(meta, "key", b"")
    if isinstance(raw_key, str):
        raw_key = raw_key.encode("utf-8", "surrogateescape")
    if value is None:
        value = getattr(meta, "value", b"")
    if isinstance(value, str):
        value = value.encode("utf-8")
    return KVValue(
        key=bytes(raw_key),
        value=bytes(value),
        mod_revision=_revision_of(meta, "mod_revision", "modified"),
        create_revision=_revision_of(meta, "create_revision", "created"),
        version=int(getattr(meta, "version", 0) or 0),
        # The client's metadata names the lease "lease_id"; the fake's
        # names it "lease".
        lease=int(getattr(meta, "lease_id", None) or getattr(meta, "lease", 0) or 0),
    )


def _revision_of(meta: object, *names: str) -> int:
    """The revision an attribute of the client's metadata carries.

    The protobuf calls it ``mod_revision`` and ``create_revision``; the
    client's own metadata object calls the same numbers ``modified`` and
    ``created``. A revision that reads back as ``0`` is a compare-and-swap
    token that can never match, so both spellings are read.
    """
    for name in names:
        value = getattr(meta, name, None)
        if value is None:
            continue
        try:
            return int(value)
        except (TypeError, ValueError):
            continue
    return 0


def _to_etcd_compare(transaction: Any, compare: Compare) -> Any:
    """Translate a comparison into the client's own builder.

    The seam carries an ``op`` field, and every comparison this package
    builds is an equality test. Any other operator would be silently
    downgraded to ``==``, which turns a lost optimistic lock into a
    permanent conflict, so it is rejected instead.
    """
    if compare.op != "==":
        raise ValueError(f"etcdstore: unsupported compare op {compare.op!r}")
    if compare.target == "create":
        return transaction.Create(compare.key) == int(compare.value)
    if compare.target == "mod":
        return transaction.Mod(compare.key) == int(compare.value)
    if compare.target == "version":
        return transaction.Version(compare.key) == int(compare.value)
    if compare.target == "value":
        expected = compare.value
        if isinstance(expected, str):
            expected = expected.encode("utf-8")
        return transaction.Value(compare.key) == bytes(expected)
    raise ValueError(f"etcdstore: unknown compare target {compare.target!r}")


def _is_lease_put(operation: Operation) -> bool:
    """Report whether the operation is the leased put the cluster half defines.

    The cluster half is a separate module, and it may not be in the tree
    at all, so the import is soft: without it there is no leased put to
    recognise, and an ordinary put stays an ordinary put.
    """
    try:
        from .cluster import LeasePutOp  # noqa: PLC0415 - the cluster half imports this one
    except ImportError:
        return False
    return isinstance(operation, LeasePutOp)


def _to_etcd_operation(transaction: Any, operation: Operation) -> Any:
    """Translate an operation into the client's own builder."""
    if _is_lease_put(operation):
        return transaction.Put(operation.key, operation.value, lease=operation.lease)
    if isinstance(operation, PutOp):
        return transaction.Put(operation.key, operation.value)
    if isinstance(operation, DeleteOp):
        return transaction.Delete(operation.key)
    raise ValueError(f"etcdstore: unknown operation {type(operation).__name__}")


class Etcd3Lease:
    """A lease on a live etcd, behind the :class:`Lease` seam.

    The client grants on construction and keeps alive through
    ``refresh``; the seam is a handle that is granted, then revoked,
    then kept alive. This class is the translation.
    """

    def __init__(self, client: Any, ttl_seconds: int, lease_id: int = 0) -> None:
        self._client = client
        self._ttl = int(ttl_seconds)
        self._id = int(lease_id)

    @property
    def lease_id(self) -> int:
        """The lease id."""
        return self._id

    def grant(self) -> int:
        """Create the lease and return its id."""
        lease = self._client.lease(self._ttl, self._id or None)
        self._id = int(lease.id)
        return self._id

    def revoke(self) -> Any:
        """Revoke the lease."""
        return self._client.revoke_lease(self._id)

    def keepalive(self) -> int:
        """Send one keepalive and return the granted TTL.

        The client hands back a generator that stays open for as long as
        the lease is refreshed, so only its first response is read and
        the generator is closed again: draining it would block forever.
        """
        responses = self._client.refresh_lease(self._id)
        try:
            response = next(iter(responses))
        except StopIteration:
            return 0
        finally:
            close = getattr(responses, "close", None)
            if close is not None:
                close()
        if isinstance(response, int):
            return response
        return int(getattr(response, "TTL", 0) or 0)


class Etcd3Leases:
    """The lease factory over a live ``etcd3`` client.

    It is what the store carries, so that the rotation lock and the
    presence marker can be leased against a real etcd.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    def lease(self, ttl_seconds: int, lease_id: int | None = None) -> Lease:
        """Return a handle onto a lease with the given TTL."""
        return Etcd3Lease(self._client, int(ttl_seconds), int(lease_id or 0))


class Etcd3KV:
    """The real ``etcd3`` client behind the :class:`KV` seam.

    The client is not the seam itself: its comparisons are protobuf
    messages that cannot be built without the library, so the seam
    speaks in plain Python values and this class translates. Everything
    that matters for correctness — the verdict of a transaction —
    crosses the boundary unchanged.
    """

    def __init__(self, client: Any) -> None:
        self._client = client

    @property
    def client(self) -> Any:
        """The wrapped client."""
        return self._client

    def get(self, key: str) -> KVValue | None:
        # The client answers with a (value, metadata) pair, or with
        # (None, None) when the key is not there.  It takes no
        # "metadata=" keyword: the metadata always comes back.
        """Get."""
        value, meta = self._client.get(key)
        if meta is None:
            return None
        return _to_key_value(meta, value)

    def get_range(
        self,
        range_start: str,
        range_end: str | None,
        limit: int = 0,
    ) -> tuple[int, list[KVValue]]:
        """Get range."""
        if range_end is None:
            iterator = self._client.get_prefix(range_start)
        else:
            iterator = self._client.get_range(range_start, range_end)
        values: list[KVValue] = []
        revision = 0
        for pair in iterator:
            # The client answers with (value, metadata) pairs.
            if isinstance(pair, tuple) and len(pair) == 2:
                raw_value, meta = pair
            else:
                raw_value, meta = None, pair
            parsed = _to_key_value(meta, raw_value)
            revision = max(revision, parsed.mod_revision)
            values.append(parsed)
            if limit > 0 and len(values) >= limit:
                break
        # The snapshot revision is the header revision of the range
        # response, which the client's public range call does not
        # surface. The highest modification revision in the range is a
        # lower bound for it, and a lower bound is the safe direction to
        # be wrong in: a watch started from it replays the tail of the
        # snapshot instead of skipping it, and the replay is idempotent.
        if values:
            return revision, values
        # An empty range carries no modification revision, but the
        # snapshot still has one: a watch resumed from 0 would replay
        # the whole keyspace and could miss the window between the list
        # and the watch, so the response header is asked for directly.
        response = getattr(self._client, "get_range_response", None)
        if response is not None:
            revision = _header_revision(response(range_start, range_end))
        return revision, values

    def put(self, key: str, value: bytes, lease: int = 0) -> int:
        # A leased write is a put that carries the lease, and the seam
        # asks for it by name.  The client takes None for "no lease" —
        # a lease id of zero is not a lease.
        """Put."""
        return _header_revision(self._client.put(key, value, lease=lease or None))

    def delete(self, key: str) -> int:
        """Delete."""
        return _header_revision(self._client.delete(key))

    def transaction(
        self,
        compare: Sequence[Compare],
        success: Sequence[Operation],
        failure: Sequence[Operation] = (),
    ) -> TxnResult:
        """Transaction."""
        from etcd3 import transactions  # noqa: PLC0415 - optional extra

        comparisons = [
            _to_etcd_compare(transactions, condition) for condition in compare
        ]
        operations = [
            _to_etcd_operation(transactions, planned_operation)
            for planned_operation in success
        ]
        failure_operations = [
            _to_etcd_operation(transactions, planned_operation)
            for planned_operation in failure
        ]
        # The failure branch is empty on purpose, but it has to be an
        # empty *list*: the client walks it unconditionally, and a None
        # there is a TypeError rather than an empty branch.
        succeeded, responses = self._client.transaction(
            compare=comparisons,
            success=operations,
            failure=failure_operations,
        )
        return TxnResult(
            succeeded=bool(succeeded), revision=transaction_revision(responses)
        )


class Etcd3FailoverClient:
    """A client that moves to the next endpoint when the current one fails.

    ``python-etcd3`` dials one host, so a multi-endpoint configuration
    would otherwise use only the first address and lose the failover the
    etcd client contract promises.  This wrapper keeps one client per
    endpoint, starts at the first working one, and retries an operation
    once per endpoint after a transport error.

    The operations exposed through the ``KV`` seam are safe to repeat:
    reads, puts of the same value, deletes, and compare-and-swap
    transactions.  A watch stream cannot be resumed on another endpoint
    in place, so the wrapper ends it and lets the sync loop reopen it;
    the reopen starts from the last applied revision, which is what makes
    the stream correct across endpoints.
    """

    def __init__(
        self,
        endpoints: Sequence[str],
        *,
        timeout: float = 5.0,
        **kwargs: Any,
    ) -> None:
        self._endpoints = tuple(str(endpoint) for endpoint in endpoints)
        if not self._endpoints:
            raise ValueError("etcdstore: at least one endpoint is required")
        self._timeout = float(timeout or 5.0)
        self._kwargs = dict(kwargs)
        self._lock = threading.Lock()
        self._clients: dict[int, Any] = {}
        self._current = 0

    @property
    def endpoints(self) -> tuple[str, ...]:
        """The configured endpoints, in preference order."""
        return self._endpoints

    def _client_at(self, index: int) -> Any:
        with self._lock:
            client = self._clients.get(index)
            if client is None:
                host, port = split_endpoint(self._endpoints[index])
                client = build_etcd_client(
                    host,
                    port,
                    timeout=self._timeout,
                    **self._kwargs,
                )
                self._clients[index] = client
            return client

    def _mark_failed(self, index: int) -> None:
        with self._lock:
            if self._current == index:
                self._current = (index + 1) % len(self._endpoints)

    def _run(
        self,
        name: str,
        args: tuple[Any, ...],
        kwargs: dict[str, Any],
        *,
        kind: str = "plain",
    ) -> Any:
        with self._lock:
            start = self._current
        last: Exception | None = None
        for offset in range(len(self._endpoints)):
            index = (start + offset) % len(self._endpoints)
            try:
                client = self._client_at(index)
                result = getattr(client, name)(*args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - retried on the next endpoint
                last = exc
                self._mark_failed(index)
                continue
            if kind == "watch":
                return self._wrap_watch(result, index)
            if kind == "range":
                return self._wrap_iterator(result, index)
            return result
        assert last is not None
        raise last

    def _wrap_watch(self, result: Any, index: int) -> Any:
        if isinstance(result, tuple) and len(result) == 2:
            events, cancel = result
            return self._wrap_iterator(events, index), cancel
        return self._wrap_iterator(result, index)

    def _wrap_iterator(self, result: Any, index: int) -> Iterator[Any]:
        def walk() -> Iterator[Any]:
            try:
                yield from result
            except Exception:  # noqa: BLE001 - the next watch reopen takes over
                self._mark_failed(index)
                raise

        if isinstance(result, (list, tuple)):
            return iter(result)
        return walk()

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        kind = (
            "watch"
            if name in ("watch", "watch_prefix")
            else ("range" if name in ("get_prefix", "get_range") else "plain")
        )

        def call(*args: Any, **kwargs: Any) -> Any:
            return self._run(name, args, kwargs, kind=kind)

        return call

    def close(self) -> None:
        """Close every client this wrapper opened."""
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            closer = getattr(client, "close", None)
            if closer is None:
                continue
            try:
                closer()
            except Exception:  # noqa: BLE001 - best effort
                pass


def build_failover_client(
    endpoints: Sequence[str],
    *,
    timeout: float = 5.0,
    **kwargs: Any,
) -> Etcd3FailoverClient:
    """Build a client that fails over across ``endpoints``."""
    return Etcd3FailoverClient(endpoints, timeout=timeout, **kwargs)
