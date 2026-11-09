"""The real etcd3 client behind the store's seam.

Everything here speaks the etcd3 protocol and nothing else speaks it.
The store is written against :mod:`security_gateway.credmgr.etcdstore.protocol`,
so the etcd3 client can be swapped for a fake without the store noticing.
"""

from __future__ import annotations

from typing import Any, Sequence

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
            text = text[len(scheme) :]
            break
    # A path is not part of an endpoint; a URL that carries one is a URL
    # the client library would not take either.
    text = text.split("/", 1)[0]
    host, _, port = text.rpartition(":")
    if not host:
        # No colon at all: the whole thing is the host.
        host, port = text, ""
    number = default_port
    if port:
        try:
            number = int(port)
        except ValueError as exc:
            raise ValueError(f"etcdstore: {endpoint!r} is not a host and a port") from exc
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


def _txn_revision(responses: Sequence[object]) -> int:
    """The revision a committed transaction landed at.

    The client's response carries the revision on the transaction's own
    header, and on the header of the operation it answered. The names
    differ between clients, so every spelling that is known is tried:
    a transaction whose revision reads back as ``0`` would be handed to
    the caller as a compare-and-swap token that can never match.
    """
    for response in responses:
        revision = _header_revision(response)
        if revision:
            return revision
        inner = getattr(response, "response", None)
        if inner is None:
            continue
        for name in (
            "response_put",
            "response_range",
            "response_delete",
            "response_txn",
            "put_response",
            "delete_response",
            "range_response",
        ):
            op = getattr(inner, name, None)
            if op is None:
                continue
            revision = _header_revision(op)
            if revision:
                return revision
    return 0


def _to_kvvalue(meta: object, value: bytes | None = None) -> KVValue:
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


def _to_etcd_compare(tx: Any, compare: Compare) -> Any:
    """Translate a comparison into the client's own builder."""
    if compare.target == "create":
        return tx.Create(compare.key) == int(compare.value)
    if compare.target == "mod":
        return tx.Mod(compare.key) == int(compare.value)
    if compare.target == "version":
        return tx.Version(compare.key) == int(compare.value)
    if compare.target == "value":
        raw = compare.value
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        return tx.Value(compare.key) == bytes(raw)
    raise ValueError(f"etcdstore: unknown compare target {compare.target!r}")


def _to_etcd_op(tx: Any, op: Operation) -> Any:
    """Translate an operation into the client's own builder."""
    try:
        from .cluster import LeasePutOp  # noqa: PLC0415 - the cluster half imports this one
    except ImportError:
        LeasePutOp = None
    if LeasePutOp is not None and isinstance(op, LeasePutOp):
        return tx.Put(op.key, op.value, lease=op.lease)
    if isinstance(op, PutOp):
        return tx.Put(op.key, op.value)
    if isinstance(op, DeleteOp):
        return tx.Delete(op.key)
    raise ValueError(f"etcdstore: unknown operation {type(op).__name__}")


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
    def id(self) -> int:
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

    def keepalive(self) -> Any:
        """Send one keepalive and return the granted TTL."""
        responses = list(self._client.refresh_lease(self._id))
        if not responses:
            return 0
        return int(getattr(responses[0], "TTL", 0) or 0)


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
        _value, meta = self._client.get(key)
        if meta is None:
            return None
        return _to_kvvalue(meta, _value)

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
        for item in iterator:
            # The client answers with (value, metadata) pairs.
            if isinstance(item, tuple) and len(item) == 2:
                raw_value, meta = item
            else:
                raw_value, meta = None, item
            kv = _to_kvvalue(meta, raw_value)
            revision = max(revision, kv.mod_revision)
            values.append(kv)
            if limit > 0 and len(values) >= limit:
                break
        # The snapshot revision is the header revision of the range
        # response, which the client's public range call does not
        # surface. The highest modification revision in the range is a
        # lower bound for it, and a lower bound is the safe direction to
        # be wrong in: a watch started from it replays the tail of the
        # snapshot instead of skipping it, and the replay is idempotent.
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
        from etcd3 import transactions as tx  # noqa: PLC0415 - optional extra

        cmp_objs = [_to_etcd_compare(tx, c) for c in compare]
        ops = [_to_etcd_op(tx, o) for o in success]
        fail_ops = [_to_etcd_op(tx, o) for o in failure]
        # The failure branch is empty on purpose, but it has to be an
        # empty *list*: the client walks it unconditionally, and a None
        # there is a TypeError rather than an empty branch.
        succeeded, responses = self._client.transaction(
            compare=cmp_objs,
            success=ops,
            failure=fail_ops,
        )
        return TxnResult(succeeded=bool(succeeded), revision=_txn_revision(responses))
