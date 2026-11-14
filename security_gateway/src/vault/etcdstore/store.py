"""The credential CRUD over the etcd key-value seam.
:class:`KV` and :class:`Lease` are ``Protocol``\\ s, so the real ``etcd3``
client satisfies them without this package depending on the library — the
import is lazy, inside :func:`build_etcd_client`, because the ``etcd``
extra is optional and ``security_gateway`` must not require it.
# Txn: a failed comparison is NOT an error
The single most dangerous mistake available when writing etcd CAS code is
treating a rejected Txn as a transport failure. It is not one::
    resp, err := cli.Txn(ctx).If(cmp).Then(op).Commit()
    err            // nil  <- even when the comparison did NOT hold
    resp.Succeeded // false <- this is the actual verdict
The Python client has the same shape and makes the same mistake easy::
    succeeded, responses = client.transaction(
        compare=[...], success=[...], failure=[])
``succeeded`` is the verdict. A ``False`` means the comparison did not
hold and **the value was not written** — that is a conflict, not an
error. Every CAS path in this module checks the verdict and raises
:class:`~.errors.ConflictError`. Any CAS added later must do the same:
checking only for an exception is the failure mode this note exists to
prevent.
The ``failure`` branch is empty on purpose — this port never writes on a
rejected comparison — but it has to be an **empty list**: the client walks
that branch unconditionally, and a ``None`` there is a ``TypeError``
rather than an empty branch.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Sequence

from .entry import (
    Entry,
    RecordEntry,
    marshal_entry,
    marshal_record,
    unmarshal_entry,
    unmarshal_record,
)
from .errors import ConflictError, InvalidValueError, NotFoundError, remap_compacted
from .etcd3 import (
    Etcd3FailoverClient as Etcd3FailoverClient,
)
from .etcd3 import (
    Etcd3KV as Etcd3KV,
)
from .etcd3 import (
    Etcd3Lease as Etcd3Lease,
)
from .etcd3 import (
    Etcd3Leases as Etcd3Leases,
)
from .etcd3 import (
    build_etcd_client as build_etcd_client,
)
from .etcd3 import (
    build_failover_client as build_failover_client,
)
from .etcd3 import (
    split_endpoint as split_endpoint,
)
from .etcd3 import (
    tls_client_kwargs as tls_client_kwargs,
)
from .keys import (
    cred_key,
    creds_prefix,
    prefix_upper_bound,
    proxy_key_from_cred_key,
    record_id_from_key,
    record_key,
    records_prefix,
)
from .protocol import (
    KV,
    Compare,
    DeleteOp,
    KVValue,
    Lease,
    Operation,
    PutOp,
    TxnResult,
    compare_create,
    compare_mod,
    compare_value,
    compare_version,
)

__all__ = [
    "Compare",
    "DeleteOp",
    "Etcd3FailoverClient",
    "Etcd3KV",
    "Etcd3Lease",
    "Etcd3Leases",
    "KV",
    "KVValue",
    "Lease",
    "ListedEntry",
    "ListedRecord",
    "Operation",
    "PutOp",
    "Store",
    "TxnResult",
    "build_etcd_client",
    "build_failover_client",
    "compare_create",
    "compare_mod",
    "compare_value",
    "compare_version",
    "split_endpoint",
    "tls_client_kwargs",
]


@dataclass
class ListedEntry:
    """A credential entry together with the proxy key it is stored under."""

    proxy_key: str
    entry: Entry


@dataclass
class ListedRecord:
    """A record entry together with the id it is stored under."""

    record_id: str
    entry: RecordEntry


class Store:
    """The credential CRUD for one namespace."""

    def __init__(
        self,
        kv: KV,
        ns: str,
        *,
        generation_key: str | None = None,
        watch_source: Any | None = None,
        leases: Any | None = None,
    ) -> None:
        """Build a store."""
        self._kv = kv
        self._ns = ns
        self._generation_key = generation_key
        self._watch_source = watch_source
        self._leases = leases

    @classmethod
    def from_client(cls, client: Any, ns: str, **kwargs: Any) -> Store:
        """Build a store over a raw ``etcd3`` client."""
        from .watch import RealWatcherSource

        kwargs.setdefault("watch_source", RealWatcherSource(client))
        # A store over a live client can lease: the presence marker, the
        # takeover claim and the rotation lock are all leased keys, and a
        # leased write needs a lease to be leased to.
        kwargs.setdefault("leases", Etcd3Leases(client))
        return cls(kv=Etcd3KV(client), ns=ns, **kwargs)

    @property
    def kv(self) -> KV:
        """The key-value seam this store talks to."""
        return self._kv

    @property
    def ns(self) -> str:
        """The namespace this store holds."""
        return self._ns

    # -- credentials ------------------------------------------------------
    def get_entry(self, proxy_key: str) -> Entry:
        """Read the credential stored under ``proxy_key``."""
        key = cred_key(self._ns, proxy_key)
        kv = self._get(key)
        if kv is None:
            raise NotFoundError(f"etcdstore: no credential under {key!r}")
        entry = unmarshal_entry(kv.value)
        entry.mod_revision = kv.mod_revision
        return entry

    def list_entries(self, limit: int = 0) -> tuple[list[ListedEntry], int]:
        """Every credential entry in the namespace, and the snapshot revision."""
        prefix = creds_prefix(self._ns)
        revision, values = self._get_range(prefix, _prefix_end(prefix), limit)
        return self._decode_listed(values), revision

    def list_entries_from(
        self, after_proxy_key: str, limit: int = 0
    ) -> list[ListedEntry]:
        """The entries whose proxy key sorts strictly after ``after_proxy_key``."""
        prefix = creds_prefix(self._ns)
        start = prefix
        if after_proxy_key:
            # Step past the cursor key so it is not listed twice. Proxy
            # keys are base64url and cannot contain NUL, so appending one
            # yields the immediate successor.
            start = cred_key(self._ns, after_proxy_key) + "\x00"
        _, values = self._get_range(start, _prefix_end(prefix), limit)
        return self._decode_listed(values)

    def create_entry(self, proxy_key: str, entry: Entry) -> Entry:
        """Write a new credential, failing with a conflict if the key exists."""
        if entry is None:
            raise InvalidValueError("etcdstore: nil entry")
        payload = replace(entry, mod_revision=0)
        raw = marshal_entry(payload)
        key = cred_key(self._ns, proxy_key)
        result = self._txn(
            [compare_create(key), *self._generation_compares(entry.dek_version)],
            [PutOp(key, raw)],
        )
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")
        return replace(
            payload, mod_revision=self._revision_after_write(key, result.revision)
        )

    def update_entry_cas(self, proxy_key: str, entry: Entry) -> Entry:
        """Replace the stored credential, but only if it is still at the entry's mod revision."""
        if entry is None:
            raise InvalidValueError("etcdstore: nil entry")
        payload = replace(entry)
        raw = marshal_entry(payload)
        key = cred_key(self._ns, proxy_key)
        result = self._txn(
            [
                compare_mod(key, entry.mod_revision),
                *self._generation_compares(entry.dek_version),
            ],
            [PutOp(key, raw)],
        )
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")
        return replace(
            payload, mod_revision=self._revision_after_write(key, result.revision)
        )

    def delete_entry_cas(self, proxy_key: str, expected_mod_rev: int) -> None:
        """Remove the credential for ``proxy_key``, but only if it is still at ``expected_mod_rev``."""
        key = cred_key(self._ns, proxy_key)
        # Existence check first so an absent key reports "not found"
        # rather than a confusing conflict: the mod revision of a missing
        # key is 0, so the compare below would fail for a reason that has
        # nothing to do with contention. The value is not decoded: the
        # delete only needs to know that the key is there.
        if self._get(key) is None:
            raise NotFoundError(f"etcdstore: no credential under {key!r}")
        result = self._txn([compare_mod(key, expected_mod_rev)], [DeleteOp(key)])
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")

    # -- records ----------------------------------------------------------
    def get_record(self, record_id: str) -> RecordEntry:
        """Read the record stored under ``record_id``."""
        key = record_key(self._ns, record_id)
        kv = self._get(key)
        if kv is None:
            raise NotFoundError(f"etcdstore: no record under {key!r}")
        entry = unmarshal_record(kv.value)
        entry.mod_revision = kv.mod_revision
        return entry

    def list_records(self, limit: int = 0) -> tuple[list[ListedRecord], int]:
        """Every record in the namespace, and the snapshot revision."""
        prefix = records_prefix(self._ns)
        revision, values = self._get_range(prefix, _prefix_end(prefix), limit)
        return self._decode_listed_records(values), revision

    def list_records_from(
        self, after_record_id: str, limit: int = 0
    ) -> list[ListedRecord]:
        """The records whose id sorts strictly after ``after_record_id``."""
        prefix = records_prefix(self._ns)
        start = prefix
        if after_record_id:
            start = record_key(self._ns, after_record_id) + "\x00"
        _, values = self._get_range(start, _prefix_end(prefix), limit)
        return self._decode_listed_records(values)

    def create_record(self, record_id: str, entry: RecordEntry) -> RecordEntry:
        """Write a new record, failing with a conflict if the id is taken."""
        if entry is None:
            raise InvalidValueError("etcdstore: nil record")
        payload = replace(entry, mod_revision=0)
        raw = marshal_record(payload)
        key = record_key(self._ns, record_id)
        result = self._txn(
            [compare_create(key), *self._generation_compares(entry.dek_version)],
            [PutOp(key, raw)],
        )
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")
        return replace(
            payload, mod_revision=self._revision_after_write(key, result.revision)
        )

    def update_record_cas(self, record_id: str, entry: RecordEntry) -> RecordEntry:
        """Replace the stored record, but only if it is still at the entry's mod revision."""
        if entry is None:
            raise InvalidValueError("etcdstore: nil record")
        payload = replace(entry)
        raw = marshal_record(payload)
        key = record_key(self._ns, record_id)
        result = self._txn(
            [
                compare_mod(key, entry.mod_revision),
                *self._generation_compares(entry.dek_version),
            ],
            [PutOp(key, raw)],
        )
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")
        return replace(
            payload, mod_revision=self._revision_after_write(key, result.revision)
        )

    def delete_record_cas(self, record_id: str, expected_mod_rev: int) -> None:
        """Remove the record, but only if it is still at ``expected_mod_rev``."""
        key = record_key(self._ns, record_id)
        if self._get(key) is None:
            raise NotFoundError(f"etcdstore: no record under {key!r}")
        result = self._txn([compare_mod(key, expected_mod_rev)], [DeleteOp(key)])
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")

    def delete_records_cas(
        self, record_ids: Sequence[str]
    ) -> tuple[list[str], list[str]]:
        """Delete every existing record in one transaction.

        Missing ids are reported instead of raising. The delete is atomic:
        all compares and deletes ride in one Txn, so a concurrent update to
        any record makes the whole batch fail with :class:`ConflictError`
        and leaves every record in place.
        """
        keys: list[str] = []
        compares: list[Compare] = []
        deleted: list[str] = []
        missing: list[str] = []
        for record_id in dict.fromkeys(record_ids):
            key = record_key(self._ns, record_id)
            kv = self._get(key)
            if kv is None:
                missing.append(record_id)
                continue
            keys.append(key)
            compares.append(compare_mod(key, int(kv.mod_revision or 0)))
            deleted.append(record_id)
        if not keys:
            return [], missing
        result = self._txn(compares, [DeleteOp(key) for key in keys])
        if not result.succeeded:
            raise ConflictError("etcdstore: CAS conflict")
        return deleted, missing

    # -- the cluster watch ------------------------------------------------
    def watch_generation(self) -> Any:
        """Stream changes to the namespace's DEK generation key."""
        return self._cluster_watch_source().watch_generation(self._ns)

    def watch_handover_requests(self) -> Any:
        """Stream changes under the namespace's handover request prefix."""
        return self._cluster_watch_source().watch_handover_requests(self._ns)

    def _cluster_watch_source(self) -> Any:
        """The watch source, or a loud failure when there is none."""
        from .watch import ClusterWatcherSource, ErrNoWatch

        source = self._watch_source
        if source is None or not isinstance(source, ClusterWatcherSource):
            raise ErrNoWatch()
        return source

    @property
    def leases(self) -> Any:
        """The lease factory, or ``None`` when the store has none."""
        return self._leases

    @property
    def watch_source(self) -> Any:
        """The watch source, or ``None`` when the store has none."""
        return self._watch_source

    # -- internals --------------------------------------------------------
    def _generation_compares(self, dek_version: int) -> list[Compare]:
        """The generation fence, when the store was given a generation key.

        A namespace that has not established its generation key yet is
        fenced by creation: the write is allowed while the key is absent
        and fails if another node establishes it concurrently. Comparing
        a value against a missing key would fail every write forever.
        """
        if self._generation_key is None:
            return []
        if self._get(self._generation_key) is None:
            return [compare_create(self._generation_key)]
        return [
            compare_value(self._generation_key, str(int(dek_version)).encode("utf-8"))
        ]

    def _decode_listed(self, values: Sequence[KVValue]) -> list[ListedEntry]:
        """Turn raw values into entries, stamping each with etcd's mod revision."""
        out: list[ListedEntry] = []
        for kv in values:
            proxy_key = proxy_key_from_cred_key(self._ns, _key_text(kv.key))
            entry = unmarshal_entry(kv.value)
            entry.mod_revision = kv.mod_revision
            out.append(ListedEntry(proxy_key=proxy_key, entry=entry))
        return out

    def _decode_listed_records(self, values: Sequence[KVValue]) -> list[ListedRecord]:
        """Turn raw values into records, stamping each with etcd's mod revision."""
        out: list[ListedRecord] = []
        for kv in values:
            rid = record_id_from_key(self._ns, _key_text(kv.key))
            entry = unmarshal_record(kv.value)
            entry.mod_revision = kv.mod_revision
            out.append(ListedRecord(record_id=rid, entry=entry))
        return out

    def _get(self, key: str) -> KVValue | None:
        try:
            return self._kv.get(key)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _get_range(
        self, start: str, end: str | None, limit: int
    ) -> tuple[int, list[KVValue]]:
        try:
            return self._kv.get_range(start, end, limit)
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise

    def _revision_after_write(self, key: str, revision: int) -> int:
        """The revision a write landed at.

        A client that does not report the revision of the transaction
        leaves the caller without a token it could compare against, so
        the key is read back once. A revision that is reported is taken
        as it is: it is the revision of the write, and not of whatever
        happens to be on the key afterwards.
        """
        if revision:
            return revision
        kv = self._get(key)
        if kv is None:
            return 0
        return int(kv.mod_revision or 0)

    def _txn(
        self, compare: Sequence[Compare], success: Sequence[Operation]
    ) -> TxnResult:
        """Run a transaction, remapping a compaction error."""
        try:
            return self._kv.transaction(compare, success, [])
        except Exception as exc:  # noqa: BLE001 - remapped below
            mapped = remap_compacted(exc)
            if mapped is not exc:
                raise mapped from exc
            raise


def _key_text(raw: bytes) -> str:
    """Decode a key for the prefix arithmetic."""
    return raw.decode("utf-8", "surrogateescape")


def _prefix_end(prefix: str) -> str | None:
    """The exclusive upper bound of the range covering ``prefix``."""
    upper, ok = prefix_upper_bound(prefix)
    if not ok:
        return None
    return upper.decode("utf-8", "surrogateescape")


# -- the real client ------------------------------------------------------
