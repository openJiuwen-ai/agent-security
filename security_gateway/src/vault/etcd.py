"""The vault's etcd authority.

With etcd as the write authority the store's local database is a
*mirror* rather than the store itself: writes go to etcd, and a watch
brings them back down. Reads are served from the mirror, so a read does
not cost an etcd round trip.

The mirror is deliberately degraded rather than wrong. If etcd is
unreachable the store keeps serving what it last saw, and says so
through its status, instead of failing every read.

Two things about this half are load-bearing and easy to get wrong:

**The generation fence is a fence, not a check.** Every write the
authority makes carries a compare-and-swap against the authority's
generation record, inside the same transaction as the write. A write the
fence refuses is **not** a transport failure: it says that the writer is
from a generation the authority has already left behind, and the caller
has to decide what to do about it.

**The fence moves before the ciphertext, not after.** The re-encryption
pass stamps every record it writes with the target generation, so an
authority still reading the old generation would reject its own rewrite.
Moving the fence first also stops a node that is lagging behind from
writing ciphertext the fleet cannot read.

The store's own key material is separate from the credential store's
keystore; what is shared is the etcd namespace, and therefore the
generation fence — the vault's DEK version is what the authority's
generation record holds.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Protocol

from security_gateway.vault.etcdstore.errors import ConflictError as _StoreConflictError
from security_gateway.crypto import decrypt_credential, encrypt_credential
from security_gateway.crypto.errors import CryptoError

from .clock import now_timestamp as _now_timestamp
from .codec import ContainerField, decode_container, encode_container
from .errors import (
    ConflictError,
    InvalidRecordError,
    NotFoundError,
    SchemaMismatchError,
    StaleGenerationError,
    UndecryptableError,
    VaultError,
)
from .format import format_held_versions
from .keys import KeySnapshot
from .mirror import apply_mirrored_record, delete_mirrored_record
from .schema import Schema
from .store import Database

if TYPE_CHECKING:
    from security_gateway.vault.etcdstore.entry import RecordEntry

__all__ = [
    "AUTHORITY_BATCH_SIZE",
    "DEFAULT_ETCD_NAMESPACE",
    "DEFAULT_FETCH_TIMEOUT_SECONDS",
    "EtcdAuthority",
    "EtcdConfig",
    "EtcdTLSConfig",
    "FencedWriteError",
    "converge_authority",
    "dial_etcd",
    "reencrypt_record_payload",
]

#: The namespace a store uses when none is given.
DEFAULT_ETCD_NAMESPACE = "security_gateway"

#: How many records one pass of the authority-side re-encryption takes at
#: a time.
AUTHORITY_BATCH_SIZE = 100

#: How long a node waits for a peer to seal the fleet's key before giving
#: up.
DEFAULT_FETCH_TIMEOUT_SECONDS = 30.0


class FencedWriteError(VaultError):
    """A write the authority's generation fence refused.

    It is deliberately not a transport error and not a plain conflict: a
    fenced write says the writer is from a generation the authority has
    already left behind, so retrying will not help and the caller has to
    fetch the current key first.
    """

    code = "fenced"


@dataclass(frozen=True)
class EtcdTLSConfig:
    """The etcd TLS material.

    It is all-or-nothing: a partially filled set is refused rather than
    silently downgraded to plaintext.
    """

    ca_file: str = ""
    cert_file: str = ""
    key_file: str = ""

    def all_set(self) -> bool:
        """Whether every TLS file was named."""
        return bool(self.ca_file and self.cert_file and self.key_file)

    def partially_set(self) -> bool:
        """Whether some, but not all, of the TLS files were named."""
        named = bool(self.ca_file or self.cert_file or self.key_file)
        return named and not self.all_set()


@dataclass
class EtcdConfig:
    """Makes etcd the write authority for the store's records.

    The namespace is the keyspace the store's records live under, and it
    defaults to ``"default"``.
    """

    #: The etcd client endpoints. At least one is required.
    endpoints: tuple[str, ...] = ()

    #: The keyspace namespace the store's records live under.
    namespace: str = ""

    #: The TLS material, or ``None`` for a plaintext deployment.
    tls: EtcdTLSConfig | None = None

    #: Bounds the initial connection. Zero means the client's default.
    dial_timeout: float = 0.0

    #: This node's identity in the cluster.
    node_id: str = ""

    #: The identity used for the fleet's key handover, separate from the
    #: transport TLS material so a TLS-terminating proxy still works.
    identity_cert_file: str = ""
    identity_key_file: str = ""

    #: The CA that signs the fleet's node certificates, used by the
    #: handover trust anchor. It is separate from ``tls.ca_file`` on
    #: purpose: the etcd connection may trust one CA while the fleet's
    #: identities are issued by another.
    identity_ca_file: str = ""

    #: The certificate fingerprints the fleet's key may be handed to.
    trusted_cert_sha256: tuple[str, ...] = ()

    #: How long a node waits for a peer to seal the fleet's key.
    fetch_timeout: float = DEFAULT_FETCH_TIMEOUT_SECONDS


class AuthorityConvergence(Protocol):
    """What the authority's convergence pass needs from the store.

    The pass opens each record with the key for the generation that
    record was written with, so it needs the snapshots and the reload
    that refreshes them.
    """

    def schema_for_version(self, version: int) -> Schema | None:
        """The schema a record with that version was written with."""
        ...

    @property
    def keys(self) -> Any:
        """The store's key snapshots."""
        ...

    def reload_snapshot(self) -> None:
        """Re-read the key metadata."""
        ...


#: How many times a write to the authority re-reads the record and decides
#: again.
#:
#: A write that loses the create race to a delete has to try again. The
#: bound keeps a record that keeps changing under the writer from spinning
#: forever.
MAX_AUTHORITY_WRITE_ATTEMPTS = 8


class EtcdAuthority:
    """The vault's handle on the etcd side of the store.

    The store is the seam: the vault's authority half is written against
    the store's verbs, so the same handle serves a live etcd and a fake.
    """

    def __init__(self, client: Any, store: Any, ns: str) -> None:
        """Build an authority over a store."""
        self._client = client
        self._store = store
        self._ns = ns

    @classmethod
    def over(cls, store: Any, ns: str | None = None) -> "EtcdAuthority":
        """Build an authority over an existing store, without seeding."""
        namespace = ns if ns is not None else store.ns
        return cls(None, store, namespace)

    @classmethod
    def from_store(cls, store: Any, ns: str | None = None) -> "EtcdAuthority":
        """Build an authority over an existing store.

        The generation record is seeded when it is absent, so that the
        fence has something real to match: an absent key's value is the
        empty string, and every write would be refused against it.
        """
        from security_gateway.vault.etcdstore import ensure_generation

        authority = cls.over(store, ns)
        try:
            ensure_generation(authority.store.kv, authority.ns)
        except Exception as exc:  # noqa: BLE001 - remapped to a vault error
            raise VaultError(
                f"vault: etcd: seed the authority's generation: {exc}"
            ) from exc
        return authority

    @property
    def store(self) -> Any:
        """The credential store's handle on the authority's namespace."""
        return self._store

    @property
    def ns(self) -> str:
        """The namespace the records live under."""
        return self._ns

    def close(self) -> None:
        """Release the etcd connection."""
        client, self._client = self._client, None
        if client is None:
            return
        closer = getattr(client, "close", None)
        if closer is None:
            return
        try:
            closer()
        except Exception:  # noqa: BLE001 - best effort
            pass

    # -- the generation fence ---------------------------------------------

    def generation(self) -> int:
        """The authority's current DEK generation."""
        from security_gateway.vault.etcdstore import read_generation

        try:
            current, _present = read_generation(self._store.kv, self._ns)
        except Exception as exc:  # noqa: BLE001 - remapped to a vault error
            raise VaultError(
                f"vault: etcd: read the authority's generation: {exc}"
            ) from exc
        return int(current)

    def advance_generation(self, target: int) -> int:
        """Move the authority's generation fence to ``target``."""
        from security_gateway.vault.etcdstore import advance_generation

        try:
            _advanced, current = advance_generation(
                self._store.kv, self._ns, int(target)
            )
        except Exception as exc:  # noqa: BLE001 - remapped to a vault error
            raise VaultError(
                f"vault: etcd: advance the authority's generation to {target}: {exc}"
            ) from exc
        return int(current)

    # -- the records ------------------------------------------------------

    def write_record(
        self,
        db: Database,
        record_id: str,
        data: bytes,
        schema_version: int,
        dek_version: int,
        *,
        expected: Callable[[str, "RecordEntry"], None] | None = None,
    ) -> None:
        """Publish a record to the authority and mirror it locally.

        ``expected`` runs against the entry the authority currently
        holds, inside the read/CAS loop, so a guarded field that moved
        between the read and the write cannot slip through. It is
        internal to the vault and never exposed as a version.

        A write the generation fence refuses raises
        :class:`FencedWriteError`.
        """
        from security_gateway.vault.etcdstore.entry import RecordEntry, Timestamp
        from security_gateway.vault.etcdstore.errors import (
            ConflictError as StoreConflictError,
        )
        from security_gateway.vault.etcdstore.errors import (
            NotFoundError as StoreNotFoundError,
        )

        now = Timestamp.now()
        entry = RecordEntry(
            data=bytes(data),
            schema_version=int(schema_version),
            dek_version=int(dek_version),
            created_at=now,
            updated_at=now,
        )

        # The write is a loop because the record can change under it in two
        # ways, and both are ordinary: another writer created it, or
        # somebody deleted it.
        for _attempt in range(MAX_AUTHORITY_WRITE_ATTEMPTS):
            existing: RecordEntry | None
            try:
                existing = self._store.get_record(record_id)
            except StoreNotFoundError:
                existing = None
            except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                raise VaultError(f"vault: etcd: read the record {record_id!r}: {exc}") from exc

            if expected is not None:
                if existing is None:
                    raise NotFoundError(f'"{record_id}"')
                expected(record_id, existing)

            if existing is None:
                try:
                    created = self._store.create_record(record_id, entry)
                except StoreConflictError as exc:
                    # The create failed its compare-and-swap. That is two
                    # different things, and the fence tells them apart: if
                    # the authority's generation has moved on, this writer
                    # is fenced out; otherwise somebody else got there
                    # first. Re-read and decide afresh.
                    if self._fenced(dek_version):
                        raise self._fenced_error(record_id, dek_version, exc) from exc
                    try:
                        existing = self._store.get_record(record_id)
                    except StoreNotFoundError:
                        continue
                    except Exception as read_exc:  # noqa: BLE001 - remapped below
                        raise VaultError(
                            f"vault: etcd: read the record {record_id!r} after a conflict: {read_exc}"
                        ) from read_exc
                except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                    raise VaultError(
                        f"vault: etcd: create the record {record_id!r}: {exc}"
                    ) from exc
                else:
                    apply_mirrored_record(
                        db,
                        record_id,
                        bytes(data),
                        int(schema_version),
                        int(dek_version),
                        created.mod_revision,
                    )
                    return

            entry.mod_revision = existing.mod_revision
            try:
                updated = self._store.update_record_cas(record_id, entry)
            except StoreConflictError as exc:
                if self._fenced(dek_version):
                    raise self._fenced_error(record_id, dek_version, exc) from exc
                # The record moved under this write -- normally because a
                # rotation re-encrypted it. Read the new revision and try
                # again; the payload is still encrypted for the generation
                # the snapshot chose.
                continue
            except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                raise VaultError(
                    f"vault: etcd: update the record {record_id!r}: {exc}"
                ) from exc

            apply_mirrored_record(
                db,
                record_id,
                bytes(data),
                int(schema_version),
                int(dek_version),
                updated.mod_revision,
            )
            return

        raise ConflictError(
            f'vault: etcd: update the record "{record_id}": the record kept changing'
        )

    def delete_record(
        self,
        db: Database,
        id: str,
        *,
        expected: Callable[[str, "RecordEntry"], None] | None = None,
    ) -> None:
        """Remove a record from the authority and from the mirror.

        A record that is not there raises :class:`NotFoundError`: a
        delete that did nothing must not report that it deleted
        something.
        """
        from security_gateway.vault.etcdstore.errors import (
            ConflictError as StoreConflictError,
        )
        from security_gateway.vault.etcdstore.errors import (
            NotFoundError as StoreNotFoundError,
        )

        for attempt in range(MAX_AUTHORITY_WRITE_ATTEMPTS):
            try:
                existing = self._store.get_record(id)
            except StoreNotFoundError as exc:
                raise NotFoundError(f'"{id}"') from exc
            except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                raise VaultError(f"vault: etcd: read the record {id!r}: {exc}") from exc

            if expected is not None:
                expected(id, existing)

            try:
                self._store.delete_record_cas(id, existing.mod_revision)
            except StoreNotFoundError as exc:
                raise NotFoundError(f'"{id}"') from exc
            except StoreConflictError as exc:
                if expected is None or attempt == MAX_AUTHORITY_WRITE_ATTEMPTS - 1:
                    raise ConflictError(
                        f'vault: etcd: delete the record "{id}": {exc}'
                    ) from exc
                continue
            except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                raise VaultError(
                    f"vault: etcd: delete the record {id!r}: {exc}"
                ) from exc

            delete_mirrored_record(db, id, existing.mod_revision)
            return

    def authority_straggler_count(self, target: int) -> int:
        """How many records the authority holds under an older key."""
        try:
            listed, _revision = self._store.list_records(0)
        except Exception as exc:  # noqa: BLE001 - remapped to a vault error
            raise VaultError(f"vault: etcd: list the records: {exc}") from exc
        return sum(1 for record in listed if record.entry.dek_version < int(target))

    def converge(self, vault: AuthorityConvergence, cur: KeySnapshot) -> None:
        """Re-encrypt every record the authority holds that is still under an older key generation."""
        converge_authority(vault, self, cur)

    # -- internals ---------------------------------------------------------

    def _fenced(self, dek_version: int) -> bool:
        """Whether the authority's generation has moved past the writer's."""
        return self.generation() != int(dek_version)

    def _fenced_error(
        self, record_id: str, dek_version: int, exc: Exception
    ) -> FencedWriteError:
        """The error a fenced write raises.

        It names both generations and which side is wrong, because the
        verdict is an inequality and "older" is only one of the two ways
        to fail it.
        """
        current = self.generation()
        side = "behind" if int(dek_version) <= current else "ahead of"
        return FencedWriteError(
            f"vault: etcd: the record {record_id!r} was refused: this writer holds "
            f"generation {dek_version} and the authority holds {current}, so the writer "
            f"is {side} the authority"
        )


def dial_etcd(cfg: EtcdConfig) -> EtcdAuthority:
    """Connect to etcd and return the authority handle."""
    from security_gateway.vault.etcdstore import (
        Store,
        build_failover_client,
        ensure_generation,
        tls_client_kwargs,
    )
    from security_gateway.vault.etcdstore.cluster import generation_key

    if cfg is None or not cfg.endpoints:
        raise VaultError("vault: etcd: at least one endpoint is required")

    tls = cfg.tls
    if tls is not None and tls.partially_set():
        raise VaultError(
            "vault: etcd: the TLS material is incomplete: a CA without a client "
            "certificate would silently fall back to plaintext, which would hand "
            "every record to the network"
        )

    ns = cfg.namespace or DEFAULT_ETCD_NAMESPACE
    kwargs: dict[str, Any] = {}
    if tls is not None:
        kwargs.update(tls_client_kwargs(tls.ca_file, tls.cert_file, tls.key_file))
    client = build_failover_client(
        cfg.endpoints,
        timeout=cfg.dial_timeout or 5.0,
        **kwargs,
    )

    store = Store.from_client(client, ns, generation_key=generation_key(ns))
    try:
        ensure_generation(store.kv, ns)
    except Exception as exc:  # noqa: BLE001 - remapped to a vault error
        raise VaultError(
            f"vault: etcd: seed the authority's generation: {exc}"
        ) from exc
    return EtcdAuthority(client, store, ns)


def converge_authority(
    vault: AuthorityConvergence,
    authority: EtcdAuthority,
    cur: KeySnapshot,
) -> None:
    """Re-encrypt every record the authority holds that is still under an older key generation.

    The keyspace is walked with a cursor rather than an offset, because
    a rewritten record comes back as the same record and an offset walk
    would never move past the first page.
    """
    store = authority.store

    # The fence is not moved here. The rotation moves it before it calls
    # this: every record this pass is about to write is stamped with the
    # target generation, so an authority still reading the old generation
    # would reject its own rewrite. Moving it a second time here would be
    # a second place where the order of the fence and the ciphertext could
    # drift apart.

    after = ""
    while True:
        listed = store.list_records_from(after, AUTHORITY_BATCH_SIZE)
        if not listed:
            return
        for record in listed:
            entry = record.entry
            for attempt in range(5):
                sch = vault.schema_for_version(entry.schema_version)
                if sch is None:
                    raise SchemaMismatchError(
                        f'the record "{record.record_id}" was written with schema '
                        f'v{entry.schema_version}, which this store does not know'
                    )
                if int(entry.dek_version) == int(cur.version):
                    break
                src = vault.keys.by_version(entry.dek_version)
                if src is None:
                    # The snapshot does not hold the generation this record
                    # was written with. Another node may have rotated the
                    # fleet since this one last looked: reload and look again.
                    vault.reload_snapshot()
                    src = vault.keys.by_version(entry.dek_version)
                if src is None:
                    raise StaleGenerationError(
                        f'record "{record.record_id}" is under generation '
                        f'{entry.dek_version}, which this store does not hold (it holds '
                        f"{format_held_versions(vault.keys.held_versions())})"
                    )
                entry.data = reencrypt_record_payload(entry.data, sch, src, cur)
                entry.dek_version = int(cur.version)
                entry.updated_at = _now_timestamp()
                try:
                    store.update_record_cas(record.record_id, entry)
                    break
                except _StoreConflictError:
                    # A writer updated the record while it was being
                    # re-encrypted. Read the newer entry: it is either
                    # already under the target generation, or it needs a
                    # fresh re-encrypt with its new revision.
                    if attempt == 4:
                        raise VaultError(
                            f"vault: etcd: re-encrypt the record {record.record_id!r}: "
                            "the record kept changing"
                        )
                    try:
                        entry = store.get_record(record.record_id)
                    except Exception:  # noqa: BLE001 - deleted under us
                        break
                except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                    raise VaultError(
                        f"vault: etcd: re-encrypt the record {record.record_id!r}: {exc}"
                    ) from exc
        after = listed[-1].record_id


def reencrypt_record_payload(
    payload: bytes, schema: Schema, src: KeySnapshot, cur: KeySnapshot
) -> bytes:
    """Re-encrypt a record's encrypted fields from the key the record is under to the current one.

    A field the source key cannot open is refused rather than carried
    over: a record that is under a key this store does not hold is one
    no key this store holds can read.
    """
    try:
        fields = decode_container(payload)
    except InvalidRecordError as exc:
        raise InvalidRecordError(
            f"decode the record payload: {exc}", whole=True
        ) from exc

    defs = schema.field_lookup()
    rewritten: list[ContainerField] = []
    for f in fields:
        definition = defs.get(f.name)
        if definition is None:
            raise SchemaMismatchError(
                f'the record has field "{f.name}", which schema v{schema.version} does not declare'
            )
        if f.encrypted != definition.encrypted:
            raise SchemaMismatchError(
                f'the record\'s field "{f.name}" is marked '
                f'encrypted={f.encrypted} but schema v{schema.version} says '
                f'{definition.encrypted}'
            )
        if not definition.encrypted:
            rewritten.append(f)
            continue
        try:
            plain = decrypt_credential(src.mode, src.dek_bytes(), f.data)
        except CryptoError as exc:
            raise UndecryptableError(
                f'the record\'s field "{f.name}" is under neither the current nor the previous key'
            ) from exc
        try:
            sealed = encrypt_credential(cur.mode, cur.dek_bytes(), plain)
        except CryptoError as exc:
            raise VaultError(
                f're-encrypt the record\'s field "{f.name}": {exc}'
            ) from exc
        rewritten.append(
            ContainerField(name=f.name, type=f.type, encrypted=True, data=sealed)
        )
    return encode_container(rewritten)
