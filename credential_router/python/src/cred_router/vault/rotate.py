"""The vault's key rotation.

A rotation replaces the store's data-encryption key and re-encrypts
every record that is still under the old one. It is the one operation in
the vault that changes what a record's bytes *mean*, so it is written as
a protocol rather than as a sequence of statements:

  1. Claim the rotation with a compare-and-swap on the pending marker.
     Two rotations cannot run at once, and neither can run on top of
     another.
  2. Mint the new key and seal it with the key-encryption key.
  3. Swap the key *before* re-encrypting anything. From that point on
     new writes use the new key, and readers of records that have not
     been re-encrypted yet fall back to the previous one.
  4. Re-encrypt the records that are still under the old key.
  5. Commit, under the write barrier, once no record is left behind.

A rotation that dies partway leaves the pending marker set on purpose.
The next open promotes the pending key, keeps the old one as the
previous key, and finishes the re-encryption before any caller sees the
store.

The rotation is a free function over the store rather than a method on
it. What the rotation needs from the store is spelled out in
:class:`RotationTarget`, and the authority's etcd store is passed in as
an argument.

**The schedule is attachable.** :func:`start_auto_rotate` puts a ticker
on an open store and takes it off again; a store nobody attached one to
is never rotated.

The rotation's machinery lives in :mod:`cred_router.vault.rotate_engine`
and :mod:`cred_router.vault.rotate_authority`. This module holds the
public API and the order the rotation runs in.
"""

from __future__ import annotations

import logging
import os  # noqa: F401 - re-exported
import random  # noqa: F401 - re-exported
import socket  # noqa: F401 - re-exported
import threading
import time
from typing import Any, Callable, Protocol  # noqa: F401 - re-exported

from cred_router.crypto import (
    DEK_SIZE,
    SHARD_SIZE,
    KeyBytes,
    decrypt_credential,
    encrypt_credential,
    parse_mode,
    wrap_dek,
)
from cred_router.crypto.errors import CryptoError

from .codec import ContainerField, decode_container, encode_container
from .errors import (
    ClosedError,
    InvalidRecordError,
    KeyMismatchError,
    RotationInProgressError,
    SchemaMismatchError,
    StaleGenerationError,
    UndecryptableError,
    UnsupportedError,
    VaultError,
)
from .format import format_held_versions
from .keys import (
    KeyManager,  # noqa: F401 - re-exported
    KeyMeta,
    KeySnapshot,
    config_shard_size_wrong,
    crypto_mode_unusable,
    derive_kek,
    load_s1_from_file,
    read_key_meta,
    s1_path,
    update_key_meta,
)
from .schema import Schema  # noqa: F401 - re-exported
from .store import Database  # noqa: F401 - re-exported
from .store import count_stragglers as _count_store_stragglers  # noqa: F401 - re-exported
from .store import run_with_busy_retry, select_stragglers, update_record_cipher

from .rotate_authority import (
    _advance_generation, _authority_store, _converge_authority,
    _count_authority_stragglers,  # noqa: F401 - re-exported
    _fleet_rotation_gate, _record_fleet_rotation_gate, _release_fleet_lock,
    _reencrypt_payload,  # noqa: F401 - re-exported
    count_stragglers, rotation_holder,
)
from .rotate_engine import (
    MAX_CLAIM_ATTEMPTS, MAX_ROTATION_ATTEMPTS, PENDING_LEASE_JITTER_SECONDS,
    PENDING_LEASE_SECONDS, ROTATION_BATCH_SIZE, ROTATION_LOCK_TTL_SECONDS,
    RotationTarget, _claim_rotation, _commit_rotation, _not_started,
    _refresh_lease, _sleep_jitter, _stop_check, _stop_from_event,
    converge_stragglers, rotation_finished_elsewhere,
)


__all__ = [
    "MAX_CLAIM_ATTEMPTS",
    "MAX_ROTATION_ATTEMPTS",
    "PENDING_LEASE_JITTER_SECONDS",
    "PENDING_LEASE_SECONDS",
    "ROTATION_BATCH_SIZE",
    "ROTATION_LOCK_TTL_SECONDS",
    "RotationTarget",
    "converge",
    "converge_stragglers",
    "converge_to",
    "count_stragglers",
    "rotate_dek",
    "rotation_finished_elsewhere",
    "rotation_holder",
    "set_rotate_before_claim_hook",
    "start_auto_rotate",
    "takeover_pending",
]

_log = logging.getLogger(__name__)


def rotate_dek(
    vault: RotationTarget,
    store: Any | None = None,
    *,
    leases: Any | None = None,
    cancel: Callable[[], BaseException | None] | None = None,
) -> None:
    """Replace the store's data encryption key.

    ``leases`` is the lease factory the rotation lock is taken on. The
    lock lives on an etcd lease, and a lease that is not renewed is a
    lock that expires in the middle of a rotation.
    """
    with vault.rotate_mu:
        lock = None
        stop_heartbeat = None
        lost_lock = None
        if store is not None:
            # In etcd mode the rotation has to be arbitrated across the
            # fleet: two nodes rotating at once would mint two keys for the
            # same generation and leave records under one of them that no
            # other node can open.
            lock = _acquire_fleet_lock(store, leases)
            # A heartbeat keeps the lock's lease alive; a rotation that
            # lost it is no longer the only one rotating the fleet, so the
            # loss stops the rotation rather than being logged and ignored.
            stop_heartbeat, lost_lock = _start_rotation_lock_heartbeat(lock)
        try:
            _rotate_locked(vault, store, _stop_check(lost_lock, cancel))
            if store is not None:
                # The fleet's gate: one timestamp for the whole fleet, so
                # three nodes with three tickers rotate once between them
                # and not three times. Only the node that held the lock
                # writes it.
                _record_fleet_rotation_gate(store)
        finally:
            if stop_heartbeat is not None:
                stop_heartbeat()
            if lock is not None:
                _release_fleet_lock(lock)


def start_auto_rotate(vault: RotationTarget, period: float) -> Callable[[], None]:
    """Start the background ticker that rotates the store's DEK every ``period``."""
    if period <= 0:
        return _not_started

    stop = threading.Event()
    thread = threading.Thread(
        target=_auto_rotate_loop,
        args=(vault, period, stop),
        name="cred-router-vault-auto-rotate",
        daemon=True,
    )
    thread.start()

    def stop_auto_rotate() -> None:
        """Stop the ticker and wait for the tick in flight to finish."""
        stop.set()
        thread.join(timeout=5.0)

    return stop_auto_rotate


# The claim seam. It is called by the rotation after it reads the key
# metadata and before it claims the generation, so a test can let another
# rotation finish inside that window — the race the claim's compare-and-swap
# is there to catch.
_rotate_before_claim_hook: Callable[[], None] | None = None


def set_rotate_before_claim_hook(fn: Callable[[], None] | None) -> None:
    """Install the hook the rotation calls before it claims the generation."""
    global _rotate_before_claim_hook
    _rotate_before_claim_hook = fn


def _auto_rotate_loop(
    vault: RotationTarget, period: float, stop: threading.Event
) -> None:
    """Run the ticker: one tick now, then one per period.

    A tick that fails is logged and the loop goes on: one bad tick must
    not cost the schedule the rest of its life.
    """
    while not stop.is_set():
        try:
            _rotate_once(vault, period, _stop_from_event(stop))
        except RotationInProgressError as exc:
            # A rotation that is already going is not a failure: the
            # schedule has nothing to add to it, and the next tick picks up
            # whatever is still owed.
            _log.info("vault: the auto-rotate is skipping this tick: %s", exc)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            if stop.is_set():
                # The schedule was stopped while the tick was running.
                # The tick gives up and the goroutine returns without a
                # complaint.
                return
            _log.error("vault: the auto-rotate failed: %s", exc)
        if stop.wait(period):
            return


def _rotate_once(
    vault: RotationTarget,
    period: float,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """Rotate the DEK, unless the period has not elapsed yet.

    A rotation that was left unfinished comes first: the store cannot
    rotate again while a generation is pending, so finishing that one is
    what unblocks the next.
    """
    km = read_key_meta(vault.db)
    if km is None:
        raise KeyMismatchError("the store has no key metadata")
    if km.pending_dek_version != 0:
        try:
            takeover_pending(vault, stop)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            _log.info(
                "vault: the auto-rotate could not take the pending rotation "
                "over: generation=%d err=%s",
                km.pending_dek_version,
                exc,
            )
        return
    store = _authority_store(vault)
    rotated_at = km.last_rotate_at
    if store is not None:
        # The gate that matters in the etcd mode is the fleet's, not this
        # node's: the local row is the node's own bookkeeping, so three nodes
        # with three tickers would each read "never rotated" and each
        # rotate. The authority keeps one timestamp for the whole fleet.
        rotated_at = _fleet_rotation_gate(store)
    if rotated_at > 0 and (time.time() - rotated_at) < period:
        _log.info(
            "vault: the auto-rotate is skipping this tick: reason=gate "
            "last_rotate_at=%d period=%s",
            rotated_at,
            period,
        )
        return
    rotate_dek(vault, store, cancel=stop)


def converge(
    vault: RotationTarget,
    target: KeySnapshot | None,
    store: Any | None = None,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """Re-encrypt the records that are still under the old key."""
    if target is None:
        raise ClosedError("the store has no key")
    if store is not None:
        _converge_authority(vault, store, target)
        return
    converge_to(vault, target, stop)


def converge_to(
    vault: RotationTarget,
    target: KeySnapshot,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """Re-encrypt every record that is not under the target generation."""
    while True:
        rows = select_stragglers(vault.db, target.version, ROTATION_BATCH_SIZE)
        if not rows:
            return

        for row in rows:
            sch = vault.schema_for_version(row.schema_version)
            if sch is None:
                raise SchemaMismatchError(
                    f'record "{row.id}" was written with schema v{row.schema_version}, which this store does not know'
                )
            try:
                fields = decode_container(row.data)
            except InvalidRecordError as exc:
                # The record is named: a container that does not parse is
                # one record's damage, and which record it is, is the whole
                # of what the operator needs to know.
                raise VaultError(
                    f'vault: decode record "{row.id}": {exc}') from exc
            defs = sch.field_lookup()

            src = vault.keys.by_version(row.dek_version)
            if src is None:
                # The snapshot does not hold the generation this record was
                # written with. Another process may have rotated the store
                # since this one last looked: reload the key metadata and
                # look again.
                #
                # Without the reload the process gives up on the records the
                # other process wrote under the generation it never saw, and
                # the rotation is lost until the lease expires and somebody
                # takes it over.
                vault.reload_snapshot()
                src = vault.keys.by_version(row.dek_version)
            if src is None:
                held = format_held_versions(vault.keys.held_versions())
                raise StaleGenerationError(
                    f'record "{row.id}" is under generation '
                    f"{row.dek_version}, which this store does not hold "
                    f"(it holds {held})"
                )

            rewritten: list[ContainerField] = []
            for f in fields:
                definition = defs.get(f.name)
                if definition is None:
                    raise SchemaMismatchError(
                        f'record "{row.id}" has field "{f.name}", which schema v{sch.version} does not declare'
                    )
                if f.encrypted != definition.encrypted:
                    raise SchemaMismatchError(
                        f'record "{row.id}" field "{f.name}" is marked '
                        f"encrypted={f.encrypted} but schema v{sch.version} "
                        f"says {definition.encrypted}"
                    )
                if not definition.encrypted:
                    rewritten.append(f)
                    continue
                try:
                    plain = decrypt_credential(src.mode, src.dek_bytes(), f.data)
                except CryptoError as exc:
                    raise UndecryptableError(
                        f'record "{row.id}" field "{f.name}" is under neither the current nor the previous key'
                    ) from exc
                try:
                    sealed = encrypt_credential(
                        target.mode, target.dek_bytes(), plain
                    )
                except CryptoError as exc:
                    raise VaultError(
                        f"vault: re-encrypt record {row.id!r} field "
                        f"{f.name!r}: {exc}") from exc
                rewritten.append(
                    ContainerField(
                        name=f.name,
                        type=f.type,
                        encrypted=True,
                        data=sealed,
                    )
                )

            encoded = encode_container(rewritten)
            # The row_version guard makes this safe against a concurrent
            # write: if the row moved on, the update matches nothing and
            # the record is skipped. That is correct — a concurrent write
            # already used the current DEK.
            #
            # The write waits out a busy store like every other write does.
            # A rotation that gave up its turn would leave the store in the
            # pending state until the lease expires.
            run_with_busy_retry(
                lambda: update_record_cipher(
                    vault.db, row.id, row.row_version, encoded, target.version
                ),
                stop,
            )

        _refresh_lease(vault, target.version, stop)


def takeover_pending(
    vault: RotationTarget,
    cancel: Callable[[], BaseException | None] | None = None,
) -> None:
    """Finish a rotation that was left unfinished.

    Finishing it means adopting the pending generation — the key that is
    already in the store, never a new one — re-encrypting the records
    that are still under the old generation, and committing the result.
    """
    with vault.rotate_mu:
        _takeover_locked(vault, cancel)


def _takeover_locked(
    vault: RotationTarget,
    cancel: Callable[[], BaseException | None] | None = None,
) -> None:
    """The takeover, with the process-local lock already held."""
    if getattr(vault, "authority", None) is not None:
        raise UnsupportedError("the takeover applies to a local store")

    km = read_key_meta(vault.db)
    if km is None:
        raise KeyMismatchError("the store has no key metadata")
    if km.pending_dek_version == 0:
        # Nothing was left unfinished.
        return
    pending = km.pending_dek_version
    updated_at = km.updated_at

    # A fresh lease means the rotation that claimed the generation is still
    # working. It is not ours to take over.
    if (time.time() - updated_at) < PENDING_LEASE_SECONDS:
        raise RotationInProgressError(
            f"a rotation to v{pending} is in progress"
        )

    # Wait a random moment, then look again. Several processes can notice
    # the same stale lease at the same time; staggering them means one of
    # them takes over and refreshes the lease, and the others see the fresh
    # lease and give up.
    _sleep_jitter(PENDING_LEASE_JITTER_SECONDS)

    km = read_key_meta(vault.db)
    if km is None:
        raise KeyMismatchError("the store has no key metadata")
    if km.pending_dek_version == 0:
        # Somebody else finished it while we waited.
        return
    if km.pending_dek_version != pending:
        raise RotationInProgressError(
            f"the pending generation moved from v{pending} to v{km.pending_dek_version}"
        )
    if km.updated_at != updated_at:
        # The lease was refreshed: the rotation is alive.
        raise RotationInProgressError(
            f"a rotation to v{pending} is in progress"
        )

    # Adopt the pending generation. The key is already in the store — the
    # rotation that claimed it wrapped it there before it died — so the
    # takeover never mints a second key under the same generation.
    vault.reload_snapshot()
    target = vault.keys.pend()
    if target is None or target.version != pending:
        raise KeyMismatchError(
            f"the pending generation {pending} does not open with this store's key material"
        )

    # Announce the takeover: a fresh lease tells the other processes that
    # somebody is on it.
    _refresh_lease(vault, target.version, cancel)

    old_active = vault.keys.by_version(km.active_dek_version)
    for _attempt in range(MAX_ROTATION_ATTEMPTS):
        converge_to(vault, target, cancel)
        if _commit_rotation(
            vault,
            target.version,
            km.pending_wrapped_dek,
            km.wrapped_dek,
            km.active_dek_version,
            cancel,
        ):
            vault.keys.replace(target, old_active, None)
            return

        # The commit did not land. Either there are still records under the
        # old generation, or somebody else finished the rotation.
        if rotation_finished_elsewhere(vault, target.version):
            # Somebody else committed this generation. The rotation is
            # finished; the loser of the race has nothing left to do and
            # must not report a failure.
            vault.reload_snapshot()
            return

    raise RotationInProgressError(
        "the takeover did not converge: records are still under the old "
        f"key after {MAX_ROTATION_ATTEMPTS} passes; the pending generation "
        "stays in the store and the next takeover finishes it"
    )


# -- the rotation proper ----------------------------------------------------


def _rotate_locked(
    vault: RotationTarget,
    store: Any | None,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """The rotation, with the process-local lock already held.

    ``stop`` reports the reason to stop, if there is one: a rotation
    that lost the fleet lock's lease, or one the caller called off, is
    no longer the only one rotating the fleet, so it stops.
    """
    # The rotation is a loop because the claim may lose to another
    # rotation that finished between the read and the claim. It then
    # starts over with the generation that is current now.
    start_version = 0
    for _attempt in range(MAX_CLAIM_ATTEMPTS):
        if stop is not None:
            reason = stop()
            if reason is not None:
                raise reason
        km = read_key_meta(vault.db)
        if km is None:
            raise KeyMismatchError("the store has no key metadata")
        if _attempt == 0:
            start_version = km.active_dek_version
        if km.pending_dek_version != 0:
            raise RotationInProgressError(
                f"a rotation to v{km.pending_dek_version} is already in progress"
            )

        try:
            mode = parse_mode(km.crypto_mode)
        except CryptoError as exc:
            raise crypto_mode_unusable(km.crypto_mode, exc) from exc

        if len(km.active_config_shard) != SHARD_SIZE:
            raise config_shard_size_wrong(len(km.active_config_shard))
        s2 = km.active_config_shard

        s1 = load_s1_from_file(s1_path(vault.secrets_dir, km.file_shard_version))
        kek = derive_kek(s1, s2, mode)
        try:
            new_dek = KeyBytes.random(DEK_SIZE)
            wrapped = wrap_dek(mode, kek.bytes(), new_dek.bytes())
        except CryptoError as exc:
            raise VaultError(f"vault: wrap DEK: {exc}") from exc
        finally:
            kek.zero()

        target = km.active_dek_version + 1
        if store is not None:
            # The authority's generation is the truth in the etcd mode: the
            # local row is this node's own bookkeeping and can lag behind
            # the fleet. A target taken from the local row would mint a key
            # for a generation the fleet has already left — two keys under
            # one generation, and records neither of them can open.
            from cred_router.credmgr.etcdstore import read_generation

            try:
                gen, present = read_generation(store.kv, store.ns)
            except Exception as exc:  # noqa: BLE001 - remapped to a vault error
                raise VaultError(
                    f"vault: etcd: read the authority's generation: {exc}"
                ) from exc
            if not present:
                # The authority has no fence yet: nothing has been written
                # to it, and this node's own generation is the only one in
                # play.
                gen = km.active_dek_version
            if km.active_dek_version != gen:
                # This node is behind the fleet. It cannot rotate: the
                # records it would have to re-encrypt are sealed under
                # generations it does not hold. It has to adopt the
                # fleet's current generation first, and say so rather than
                # fail later with an undecryptable record.
                raise StaleGenerationError(
                    f"this node holds generation {km.active_dek_version} and the authority holds {gen}; "
                    f"the node must adopt the fleet's current generation before it rotates"
                )
            target = int(gen) + 1
        old_wrapped = km.wrapped_dek
        old_version = km.active_dek_version

        # Claim the rotation. The guard on the pending marker is what
        # makes this safe against a second rotation: the update only lands
        # when no rotation is pending, and the database decides that
        # atomically.
        #
        # The guard on the active generation is the other half: two
        # rotations that both saw generation v1 would both mint a key for
        # v2 — two data keys under one generation, and records neither
        # could open.
        if _rotate_before_claim_hook is not None:
            _rotate_before_claim_hook()

        if not _claim_rotation(vault, target, wrapped, old_version, stop):
            # Somebody else got there first. Whether that was a rotation
            # in flight or a rotation that finished under us decides
            # whether this is an error, a retry, or a success.
            now = read_key_meta(vault.db)
            if now is not None and now.pending_dek_version != 0:
                raise RotationInProgressError(
                    f"a rotation to v{now.pending_dek_version} is already in progress"
                )
            # Nobody is rotating. Either another rotation finished under
            # us — the generation moved — or the claim lost to something
            # else. Both are a retry: the loop reads the generation that is
            # current now and claims it.
            continue

        _run_claimed_rotation(
            vault,
            store,
            km,
            target,
            KeySnapshot(dek=KeyBytes(new_dek.bytes()), version=target, mode=mode),
            wrapped,
            old_wrapped,
            old_version,
            stop,
        )
        return

    # The claim lost to another rotation, every time. Either one of them is
    # still running, or the store has already moved on.
    now = read_key_meta(vault.db)
    if now is not None:
        if now.pending_dek_version != 0:
            raise RotationInProgressError(
                f"a rotation to v{now.pending_dek_version} is already in progress"
            )
        if now.active_dek_version > start_version:
            vault.reload_snapshot()
            return
    raise RotationInProgressError(
        "the generation kept moving under the rotation"
    )


def _run_claimed_rotation(
    vault: RotationTarget,
    store: Any | None,
    km: KeyMeta,
    target: int,
    target_snap: KeySnapshot,
    wrapped: bytes,
    old_wrapped: bytes,
    old_version: int,
    stop: Callable[[], BaseException | None] | None = None,
) -> None:
    """Converge the records onto the claimed generation and commit."""
    old_active = vault.keys.cur()

    if store is not None:
        # Swap before re-encrypting, so that new writes already use the new
        # key and readers of not-yet-re-encrypted records fall back to the
        # previous one.
        vault.keys.swap(target_snap)

        # The authority's fence moves before the ciphertext, not after:
        # moving it first also stops a node that is lagging behind from
        # writing ciphertext the fleet cannot read.
        _advance_generation(store, target)
    else:
        # The claimed generation goes into the pending slot. It is not the
        # authoritative one until the rotation commits, but the write path
        # stamps new records with it — that is the local equivalent of the
        # authority's generation moving ahead of the ciphertext, and without
        # it the writes of the other processes would keep the rotation from
        # ever committing.
        vault.keys.set_pending(target_snap)

    # Converge, then commit. The two are in a loop because a writer can
    # slip a record in under the old key after the re-encryption pass has
    # already scanned past it. The final count happens under the write
    # barrier, so it sees every write that was in flight; if anything is
    # still behind, the re-encryption runs again rather than the rotation
    # being abandoned with a record no key can open.
    for _attempt in range(MAX_ROTATION_ATTEMPTS):
        if stop is not None:
            reason = stop()
            if reason is not None:
                raise reason
        converge(vault, target_snap, store, stop)

        if store is not None:
            # The etcd mode's records live in the authority, so the final
            # check is against the authority and the local write barrier is
            # what keeps this process's own writers from slipping between
            # the check and the commit.
            with vault.wmu:
                stragglers = count_stragglers(vault, target, store)
                if stragglers > 0:
                    continue

                km.active_dek_version = target
                km.wrapped_dek = wrapped
                km.pending_wrapped_dek = b""
                km.pending_dek_version = 0
                km.superseded_dek_version = old_version
                km.superseded_wrapped_dek = old_wrapped
                km.last_rotate_at = int(time.time())
                update_key_meta(vault.db, km)
            return

        # The local mode: the count and the commit are one write
        # transaction, so a write that lands between them cannot slip past
        # the count.
        if _commit_rotation(vault, target, wrapped, old_wrapped, old_version, stop):
            # The store's generation moved. The snapshot follows.
            vault.keys.replace(target_snap, old_active, None)
            return

        # The commit did not land. Either there are still records under the
        # old generation, or somebody else finished this rotation.
        if rotation_finished_elsewhere(vault, target):
            # Somebody else committed this generation. The store is on it
            # and the records are under it: the rotation is done, whether
            # this process is the one that committed it or not.
            vault.reload_snapshot()
            return

    # The rotation did not converge. The pending generation stays in the
    # store, so the rotation is not lost: a takeover finishes it once the
    # lease goes stale. It is reported as a rotation in progress rather than
    # as a fault, because a store that keeps taking writes is not a fault —
    # it is a rotation that has not caught up yet.
    raise RotationInProgressError(
        "the rotation did not converge: records are still under the old "
        f"key after {MAX_ROTATION_ATTEMPTS} passes; the pending generation "
        "stays in the store and a takeover finishes it"
    )


# -- the authority's side ----------------------------------------------------


def _acquire_fleet_lock(store: Any, leases: Any | None) -> Any:
    """Take the authority's rotation lock.

    The lock is the one thing that keeps two nodes from minting two keys
    for the same generation, so it is taken before anything else
    happens.
    """
    from cred_router.credmgr.etcdstore import acquire_rotation_lock

    if leases is None:
        leases = getattr(store, "leases", None)
    if leases is None:
        raise VaultError(
            "vault: etcd: the rotation lock needs a lease factory; the lock "
            "lives on a lease and a lock without one never expires"
        )
    from cred_router.credmgr.etcdstore.errors import RotationHeldError

    try:
        return acquire_rotation_lock(
            store.kv, leases, store.ns, rotation_holder(), ROTATION_LOCK_TTL_SECONDS
        )
    except RotationHeldError as exc:
        # Another node is rotating the fleet right now. That is the one
        # contention a rotation is allowed to fail on.
        raise RotationInProgressError(
            "another node holds the fleet's rotation lock"
        ) from exc
    except Exception as exc:  # noqa: BLE001 - remapped to a vault error below
        raise VaultError(
            f"vault: etcd: acquire the rotation lock: {exc}"
        ) from exc


def _start_rotation_lock_heartbeat(
    lock: Any,
) -> tuple[Callable[[], None], Callable[[], Exception | None]]:
    """Keep the fleet's rotation lock's lease alive for as long as the rotation runs.

    It returns a function that stops the heartbeat and one that reports
    the renewal failure, if there was one.
    """
    interval = ROTATION_LOCK_TTL_SECONDS / 3
    stop = threading.Event()
    done = threading.Event()
    failures: list[Exception] = []

    def beat() -> None:
        try:
            while not stop.wait(interval):
                try:
                    lock.renew()
                except Exception as exc:  # noqa: BLE001 - reported to the rotation
                    failures.append(exc)
                    return
        finally:
            done.set()

    thread = threading.Thread(
        target=beat, name="vault-rotation-lock-heartbeat", daemon=True
    )
    thread.start()

    def stop_heartbeat() -> None:
        stop.set()
        # The heartbeat may be inside a renewal; it is a daemon thread and
        # the lock is released right after, so the wait is bounded rather
        # than open-ended.
        done.wait(timeout=5.0)

    def failed() -> Exception | None:
        return failures[0] if failures else None

    return stop_heartbeat, failed
