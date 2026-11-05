"""The fleet's side of a rotation.

A store backed by etcd is not alone in the world: another node may
rotate the same store at the same moment, and two rotations that mint
two keys for one generation leave records under a key no node can open.
This module holds the parts that make a rotation a fleet-wide operation
rather than a local one — the lock that says who is rotating, the gate
that says when the fleet last rotated, the generation fence the
authority keeps, and the count of the records the authority still holds
under an older key.

It is split out of :mod:`cred_router.vault.rotate` so that everything
that talks to the authority sits in one place: the rotation's own order
of operations and the authority it arbitrates with are different
things, and the code that reads and moves the authority's fence is the
code that has to agree with itself.
"""

from __future__ import annotations

import logging
import os
import socket
from typing import Any

from .errors import StaleGenerationError, VaultError
from .keys import KeySnapshot
from .rotate_engine import RotationTarget
from .schema import Schema

_log = logging.getLogger(__name__)


def rotation_holder() -> str:
    """This process's identity in the authority's rotation lock.

    The holder is a process identity, not a node identity: the lock
    belongs to whoever is rotating, and a restarted process is a
    different holder.
    """
    try:
        host = socket.gethostname()
    except OSError:
        host = "unknown-host"
    return f"{host}:{os.getpid()}"


def _fleet_rotation_gate(store: Any) -> int:
    """When the fleet last completed a rotation, as a unix timestamp.

    Zero means the fleet has never rotated: a namespace with no record
    is a fleet that is due, and a caller that cannot tell the two apart
    would freeze a fresh fleet forever.
    """
    from cred_router.credmgr.etcdstore import last_rotation_at
    from cred_router.credmgr.etcdstore.errors import NotFoundError

    try:
        at = last_rotation_at(store.kv, store.ns)
    except NotFoundError:
        return 0
    except Exception as exc:  # noqa: BLE001 - remapped to a vault error
        raise VaultError(
            f"vault: etcd: read the fleet's rotation gate: {exc}"
        ) from exc
    return int(at.timestamp())


def _record_fleet_rotation_gate(store: Any) -> None:
    """Record the fleet's rotation gate.

    Only the node that held the rotation lock writes it, so there is one
    writer per rotation and a later rotation's timestamp is strictly the
    more useful one.
    """
    from datetime import datetime, timezone

    from cred_router.credmgr.etcdstore import set_last_rotation_at

    try:
        set_last_rotation_at(store.kv, store.ns, datetime.now(timezone.utc))
    except Exception as exc:  # noqa: BLE001 - reported, not fatal
        _log.error(
            "vault: etcd: could not record the fleet's rotation gate: %s", exc
        )


def _authority_store(vault: RotationTarget) -> Any | None:
    """The authority's store, when the store has one."""
    authority = getattr(vault, "authority", None)
    if authority is None:
        return None
    return getattr(authority, "store", None)


def count_stragglers(
    vault: RotationTarget, target: int, store: Any | None = None
) -> int:
    """How many records are still under an older key generation."""
    if store is not None:
        return _count_authority_stragglers(store, target)
    return vault.count_stragglers(target)


def _release_fleet_lock(lock: Any) -> None:
    """Drop the authority's rotation lock.

    The error is dropped: the lock's own lease expires on its own if
    this fails, and a rotation that succeeded must not be reported as
    failed because the lock outlived it by a moment.
    """
    try:
        lock.release()
    except Exception:  # noqa: BLE001 - best effort
        pass


def _advance_generation(store: Any, target: int) -> None:
    """Move the authority's generation fence to the target.

    The fence moves before the ciphertext does, so an authority still
    reading the old generation never sees a record written under the new
    one.
    """
    from cred_router.credmgr.etcdstore import advance_generation

    try:
        advanced, current = advance_generation(store.kv, store.ns, target)
    except Exception as exc:  # noqa: BLE001 - remapped to a vault error below
        raise VaultError(
            f"vault: etcd: advance the authority's generation to {target}: {exc}"
        ) from exc
    if not advanced and int(current) != int(target):
        # The fence is not where this rotation put it and the authority did
        # not refuse: the fleet moved under the rotation. Rotating anyway
        # would put this node's key under a generation the fleet already
        # left.
        raise StaleGenerationError(
            f"the authority holds generation {current}, which is not the rotation's {target}"
        )


def _count_authority_stragglers(store: Any, target: int) -> int:
    """How many of the authority's records are under an older key."""
    listed, _revision = store.list_records(0)
    return sum(1 for record in listed if record.entry.dek_version < target)


def _converge_authority(
    vault: RotationTarget, store: Any, cur: KeySnapshot
) -> None:
    """Re-encrypt every record the authority holds that is still under an older key generation.
    """
    from .etcd import EtcdAuthority, converge_authority

    authority = EtcdAuthority.over(store)
    converge_authority(vault, authority, cur)


def _reencrypt_payload(
    data: bytes, schema: Schema, src: KeySnapshot, cur: KeySnapshot
) -> bytes:
    """Re-encrypt a record's encrypted fields from the key the record is under to the current one.
    """
    from .etcd import reencrypt_record_payload

    return reencrypt_record_payload(data, schema, src, cur)
