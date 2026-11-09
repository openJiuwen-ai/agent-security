"""The store's half of the cluster: the authority and the fleet's key.

A store that has an authority writes through it and keeps a local
mirror of what the authority holds; the fleet shares one key, and a node
that missed a rotation adopts the fleet's newer generation when it
learns of it. Those concerns are gathered here so that the vault module
holds the store itself rather than the cluster's protocol.

The mixin uses only what the store provides — its keys, its database,
its authority and its locks — so the two halves stay apart: the store
owns the behaviour, and this module owns what it does with a fleet.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from .errors import ClosedError, KeyMismatchError
from .store import count_stragglers

_log = logging.getLogger(__name__)

__all__ = ["AuthorityMixin"]


class AuthorityMixin:
    """The store's cluster-authority half.

    The methods here need the store's own state — its keys, its
    database, its authority and its write barrier — and take it from the
    instance they are called on.
    """

    def _seed_fleet_rotation_gate(self) -> None:
        """Record when the fleet's rotation gate was last passed, if it has none yet."""
        from datetime import datetime, timezone

        from security_gateway.credmgr.etcdstore import (
            last_rotation_at,
            set_last_rotation_at,
        )
        from security_gateway.credmgr.etcdstore.errors import NotFoundError

        store = self.authority.store
        try:
            last_rotation_at(store.kv, store.ns)
        except NotFoundError:
            try:
                set_last_rotation_at(store.kv, store.ns, datetime.now(timezone.utc))
            except Exception as exc:  # noqa: BLE001 - reported, not fatal
                _log.warning("vault: could not seed the fleet's rotation gate: %s", exc)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            _log.warning("vault: could not read the fleet's rotation gate: %s", exc)

    def start_authority(
        self,
        cfg: Any,
        self_identity: Any,
        anchor: Any,
        cluster_store: Any,
        leader: Any = None,
    ) -> None:
        """Bring the authority's background loops up.

        They answer different questions:

        * the **mirror** keeps this node's database in step with the
          authority.
        * the **sealing loop** answers the handover requests this node
          can serve, and asks for a newer generation when it holds an
          old one.
        * the **key watch** follows generations another process
          committed and finishes a pending rotation it finds.
        """
        # The authority's generation and this store's have to agree. They
        # are the same key: a node holding generation 3 against an authority
        # at generation 4 would write ciphertext the fleet cannot read, and
        # would read records it cannot open.
        try:
            generation = int(self.authority.generation())
        except Exception:  # noqa: BLE001 - an absent generation is zero
            generation = 0
        local = 0
        cur = self.keys.cur()
        if cur is not None:
            local = int(cur.version)
        pending = self.keys.pend()
        pending_version = int(pending.version) if pending is not None else 0
        if generation and generation != local:
            shared_pending = self._shared_key_meta and pending_version == generation
            catching_up = self._shared_key_meta and generation > local
            if leader is None and not shared_pending and not catching_up:
                raise KeyMismatchError(f"the authority holds key generation {generation} and this store holds {local}")

        # The fleet's rotation gate is seeded when the fleet forms.
        self._seed_fleet_rotation_gate()

        if pending is not None:
            from .rotate import finish_pending_rotation

            finish_pending_rotation(self, self.authority.store)

        from .mirror import serve_mirror

        stop = threading.Event()
        self._mirror_stop = stop
        self._mirror_thread = threading.Thread(
            target=serve_mirror,
            args=(
                stop,
                self.authority.store,
                self.db,
                self._local_dek_version,
                self.authority.store.watch_source,
            ),
            name="cred-router-vault-mirror",
            daemon=True,
        )
        self._mirror_thread.start()

        if self_identity is not None and cluster_store is not None:
            from .cluster import serve_cluster_wrapping

            wrap_stop = threading.Event()
            self._wrap_stop = wrap_stop
            self._wrap_thread = threading.Thread(
                target=serve_cluster_wrapping,
                args=(
                    wrap_stop,
                    cluster_store,
                    self_identity,
                    self.keys.cur,
                    self.keys.prev,
                    anchor,
                    self.adopt_cluster_dek,
                ),
                # The watch is opened on the record store, which is the
                # one that can open one. The cluster store above is the
                # roster, the mint election and the handover log.
                kwargs={"watch_store": self.authority.store},
                name="cred-router-vault-cluster-wrap",
                daemon=True,
            )
            self._wrap_thread.start()

        if self._shared_key_meta:
            key_stop = threading.Event()
            self._key_stop = key_stop
            self._key_thread = threading.Thread(
                target=self._watch_key_generations,
                args=(key_stop,),
                name="cred-router-vault-key-watch",
                daemon=True,
            )
            self._key_thread.start()

    def _watch_key_generations(self, stop: threading.Event) -> None:
        """Follow a generation another process committed."""
        from .keys import read_key_meta
        from .rotate import finish_pending_rotation

        while not stop.wait(1.0):
            try:
                generation = int(self.authority.generation())
            except Exception:  # noqa: BLE001 - the next tick retries
                continue
            if generation and self.keys.by_version(generation) is None:
                try:
                    self.reload_snapshot()
                except Exception as exc:  # noqa: BLE001 - the next tick retries
                    _log.warning("vault: could not reload the newer key generation: %s", exc)
            km = read_key_meta(self.db)
            if km is not None and km.pending_dek_version != 0:
                try:
                    finish_pending_rotation(self, self.authority.store)
                except Exception as exc:  # noqa: BLE001 - the next tick retries
                    _log.info("vault: the pending rotation is not finished yet: %s", exc)

    def count_stragglers(self, target: int) -> int:
        """How many records are still under an older key generation."""
        return count_stragglers(self.db, target)

    def converge_stragglers(self) -> None:
        """Re-encrypt every record that is still under an older key generation."""
        from .rotate import converge_to

        cur = self.keys.cur()
        if cur is None:
            raise ClosedError("the store has no key")
        converge_to(self, cur)

    def takeover_pending(self) -> None:
        """Finish a rotation that was left unfinished.

        Finishing it means adopting the pending generation — the key
        that is already in the store, never a new one — re-encrypting
        the records that are still under the old generation, and
        committing the result.
        """
        from .rotate import takeover_pending

        takeover_pending(self)

    def adopt_cluster_dek(self, dek: bytes, generation: int) -> None:
        """Install the fleet's newer generation on this node."""
        from security_gateway.crypto import KeyBytes, parse_mode, wrap_dek
        from security_gateway.vault.keys import (
            KeySnapshot,
            derive_kek,
            load_s1_from_file,
            read_key_meta,
            s1_path,
            update_key_meta,
        )

        km = read_key_meta(self.db)
        if km is None:
            raise KeyMismatchError("the store has no key metadata")
        if int(generation) <= int(km.active_dek_version):
            # The node is already at that generation, or past it.
            return

        mode = parse_mode(km.crypto_mode)
        s2 = bytes(km.active_config_shard)
        s1 = load_s1_from_file(s1_path(self.secrets_dir, km.file_shard_version))
        kek = derive_kek(s1, s2, mode)
        try:
            wrapped = wrap_dek(mode, kek.bytes(), dek)
        finally:
            kek.zero()

        old = self.keys.cur()
        old_version = km.active_dek_version
        old_wrapped = km.wrapped_dek

        km.active_dek_version = int(generation)
        km.wrapped_dek = wrapped
        km.superseded_dek_version = old_version
        km.superseded_wrapped_dek = old_wrapped
        km.pending_dek_version = 0
        km.pending_wrapped_dek = b""
        km.updated_at = int(time.time())
        update_key_meta(self.db, km)

        # The snapshot follows the row: the new generation is current, the one
        # it replaces is the previous one, and nothing is pending.
        self.keys.replace(
            KeySnapshot(dek=KeyBytes(dek), version=int(generation), mode=mode),
            old,
            None,
        )

        # The mirror caught up with the rotation while this node was behind
        # it, and the rows it could not open were withheld: the watch will
        # not deliver them again — they did not change — so the mirror is
        # reconciled by hand, once, now that this node can open them.
        try:
            self._reconcile_mirror()
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            _log.warning(
                "vault: could not reconcile the mirror after adopting a newer generation: %s",
                exc,
            )

    def _reconcile_mirror(self) -> None:
        """Re-apply the authority's records to the local mirror."""
        authority = getattr(self, "authority", None)
        if authority is None:
            return
        from .mirror import MirrorApplier, RecordSource

        source = RecordSource(authority.store, authority.store.watch_source)
        listing = source.list_entries()
        applier = MirrorApplier(self.db, self._local_dek_version)
        applier.reconcile(listing.items)
