"""The vault's half of the cluster handover protocol.

A fleet of nodes shares one data encryption key, and a node that joins
later gets that key from a peer through a handover that is sealed to a
one-shot key and signed with the node's own client certificate. The
arrangement itself belongs to the ``clusterkey`` package.

What is different here is *which* key and *where* it lives.

**The key is the vault's own.** The vault's key material is a separate
system from the credential store's keystore: its own shards, its own
salt, its own domain separation. Nothing here may be taken from the
router's keystore, and nothing in the router's keystore may be taken
from here.

**The namespace is the vault's own.** The router's credentials and the
vault's records live in one etcd keyspace, and the two also share the
cluster handover keys: the roster, the mint record and the sealed
answers. A shared namespace would have the vault's handover and the
router's handover fight over the same keys, and two fleets claiming one
keyspace is a failure that only shows up in a cluster deployment. The
vault therefore works under the operator's ``etcd.namespace`` plus
:data:`VAULT_NAMESPACE_SUFFIX`.

**The identity comes from the etcd client certificate**, the same way
the router's does: whoever can issue the node a cluster certificate
already controls who can participate.
"""

from __future__ import annotations

import logging
import queue
import threading
from dataclasses import dataclass
from typing import Any, Callable

from cred_router.credmgr.clusterdek import Anchor, Fingerprint
from cred_router.credmgr.clusterkey.clusterkey import (
    Config as ClusterKeyConfig,
)
from cred_router.credmgr.clusterkey.clusterkey import (
    HeldDEK,
    Identity,
    anchor_for,
    load_identity,
    obtain_pair,
)
from cred_router.credmgr.clusterkey.handover import (
    answer_requests,
    ask_for_newer_key,
)
from cred_router.credmgr.clusterkey.wake import (
    start_rounds,
    start_ticks,
    wake,
)

from .errors import KeyMismatchError
from .keys import AdoptedDEK, KeySnapshot

_log = logging.getLogger(__name__)

__all__ = [
    "CLUSTER_WRAP_INTERVAL",
    "VAULT_NAMESPACE_SUFFIX",
    "EtcdConfig",
    "TLSConfig",
    "cluster_anchor_for",
    "held_deks",
    "load_cluster_identity",
    "obtain_cluster_dek",
    "serve_cluster_wrapping",
    "vault_etcd_config",
    "vault_namespace",
]

#: The suffix that separates the vault's keys from the router's.
#:
#: A suffix keeps the two apart without a second etcd to point at.
VAULT_NAMESPACE_SUFFIX = "-vault"

#: How often a node holding the vault's key answers the requests that are
#: waiting for it.
#:
#: Joining is rare and a joining node waits out its fetch timeout, so a
#: coarse interval costs nothing.
CLUSTER_WRAP_INTERVAL = 5.0

#: How often a waiting loop checks whether it has been asked to stop.
#:
#: It is short enough that a shutdown is not held up by the tick and long
#: enough that a loop waiting on nothing does not spin.
_ROUND_POLL_SECONDS = 0.25


# -- the vault's own view of the etcd deployment ---------------------------


@dataclass(frozen=True)
class TLSConfig:
    """The etcd TLS material the vault presents.

    The certificate the node presents is also the keypair it seals the
    vault's key with.
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


# These two are here because this configuration and the vault's own are
# used interchangeably: the runtime builds one of these and the vault's
# dialer reads it as its own.
@dataclass(frozen=True)
class EtcdConfig:
    """The vault's own view of the etcd deployment.

    It is *not* the router's platform configuration: the namespace here
    is the vault's own, and the node id and the pinned certificates are
    the ones the vault hands the vault's key over under.
    """

    #: The etcd endpoints.
    endpoints: tuple[str, ...] = ()

    #: The keyspace the vault keeps its records *and* its handover keys in.
    #: It is the operator's namespace plus :data:`VAULT_NAMESPACE_SUFFIX`.
    namespace: str = ""

    #: How long the dial may take.
    dial_timeout: float = 0.0

    #: The identity this node answers requests under.
    node_id: str = ""

    #: The SHA-256 fingerprints of the certificates the fleet's key may be
    #: handed to, when no CA file is configured.
    trusted_cert_sha256: tuple[str, ...] = ()

    #: Bounds how long this node waits for a peer to seal the vault's key
    #: before it gives up, in seconds.
    fetch_timeout: float = 0.0

    #: The TLS material, or ``None`` when the deployment has none.
    tls: TLSConfig | None = None


def vault_namespace(namespace: str) -> str:
    """Return the keyspace the vault keeps its keys in.

    It is the operator's namespace plus :data:`VAULT_NAMESPACE_SUFFIX`.
    The vault's records and the router's credentials share one etcd, so
    the two must not share one keyspace.
    """
    return f"{namespace or ''}{VAULT_NAMESPACE_SUFFIX}"


def vault_etcd_config(cfg: Any) -> EtcdConfig:
    """Map the operator's configuration onto the vault's own."""
    etcd = cfg.etcd
    cluster = cfg.cluster
    tls = getattr(etcd, "tls", None)
    fetch_timeout = cluster.fetch_timeout
    if hasattr(fetch_timeout, "total_seconds"):
        fetch_timeout = fetch_timeout.total_seconds()
    # The platform holds a duration; the vault holds seconds. A timedelta is
    # not a number, and float() on one is a TypeError.
    dial_timeout = getattr(etcd, "dial_timeout", 0.0)
    if hasattr(dial_timeout, "total_seconds"):
        dial_timeout = dial_timeout.total_seconds()
    out = EtcdConfig(
        endpoints=tuple(etcd.endpoints or ()),
        namespace=vault_namespace(getattr(etcd, "namespace", "") or ""),
        dial_timeout=dial_timeout,
        node_id=cluster.node_id,
        trusted_cert_sha256=tuple(cluster.trusted_cert_sha256 or ()),
        fetch_timeout=float(fetch_timeout or 0.0),
    )
    # The TLS material only when there is any: an empty set of paths handed
    # to the client is a FileNotFoundError on "".
    tls_named = bool(tls.ca_file or tls.cert_file or tls.key_file) if tls else False
    if tls is not None and tls_named:
        out = EtcdConfig(
            endpoints=out.endpoints,
            namespace=out.namespace,
            dial_timeout=out.dial_timeout,
            node_id=out.node_id,
            trusted_cert_sha256=out.trusted_cert_sha256,
            fetch_timeout=out.fetch_timeout,
            tls=TLSConfig(
                ca_file=tls.ca_file or "",
                cert_file=tls.cert_file or "",
                key_file=tls.key_file or "",
            ),
        )
    return out


# -- the cluster identity and the trust anchor ----------------------------


def load_cluster_identity(cfg: EtcdConfig) -> Identity:
    """Read this node's wrapping keypair from the etcd client certificate it already presents.
    """
    tls = cfg.tls or TLSConfig()
    identity = load_identity(cfg.node_id, tls.cert_file, tls.key_file)
    _log.info(
        "cluster identity ready",
        extra={
            "node_id": identity.node_id,
            "cert_fingerprint_sha256": Fingerprint(identity.cert),
        },
    )
    return identity


def cluster_anchor_for(cfg: EtcdConfig) -> Anchor | None:
    """Build the trust anchor that decides which certificates the vault's key may be handed to.

    ``None`` means "this node hands nothing over": such a node still
    serves traffic and still adopts a key from a peer, it just never
    mints and never answers a request.
    """
    tls = cfg.tls or TLSConfig()
    ca_file = (tls.ca_file or "").strip()
    pins = list(cfg.trusted_cert_sha256 or [])
    if ca_file == "" and not pins:
        _log.warning(
            "cluster mode is on but no trust anchor is configured; this node "
            "will not mint the fleet's key and will not hand it to new peers"
        )
        return None
    anchor = anchor_for(ca_file, pins)
    if anchor is None:
        # Only reachable when nothing was configured, which the branch
        # above already handled.
        return None
    if anchor.pins_take_over() and anchor.has_ca():
        _log.warning(
            "both etcd.tls.ca_file and cluster.trusted_cert_sha256 are set; "
            "the pin list alone decides which certificates the vault's key is "
            "handed to, and the CA is not consulted",
            extra={"pinned_certificates": len(pins)},
        )
    return anchor


# -- the fleet's key -------------------------------------------------------


def obtain_cluster_dek(
    cfg: EtcdConfig,
    authority: Any,
    self_identity: Identity | None,
    anchor: Anchor | None,
) -> AdoptedDEK | None:
    """Return the key this node must use, and the one it replaces.

    It never mints unless this node wins the one-node election, and it
    never falls back to minting on failure: a node that invented its own
    key would be unable to read anything the rest of the fleet
    published.
    """
    if authority is None or self_identity is None:
        return None
    try:
        dek, generation, previous = obtain_pair(
            ClusterKeyConfig(
                node_id=self_identity.node_id,
                fetch_timeout=cfg.fetch_timeout,
            ),
            authority,
            self_identity,
            anchor,
        )
    except Exception as exc:
        from cred_router.credmgr.clusterkey.clusterkey import ErrNoPeerSealed

        if isinstance(exc, ErrNoPeerSealed):
            raise KeyMismatchError(f"{exc}") from exc
        raise
    return AdoptedDEK(dek=dek, version=int(generation), previous=previous)


def held_deks(
    current: KeySnapshot | None, previous: KeySnapshot | None
) -> list[HeldDEK]:
    """List the generations of the vault's key this node can hand over."""
    held: list[HeldDEK] = []
    for snap in (current, previous):
        if snap is None:
            continue
        dek = snap.dek_bytes()
        if not dek:
            continue
        held.append(HeldDEK(dek=dek, generation=int(snap.version)))
    return held


# -- the background loop ---------------------------------------------------


def serve_cluster_wrapping(
    stop: threading.Event,
    authority: Any,
    self_identity: Identity,
    snapshot: Callable[[], KeySnapshot | None],
    previous: Callable[[], KeySnapshot | None],
    anchor: Anchor | None = None,
    adopt: Callable[[bytes, int], None] | None = None,
    interval: float = CLUSTER_WRAP_INTERVAL,
    watch_store: Any | None = None,
) -> None:
    """Answer the handover requests this node can serve, and ask for a newer generation when it holds an old one.
    """
    if anchor is None:
        # Nothing here would ever be handed over, so running the loop
        # would only produce a warning every few seconds. Serve traffic
        # regardless: a node that holds the key can decrypt every record
        # it is asked for without handing anything to anyone.
        _log.warning(
            "serving without a trust anchor: the vault's key will not be "
            "handed to new peers",
            extra={"node_id": self_identity.node_id},
        )
        return

    # asked_generation is the generation the outstanding standing request
    # names. It changes when the node adopts one, which is when a new
    # request has to go out.
    ticks = start_ticks(interval, stop)
    rounds = start_rounds(ticks, wake(watch_store))

    asked_generation = -1
    while not stop.is_set():
        # The round comes first and the work afterwards: a round that starts
        # before the wake channel is opened would answer requests nobody
        # has published yet, and the node would then sit on its answer until
        # the next tick.
        if not _wait_for_round(rounds):
            continue

        current = snapshot()
        if current is None:
            # A node with no key has nothing to seal for anybody and no
            # generation to announce.
            _log.warning(
                "the vault holds no key; the handover loop stops here",
                extra={"node_id": self_identity.node_id},
            )
            return
        dek_version = int(current.version)

        # Answer the requests that name a generation this node holds. The
        # answer is sealed to the requester's one-shot key and opens for the
        # requester and for nobody else, which is what makes the copy the
        # write-ahead log keeps inert.
        #
        # Both generations go in: a node that joins during a rotation asks
        # for the older one after taking the newer, and the older one is
        # what lets it read the records the rewrite has not reached.
        try:
            answered = int(
                answer_requests(
                    authority,
                    self_identity,
                    anchor,
                    held_deks(current, previous()),
                )
            )
        except Exception as exc:  # noqa: BLE001 - the next round retries
            _log.warning("could not answer the handover requests", extra={"error": exc})
            answered = 0
        if answered > 0:
            _log.info(
                "answered the handover requests",
                extra={"answered": answered, "generation": dek_version},
            )

        # The node's standing request: "I hold generation N, give me
        # something newer". It is published once and answered whenever a
        # holder has something newer, so the node does not have to notice
        # that the fleet moved on before it can ask for the result of it.
        if dek_version != asked_generation:
            asked_generation = dek_version
            try:
                ask_for_newer_key(
                    authority,
                    self_identity,
                    asked_generation,
                    lambda dek, generation: _adopt_newer_generation(
                        self_identity, dek_version, dek, generation, adopt
                    ),
                )
            except Exception as exc:  # noqa: BLE001 - the next round retries
                _log.warning(
                    "could not ask the fleet for a newer key generation",
                    extra={"error": exc, "generation": asked_generation},
                )


def _wait_for_round(rounds: Any) -> bool:
    """Wait for the next round, and say whether one arrived.

    A timeout is not a round: the timer and the watch are the two things
    that start a round, and a loop that did work on a timeout would be
    running rounds it should not.
    """
    try:
        rounds.get(timeout=_ROUND_POLL_SECONDS)
    except queue.Empty:
        return False
    return True


def _adopt_newer_generation(
    self_identity: Identity,
    local_generation: int,
    dek: bytes,
    fleet_generation: int,
    adopt: Callable[[bytes, int], None] | None,
) -> None:
    """Take the fleet's newer key, in place.

    A failure is logged and the standing request stays put: the next
    round asks again, and the node keeps serving under the generation it
    holds.
    """
    if adopt is None:
        _log.warning(
            "the vault's key has advanced and this node cannot adopt it",
            extra={
                "node_id": self_identity.node_id,
                "local_generation": local_generation,
                "fleet_generation": fleet_generation,
            },
        )
        return
    try:
        adopt(dek, fleet_generation)
    except Exception as exc:  # noqa: BLE001 - reported, not fatal
        _log.warning(
            "could not adopt the fleet's newer key generation",
            extra={
                "node_id": self_identity.node_id,
                "local_generation": local_generation,
                "fleet_generation": fleet_generation,
                "error": str(exc),
            },
        )
        return
    _log.info(
        "adopted the fleet's newer key generation",
        extra={
            "node_id": self_identity.node_id,
            "local_generation": local_generation,
            "fleet_generation": fleet_generation,
        },
    )
