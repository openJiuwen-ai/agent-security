"""The key a fleet of nodes shares.

The nodes of a cluster all encrypt under one data encryption key.  That
key cannot simply be written down somewhere, so it reaches a node
through an exchange: the node publishes a key it generated for that one
exchange, a holder seals the fleet's key to it, and the node throws the
key away afterwards.  Nothing in the authority can open the answer, so
the copy the write-ahead log keeps is inert.

The node identifies itself with the keypair it already presents to the
authority as its client certificate, so cluster participation requires
no new secret: whoever can issue a node a client certificate can
already make it a member.

This package is deliberately independent of what the fleet is keeping:
it produces and consumes a key, and it does not know whether the key
encrypts credentials, records, or anything else.  Two callers in this
repository use it — the credential router's own store and the vault —
and they must not each carry their own copy of the minting, the roster
and the exchange, because the failure modes there are quiet: a node
that invents its own key cannot read anything the rest of the fleet
published, and nothing reports that.

The functions here are synchronous, like the ``etcdstore`` they talk to.
An asynchronous caller runs them through ``asyncio.to_thread``, which is
what the rest of this repository does with its synchronous I/O.
"""

from __future__ import annotations

import base64
import logging
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from security_gateway.crypto import DEK_SIZE

from ..clusterdek import Anchor, new_anchor, public_key_of

__all__ = [
    "AdoptFunc",
    "Config",
    "DEFAULT_FETCH_TIMEOUT",
    "ErrNoPeerSealed",
    "ErrNoPredecessor",
    "HeldDEK",
    "Identity",
    "MINTED_GENERATION",
    "anchor_for",
    "load_identity",
    "obtain",
    "obtain_pair",
]

_log = logging.getLogger(__name__)

#: The generation of a freshly minted fleet key.
#:
#: The mint election succeeds at most once per namespace, so the first
#: mint is always generation 1.
MINTED_GENERATION = 1

#: Bounds how long a node waits for a peer to seal the fleet's key before
#: giving up.
DEFAULT_FETCH_TIMEOUT = 30.0

#: How long a joining node waits for the generation below the fleet's
#: current one.
#:
#: It is an extra, not the key the node needs to start: giving up costs the
#: records still sealed to the older generation until the rewrite reaches
#: them, and nothing else, so it does not get the time the first key gets.
PREDECESSOR_FETCH_TIMEOUT = 10.0


class ClusterKeyError(Exception):
    """The base of every error this package raises."""


class ErrNoPeerSealed(ClusterKeyError):
    """No node sealed the fleet's key for this one in time.

    It is distinct from a transport failure: the authority was reachable
    the whole time, and its answer was that nobody holds the key.
    """


class ErrNoPredecessor(ClusterKeyError):
    """The fleet could not hand over the generation below this node's.

    It is not a failure of the exchange. A fleet that is not rewriting
    anything has no reason to serve that generation, and a fleet whose
    holders predate it cannot serve it at all; either way the caller
    carries on with the current key alone.
    """


@dataclass(frozen=True)
class Config:
    """What the fleet's key management needs to know."""

    #: Identifies this node in the roster. It is the identity this node
    #: answers requests under, so it is required.
    node_id: str = ""

    #: Bounds how long the node waits for a peer to hand the key over, in
    #: seconds. It defaults to :data:`DEFAULT_FETCH_TIMEOUT`.
    fetch_timeout: float = DEFAULT_FETCH_TIMEOUT


@dataclass(frozen=True)
class Identity:
    """A node's wrapping keypair.

    It is the keypair the node presents to the authority, loaded from
    the etcd client certificate rather than generated.
    """

    #: The identity this node answers requests under.
    node_id: str = ""

    #: The private half. It never leaves this process.
    private: ec.EllipticCurvePrivateKey | None = None

    #: The public half.
    public: ec.EllipticCurvePublicKey | None = None

    #: The client certificate the roster vouches for.
    cert: x509.Certificate | None = None


#: ``AdoptFunc`` is called with a generation of the fleet's key that is
#: newer than the one the caller holds.
#:
#: It is a callable rather than a rotator because this package does not
#: know what the key encrypts: the credential router adopts into its
#: keystore and the vault adopts into its own key manager, and neither of
#: those belongs here.
AdoptFunc = Callable[[bytes, int], None]


@dataclass(frozen=True)
class HeldDEK:
    """One generation of the fleet's key a holder can hand over.

    A holder normally has two: the generation in use and the one it
    replaced. Handing over the older generation lets a node that joins
    mid-rotation read the records the rewrite has not reached.
    """

    #: The key material.
    dek: bytes = b""

    #: The generation it belongs to.
    generation: int = 0


def load_identity(node_id: str, cert_file: str, key_file: str) -> Identity:
    """Read a node's wrapping keypair from its client certificate."""
    if not cert_file or not key_file:
        raise ValueError(
            "clusterkey: a client certificate and key are required to seal the fleet's key to this node"
        )
    try:
        cert_pem = Path(cert_file).read_bytes()
    except OSError as exc:
        raise ValueError(f"clusterkey: load the client keypair: {exc}") from exc
    try:
        key_pem = Path(key_file).read_bytes()
    except OSError as exc:
        raise ValueError(f"clusterkey: load the client keypair: {exc}") from exc
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise ValueError(f"clusterkey: parse the client certificate: {exc}") from exc
    try:
        private = serialization.load_pem_private_key(key_pem, password=None)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"clusterkey: load the client keypair: {exc}") from exc
    if not isinstance(private, ec.EllipticCurvePrivateKey):
        raise ValueError(
            f"clusterkey: the client key {key_file} is {type(private).__name__}, but sealing needs ECDSA"
        )
    try:
        public = public_key_of(cert)
    except Exception as exc:
        raise ValueError(f"clusterkey: client certificate: {exc}") from exc
    if public.public_numbers() != private.public_key().public_numbers():
        raise ValueError(
            "clusterkey: the client certificate and the client key are not a pair"
        )
    return Identity(node_id=node_id, private=private, public=public, cert=cert)


def anchor_for(ca_file: str | None, pins: list[str] | None) -> Anchor | None:
    """Build the trust anchor deciding who may hold the fleet's key.

    An anchor that *is* configured but cannot be built — an unreadable
    CA file, a malformed pin — is an error, not a missing anchor.
    """
    if not ca_file and not pins:
        return None
    return new_anchor(ca_file, pins)


def obtain(
    cfg: Config,
    etcd_store,
    self: Identity,
    anchor: Anchor | None,
) -> tuple[bytes, int]:
    """Return the fleet's key this node must use.

    Raises :class:`ErrNoPeerSealed` when nobody answered in time.
    """
    if etcd_store is None or self is None:
        raise ValueError("clusterkey: obtain the fleet's key: no identity")

    _register_node(etcd_store, self)

    # Minting is the one step that cannot be delegated, so it is the one
    # step that needs a trust anchor: a node without one cannot decide
    # which roster entries may be answered, and minting means holding the
    # key for the whole fleet. Such a node still registers, and still
    # adopts from a peer.
    if anchor is None:
        _log.info(
            "no trust anchor is configured; waiting for a peer to hand over the fleet's key instead of minting one",
            extra={"node_id": self.node_id},
        )
    else:
        won = etcd_store.claim_mint(self.node_id)
        if won:
            dek = _random_key()
            _log.info("minted the fleet's key", extra={"node_id": self.node_id})
            # The authority's fence starts here. Until this lands,
            # generation answers 1 and every node's first write is stamped
            # with the generation it already holds.
            etcd_store.advance_generation(MINTED_GENERATION)
            return dek, MINTED_GENERATION

    # Someone else holds the key. Ask for it: publish a request carrying a
    # key generated for this one exchange, and wait for a holder to answer
    # it.
    #
    # The request names generation 0, because this node holds no key. A
    # holder answers only when it holds something strictly newer, so the
    # request stands on its own until the fleet has one.
    from .handover import await_answer, publish_request

    nonce, one_shot = publish_request(etcd_store, self, 0)
    timeout = (
        cfg.fetch_timeout
        if cfg.fetch_timeout and cfg.fetch_timeout > 0
        else DEFAULT_FETCH_TIMEOUT
    )
    try:
        version, dek = await_answer(etcd_store, self, nonce, one_shot, timeout)
    except TimeoutError as exc:
        owner = "<unknown>"
        try:
            owner = etcd_store.mint_owner()
        except Exception:  # noqa: BLE001 - the hint must not mask the failure
            pass
        hint = "check that a holder of the key is running and reachable"
        if anchor is None:
            hint = (
                "no trust anchor is configured here, so this node did not mint "
                "either; set etcd.tls.ca_file or cluster.trusted_cert_sha256 on "
                "at least one node"
            )
        raise ErrNoPeerSealed(
            f"clusterkey: no peer sealed the fleet's key for {self.node_id} "
            f"within {timeout}s (the last mint went to {owner}); {hint}"
        ) from exc
    _log.info(
        "adopted the fleet's key from a peer",
        extra={"node_id": self.node_id, "generation": version},
    )
    return dek, version


def obtain_pair(
    cfg: Config,
    etcd_store,
    self: Identity,
    anchor: Anchor | None,
) -> tuple[bytes, int, bytes]:
    """Return the fleet's key and, while the fleet is rewriting its records, the generation it is replacing.

    The predecessor is best-effort by design: there is nothing to fetch
    when no rotation is under way, and a fleet of older binaries cannot
    serve it.
    """
    dek, generation = obtain(cfg, etcd_store, self, anchor)
    try:
        previous = obtain_predecessor(etcd_store, self, generation)
    except ErrNoPredecessor:
        previous = b""
    except Exception as exc:  # noqa: BLE001 - the predecessor is an extra
        _log.warning(
            "could not fetch the generation below the fleet's current one",
            extra={"node_id": self.node_id, "generation": generation, "error": exc},
        )
        previous = b""
    return dek, generation, previous


def obtain_predecessor(etcd_store, self: Identity, current: int) -> bytes:
    """Fetch the generation below ``current``, but only while a rotation is in progress and heading for ``current``.

    Raises :class:`ErrNoPredecessor` when there is nothing to fetch.
    """
    if current <= 1:
        return b""
    from .authority import ROTATION_STATE_IN_PROGRESS
    from .handover import predecessor

    try:
        state = etcd_store.get_rotation_state()
    except Exception as exc:  # noqa: BLE001 - only "no rotation" is meaningful
        if _is_not_found(exc):
            return b""
        raise ClusterKeyError(f"clusterkey: read the rotation state: {exc}") from exc
    if (
        state.state != ROTATION_STATE_IN_PROGRESS
        or int(state.target_dek_version) != current
    ):
        return b""
    dek, _ = predecessor(etcd_store, self, current, timeout=PREDECESSOR_FETCH_TIMEOUT)
    return dek


def _register_node(etcd_store, self: Identity) -> None:
    """Publish this node's roster entry."""
    from .authority import NodeEntry

    entry = NodeEntry(
        node_id=self.node_id,
        cert_der=base64.b64encode(
            self.cert.public_bytes(serialization.Encoding.DER)
        ).decode("ascii"),
        dek_version=0,
    )
    try:
        existing = etcd_store.get_node(self.node_id)
    except Exception as exc:  # noqa: BLE001 - only "absent" is expected
        if not _is_not_found(exc):
            raise
    else:
        if existing.cert_der != entry.cert_der:
            raise ClusterKeyError(
                f"clusterkey: node id {self.node_id!r} is already registered "
                "with a different certificate; node ids must be unique"
            )
    etcd_store.register_node(entry)


def _random_key() -> bytes:
    """Mint a data encryption key for the fleet."""
    return os.urandom(DEK_SIZE)


def _is_not_found(exc: BaseException) -> bool:
    """Report whether an error means "the key does not exist".

    The ``etcdstore``'s ``NotFoundError`` is the honest answer; the name
    check keeps this working with a store that raises its own.
    """
    return type(exc).__name__ == "NotFoundError" or "not found" in str(exc).lower()
