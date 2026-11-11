"""The handover: how a joining node gets the fleet's key.

The handover is a session, not a store.

A node that needs the fleet's key publishes a request carrying a key it
generated for this one exchange, a holder seals the key to that key, and
the requester opens the answer and throws the key away.  Nothing in the
authority can open the answer afterwards, so the copy the write-ahead
log keeps is inert.

The request is signed with the node's etcd client key, and the holder
checks that signature against the certificate the roster already vouches
for.  An unsigned request would hand the fleet's key to whoever asked:
anyone who can write to the authority could publish a key of their own
and be answered.

The arrangement lives here rather than in a caller because there are
two callers — the credential router's own store and the vault — and a
second copy of it is a second place for the quiet failure to be in: a
node that invents its own key cannot read anything the rest of the fleet
published, and nothing reports that.
"""

from __future__ import annotations

import logging
import os
import threading
import time

from cryptography.hazmat.primitives.asymmetric import ec

from ..clusterdek import (
    Anchor,
    HandoverRequest,
    marshal_public_key,
    parse_public_key,
    unwrap,
    verify_request,
    wrap,
    marshal_request,
    unmarshal_request,
)
from .clusterkey import (
    AdoptFunc,
    ClusterKeyError,
    ErrNoPredecessor,
    HeldDEK,
    Identity,
)
from .fault import HANDOVER_ANSWERED_STAGE, invoke_handover_fault

__all__ = [
    "ask_for_newer_key",
    "answer_requests",
    "predecessor",
    "request_generation",
]

_log = logging.getLogger(__name__)

#: How many random bytes a nonce carries. It only has to be unique among
#: the requests of one node, and a node publishes at most one at a time.
HANDOVER_NONCE_LENGTH = 16

#: How long a requester waits between looks for an answer.
#:
#: It is short because waiting is not the only thing the requester has to
#: notice: the generation it asked for can move while it waits, and only a
#: fresh look notices that.
HANDOVER_ANSWER_POLL_INTERVAL = 0.2

#: How long a request for a specific generation waits for its answer.
DEFAULT_REQUEST_TIMEOUT = 30.0


def publish_request(
    etcd_store,
    self: Identity,
    generation: int,
    *,
    latest: bool = False,
) -> tuple[str, ec.EllipticCurvePrivateKey]:
    """Ask the fleet for a key newer than the one the requester holds.

    The node generates a one-shot keypair, signs the request with its
    etcd client key, and publishes it. The private half never leaves
    this process and is discarded once the answer has been opened.
    """
    if etcd_store is None or self is None:
        raise ValueError("clusterkey: publish a handover request: no identity")
    nonce = os.urandom(HANDOVER_NONCE_LENGTH).hex()
    one_shot = ec.generate_private_key(ec.SECP256R1())
    request = HandoverRequest(
        node_id=self.node_id,
        generation=int(generation),
        nonce=nonce,
        public_key=marshal_public_key(one_shot.public_key()),
        latest=latest,
    )
    request.sign(self.private)
    payload = marshal_request(request)
    etcd_store.put_handover_request(self.node_id, nonce, payload)
    return nonce, one_shot


def _clear_handover(etcd_store, node_id: str, nonce: str) -> None:
    """Delete both halves of an exchange, reporting rather than raising."""
    try:
        etcd_store.delete_handover(node_id, nonce)
    except Exception as exc:  # noqa: BLE001 - the exchange is already over
        _log.warning(
            "could not clear the handover exchange",
            extra={"node_id": node_id, "error": exc},
        )


def await_answer(
    etcd_store,
    self: Identity,
    nonce: str,
    one_shot: ec.EllipticCurvePrivateKey,
    timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
    poll_interval: float = HANDOVER_ANSWER_POLL_INTERVAL,
) -> tuple[int, bytes]:
    """Wait for a holder to answer and open the answer.

    Raises :class:`TimeoutError` when no answer arrives in time.
    """
    if etcd_store is None or self is None:
        raise ValueError("clusterkey: await a handover answer: no identity")
    if one_shot is None:
        raise ValueError("clusterkey: await a handover answer: no one-shot key")

    deadline = None if timeout is None else time.monotonic() + timeout
    while True:
        try:
            version, sealed = etcd_store.get_handover_sealed(self.node_id, nonce)
        except Exception as exc:  # noqa: BLE001 - only "not there yet" is benign
            if not _is_not_found(exc):
                raise
        else:
            # The exchange is over either way: an answer that does not open
            # is not going to start opening later. Clear it even when unwrap
            # fails, otherwise the request and the sealed answer stay in etcd
            # forever and every holder keeps verifying a dead request.
            try:
                dek = unwrap(one_shot, sealed)
            except BaseException:
                _clear_handover(etcd_store, self.node_id, nonce)
                raise
            _clear_handover(etcd_store, self.node_id, nonce)
            return version, dek
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError(f"clusterkey: no handover answer for {self.node_id} within {timeout}s")
        time.sleep(poll_interval)


def request_generation(
    etcd_store,
    self: Identity,
    generation: int,
    timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
) -> tuple[int, bytes]:
    """Ask the fleet for a specific generation of the key."""
    nonce, one_shot = publish_request(etcd_store, self, int(generation) - 1)
    return await_answer(etcd_store, self, nonce, one_shot, timeout)


def predecessor(
    etcd_store,
    self: Identity,
    current: int,
    timeout: float | None = DEFAULT_REQUEST_TIMEOUT,
) -> tuple[bytes, int]:
    """Ask the fleet for the generation below ``current``."""
    if current <= 2:
        raise ErrNoPredecessor("clusterkey: no peer offered the generation below the one this node holds")
    version, dek = request_generation(etcd_store, self, current - 1, timeout)
    if version != current - 1:
        raise ErrNoPredecessor("clusterkey: no peer offered the generation below the one this node holds")
    return dek, version


def answer_requests(
    etcd_store,
    self: Identity,
    anchor: Anchor | None,
    held: list[HeldDEK],
) -> int:
    """Answer the requests this holder can serve.

    A request whose signature does not verify against the certificate
    the roster vouches for is refused. That is the whole reason the
    request is signed.
    """
    if etcd_store is None or self is None:
        return 0

    requests = etcd_store.list_handover_requests()
    answered = 0
    for entry in requests:
        try:
            request = unmarshal_request(entry.payload)
        except Exception as exc:  # noqa: BLE001 - a bad request is skipped
            _log.warning(
                "ignoring a handover request that could not be read",
                extra={"node_id": entry.node_id, "error": exc},
            )
            continue
        if request.node_id != entry.node_id or request.nonce != entry.nonce:
            _log.warning(
                "ignoring a handover request whose identity does not match the key it is under",
                extra={"node_id": entry.node_id},
            )
            continue
        if request.node_id == self.node_id:
            # A node never has anything newer than itself to hand itself, and
            # answering its own request would consume it: the requester opens
            # the answer and deletes the exchange with it. The node would then
            # believe it is still asking, while the request is gone from the
            # authority, and nothing would publish another one — so it would
            # never hear about the next rotation.
            continue
        serve = answer_for(held, request.generation, latest=request.latest)
        if serve is None:
            continue
        try:
            roster = etcd_store.get_node(request.node_id)
        except Exception as exc:  # noqa: BLE001 - an unknown requester is skipped
            _log.warning(
                "cannot answer a handover request: the requester is not in the roster",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        try:
            cert = _roster_certificate(roster)
        except Exception as exc:  # noqa: BLE001 - an unusable entry is skipped
            _log.warning(
                "cannot answer a handover request: the roster entry carries no usable certificate",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        # The certificate has to be one the trust anchor vouches for before
        # its key means anything. Without that check anyone who can write to
        # the authority could replace the roster entry with a certificate of
        # their own and sign the request with it.
        if anchor is None:
            _log.error(
                "refusing a handover request: this node has no trust anchor, so "
                "it cannot decide who may hold the fleet's key",
                extra={"node_id": request.node_id},
            )
            continue
        try:
            anchor.verify(cert)
        except Exception as exc:  # noqa: BLE001 - an untrusted requester is skipped
            _log.error(
                "refusing a handover request: the requester's certificate is not trusted",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        try:
            cert_public = cert.public_key()
            if not isinstance(cert_public, ec.EllipticCurvePublicKey):
                raise ClusterKeyError(f"clusterkey: the roster entry carries {type(cert_public).__name__}, want ECDSA")
            verify_request(cert_public, request)
        except Exception as exc:  # noqa: BLE001 - a bad signature is skipped
            _log.error(
                "refusing a handover request whose signature does not verify",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        try:
            one_shot = parse_public_key(request.public_key)
        except Exception as exc:  # noqa: BLE001 - an unusable key is skipped
            _log.warning(
                "cannot answer a handover request: the one-shot key is unusable",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        # A request that has already been answered is left alone. Re-sealing it
        # would publish a fresh ciphertext for a key the requester has already
        # opened, and every pass would leave another copy in the write-ahead log
        # for no gain.
        try:
            etcd_store.get_handover_sealed(request.node_id, request.nonce)
        except Exception as exc:  # noqa: BLE001 - only "not answered" is benign
            if not _is_not_found(exc):
                _log.warning(
                    "cannot answer a handover request: reading the answer failed",
                    extra={"node_id": request.node_id, "error": exc},
                )
                continue
        else:
            continue
        try:
            sealed = wrap(one_shot, serve.dek)
        except Exception as exc:  # noqa: BLE001 - a failed seal is skipped
            _log.warning(
                "cannot answer a handover request: sealing the key failed",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        try:
            etcd_store.put_handover_sealed(request.node_id, request.nonce, serve.generation, sealed)
        except Exception as exc:  # noqa: BLE001 - a failed write is skipped
            _log.warning(
                "cannot answer a handover request: publishing the answer failed",
                extra={"node_id": request.node_id, "error": exc},
            )
            continue
        answered += 1
        # Between the answer being published and the next request being
        # answered. A process that dies here leaves some requests answered
        # and some not, and the next pass has to pick the rest up.
        invoke_handover_fault(HANDOVER_ANSWERED_STAGE)
    return answered


def answer_for(
    held: list[HeldDEK],
    want: int,
    *,
    latest: bool = False,
) -> HeldDEK | None:
    """Pick the generation to hand a requester that holds ``want``.

    ``latest`` asks for the newest generation, which is what a node that
    is catching up wants. Without it the answer is the oldest generation
    above ``want``, which is what a predecessor lookup needs: it must be
    exactly the next generation, not the newest one.
    """
    choice: HeldDEK | None = None
    for candidate in held:
        if not candidate.dek or candidate.generation <= want:
            continue
        if choice is None:
            choice = candidate
            continue
        if latest or want == 0:
            if candidate.generation > choice.generation:
                choice = candidate
            continue
        if candidate.generation < choice.generation:
            choice = candidate
    return choice


def ask_for_newer_key(
    etcd_store,
    self: Identity,
    generation: int,
    adopt: AdoptFunc | None,
) -> threading.Thread:
    """Publish the node's standing request and hand the answer to a thread of its own.

    The thread it returns is a daemon: the request stands until it is
    answered, so the thread waits without a deadline, and a node that is
    shutting down must not be held up by it.
    """
    try:
        nonce, one_shot = publish_request(etcd_store, self, int(generation), latest=True)
    except Exception as exc:  # noqa: BLE001 - a failed request is not fatal
        _log.warning(
            "could not ask the fleet for a newer key generation",
            extra={"node_id": self.node_id, "generation": generation, "error": exc},
        )
        raise
    thread = threading.Thread(
        target=_await_and_adopt,
        args=(etcd_store, self, nonce, one_shot, adopt),
        name=f"cluster-handover-{self.node_id}",
        daemon=True,
    )
    thread.start()
    return thread


def _await_and_adopt(
    etcd_store,
    self: Identity,
    nonce: str,
    one_shot: ec.EllipticCurvePrivateKey,
    adopt: AdoptFunc | None,
) -> None:
    """Wait for the answer to a standing request and adopt it."""
    try:
        version, dek = await_answer(etcd_store, self, nonce, one_shot, timeout=None)
    except Exception as exc:  # noqa: BLE001 - the failure is reported, not raised
        _log.warning(
            "could not open the newer fleet key",
            extra={"node_id": self.node_id, "error": exc},
        )
        return
    if adopt is None:
        return
    try:
        adopt(dek, version)
    except Exception as exc:  # noqa: BLE001 - the failure is reported, not raised
        _log.warning(
            "could not adopt the newer fleet key",
            extra={"node_id": self.node_id, "generation": version, "error": exc},
        )


def _roster_certificate(roster) -> object:
    """Parse the certificate a roster entry carries."""
    import base64

    from cryptography import x509

    cert_der = getattr(roster, "cert_der", "")
    raw = base64.b64decode(cert_der, validate=True)
    return x509.load_der_x509_certificate(raw)


def _is_not_found(exc: BaseException) -> bool:
    """Report whether an error means "the key does not exist"."""
    return type(exc).__name__ == "NotFoundError" or "not found" in str(exc).lower()
