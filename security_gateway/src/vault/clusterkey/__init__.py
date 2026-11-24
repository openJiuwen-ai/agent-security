"""The key a fleet of nodes shares.

The nodes of a cluster all encrypt under one data encryption key.  That
key cannot simply be written down somewhere, so it reaches a node
through an exchange: the node publishes a key it generated for that one
exchange, a holder seals the fleet's key to it, and the node throws the
key away afterwards.  Nothing in the authority can open the answer, so
the copy the write-ahead log keeps is inert.

A node identifies itself with the keypair it already presents to the
authority as its client certificate, so cluster participation requires
no new secret: whoever can issue a node a client certificate can
already make it a member.

This package is deliberately independent of what the fleet is keeping:
it produces and consumes a key, and it does not know whether the key
encrypts credentials, records, or anything else.  Two callers in this
repository use it — the credential router's own store and the vault —
and they must not each carry their own copy of the minting, the roster
and the exchange: the failure modes there are quiet, and a node that
invents its own key cannot read what the rest of the fleet published.

The modules
-----------

``clusterkey``
    Minting, obtaining, and adopting the fleet's key.
``authority``
    The etcd keyspace this package owns, and the store seam it reads
    and writes through.
``handover``
    The exchange itself: publishing a request, answering one, opening
    an answer.
``wake``
    The watch that lets a wrapping loop react before its timer does.
``fault``
    The crash-injection seam that lets a test interrupt the answering
    loop between requests.

One name to watch
-----------------

``wake`` is both a module and the function that module exports.  The
package exports the *function*; the module is still reachable through
a normal ``from security_gateway.vault.clusterkey.wake import ...``.
"""

from __future__ import annotations

from .authority import (
    GENERATION_HEADER_SIZE,
    ROTATION_STATE_IN_PROGRESS,
    ClusterStore,
    HandoverRequestEntry,
    KVClusterStore,
    NodeEntry,
    RotationState,
    generation_key,
    handover_req_key,
    handover_req_prefix,
    handover_sealed_key,
    mint_key,
    node_key,
    nodes_prefix,
)
from .clusterkey import (
    DEFAULT_FETCH_TIMEOUT,
    MINTED_GENERATION,
    PREDECESSOR_FETCH_TIMEOUT,
    AdoptFunc,
    ClusterKeyError,
    Config,
    ErrNoPeerSealed,
    ErrNoPredecessor,
    HeldDEK,
    Identity,
    anchor_for,
    load_identity,
    obtain,
    obtain_pair,
    obtain_predecessor,
)
from .fault import (
    HANDOVER_ANSWERED_STAGE,
    invoke_handover_fault,
    set_handover_fault_hook_for_testing,
)
from .handover import (
    DEFAULT_REQUEST_TIMEOUT,
    HANDOVER_ANSWER_POLL_INTERVAL,
    HANDOVER_NONCE_LENGTH,
    answer_for,
    answer_requests,
    ask_for_newer_key,
    await_answer,
    predecessor,
    publish_request,
    request_generation,
)
from .wake import (
    ClusterWatchStore,
    drain_watch,
    start_rounds,
    start_ticks,
    wake,
)

__all__ = [
    # -- the fleet's key ---------------------------------------------------
    "AdoptFunc",
    "ClusterKeyError",
    "Config",
    "DEFAULT_FETCH_TIMEOUT",
    "ErrNoPeerSealed",
    "ErrNoPredecessor",
    "HeldDEK",
    "Identity",
    "MINTED_GENERATION",
    "PREDECESSOR_FETCH_TIMEOUT",
    "anchor_for",
    "load_identity",
    "obtain",
    "obtain_pair",
    "obtain_predecessor",
    # -- the authority's keyspace ------------------------------------------
    "ClusterStore",
    "GENERATION_HEADER_SIZE",
    "HandoverRequestEntry",
    "KVClusterStore",
    "NodeEntry",
    "ROTATION_STATE_IN_PROGRESS",
    "RotationState",
    "generation_key",
    "handover_req_key",
    "handover_req_prefix",
    "handover_sealed_key",
    "mint_key",
    "node_key",
    "nodes_prefix",
    # -- the exchange -------------------------------------------------------
    "DEFAULT_REQUEST_TIMEOUT",
    "HANDOVER_ANSWER_POLL_INTERVAL",
    "HANDOVER_NONCE_LENGTH",
    "answer_for",
    "answer_requests",
    "ask_for_newer_key",
    "await_answer",
    "predecessor",
    "publish_request",
    "request_generation",
    # -- the crash-injection seam ------------------------------------------
    "HANDOVER_ANSWERED_STAGE",
    "invoke_handover_fault",
    "set_handover_fault_hook_for_testing",
    # -- the watch ---------------------------------------------------------
    "ClusterWatchStore",
    "drain_watch",
    "start_rounds",
    "start_ticks",
    "wake",
]
