"""Keeping a local credential store in step with the etcd keyspace.

The Go original is the package ``internal/credmgr/etcdsync``.

It is deliberately the only place in the project that knows how to turn
a watch stream into local state, so each of those failure modes has
exactly one place to be correct.

The three ways events go missing, and what this package does about them:

* **Compaction.** etcd drops history it has been told to compact and
  reports the error on the stream.  Detecting it and re-listing is the
  fix; swallowing it leaves the watcher pinned to a revision etcd no
  longer retains.
* **Stream termination.** A server restart, a leader change or a
  network blip ends the stream.  Reconnecting without re-listing loses
  the changes made during the outage forever; here every abnormal exit
  from the watch loop triggers a full re-listing.
* **A silently dead stream.** If the stream stays open but nothing is
  delivered — a half-open connection, a wedged proxy — no amount of
  reading will recover it.  Progress notifications are the only signal
  that distinguishes this from a merely quiet cluster; see the liveness
  guard in :mod:`security_gateway.credmgr.etcdsync.syncer`.

Each of those ends in a full re-listing, and a full re-listing is
idempotent and self-healing, so the failure mode is bounded by "how
long until the next resync", never by silent divergence.
"""

from __future__ import annotations

from .etcdsync import (
    DEFAULT_LIVENESS_INTERVAL,
    DEFAULT_LIVENESS_TIMEOUT,
    DEFAULT_RESYNC_BACKOFF_MAX,
    DEFAULT_RESYNC_BACKOFF_MIN,
    Applier,
    CredSource,
    Listed,
    Listing,
    Phase,
    RevisionStore,
    Source,
    Stats,
    StoreApplier,
    StoreRevisionStore,
    SyncError,
)
from .syncer import Config, Syncer, response_revision

__all__ = [
    "DEFAULT_LIVENESS_INTERVAL",
    "DEFAULT_LIVENESS_TIMEOUT",
    "DEFAULT_RESYNC_BACKOFF_MAX",
    "DEFAULT_RESYNC_BACKOFF_MIN",
    "Applier",
    "Config",
    "CredSource",
    "Listing",
    "Listed",
    "Phase",
    "RevisionStore",
    "Source",
    "Stats",
    "StoreApplier",
    "StoreRevisionStore",
    "SyncError",
    "Syncer",
    "response_revision",
]
