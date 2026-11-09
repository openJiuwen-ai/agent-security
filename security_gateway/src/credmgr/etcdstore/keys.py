"""The etcd keyspace this package owns.

Two properties of the layout are load-bearing:

* The ``/security_gateway/`` prefix must not collide with the agent-os tree's
  ``/sn/`` keyspace, and it deliberately avoids reserving the ``/nodes/``
  and ``/boots/`` subtrees that agent-os depends on. Every full key this
  package constructs begins with exactly this string.

* The trailing slash on ``creds_prefix`` and ``records_prefix`` stops a
  future sibling prefix such as ``/security_gateway/<ns>/creds-extra/`` from
  being matched by the same prefix range. No such sibling exists today,
  so a missing slash would be silently safe — and a foot-gun the day
  someone adds one.

The prefix upper bound is the other half of a prefix range, and it is
reused from the vault: :func:`prefix_upper_bound` increments the last byte
that is not ``0xff`` and truncates, which is what ``clientv3``'s
``WithPrefix`` does internally. It is emphatically *not* ``prefix +
"\\x00"``, which sorts before every key sharing the prefix and therefore
yields an empty range.
"""

from __future__ import annotations

from security_gateway.vault import prefix_upper_bound

from .errors import InvalidValueError

__all__ = [
    "KEYSPACE_PREFIX",
    "cred_key",
    "creds_prefix",
    "prefix_upper_bound",
    "proxy_key_from_cred_key",
    "record_id_from_key",
    "record_key",
    "records_prefix",
    "rotation_key",
]

#: The top-level etcd key prefix this package owns.
#:
#: The trailing slash is part of the prefix: a caller issuing a Range over
#: a credential subtree has to include it so the scan does not bleed
#: across sibling namespaces.
KEYSPACE_PREFIX = "/security_gateway/"


def _check_segment(value: str, what: str) -> str:
    """Reject a path segment that would break the keyspace's isolation.

    The layout only isolates namespaces as long as a namespace, a proxy
    key and a record id are single segments: a segment holding ``/``
    would nest one subtree inside another, and a namespace built that
    way would overlap the prefix range of a sibling namespace. An empty
    segment is rejected for the same reason — it would collapse two
    different keys onto one.

    Raises :class:`~.errors.InvalidValueError` for such a segment.
    """
    if not value:
        raise InvalidValueError(f"{what} must not be empty")
    if "/" in value:
        raise InvalidValueError(f"{what} must not hold a slash: {value!r}")
    if "\x00" in value:
        raise InvalidValueError(f"{what} must not hold a NUL: {value!r}")
    return value


def cred_key(ns: str, proxy_key: str) -> str:
    """The etcd key under which the credential record for a proxy key lives."""
    return f"{KEYSPACE_PREFIX}{_check_segment(ns, 'namespace')}/creds/{_check_segment(proxy_key, 'proxy key')}"


def creds_prefix(ns: str) -> str:
    """The prefix that enumerates every credential under a namespace."""
    return f"{KEYSPACE_PREFIX}{_check_segment(ns, 'namespace')}/creds/"


def rotation_key(ns: str) -> str:
    """The etcd key that records the cross-node DEK rotation state.

    Both the lock-holder identity and the in-progress rotation metadata
    live here. There is exactly one such key per namespace, and the lock
    acquired by ``acquire_rotation_lock`` is held on this key.
    """
    return f"{KEYSPACE_PREFIX}{_check_segment(ns, 'namespace')}/rotation"


def record_key(ns: str, record_id: str) -> str:
    """The etcd key under which a generic record lives."""
    return f"{KEYSPACE_PREFIX}{_check_segment(ns, 'namespace')}/records/{_check_segment(record_id, 'record id')}"


def records_prefix(ns: str) -> str:
    """The prefix that enumerates every record under a namespace."""
    return f"{KEYSPACE_PREFIX}{_check_segment(ns, 'namespace')}/records/"


def proxy_key_from_cred_key(ns: str, key: str) -> str:
    """The inverse of :func:`cred_key`.

    Raises :class:`~.errors.InvalidValueError` when the key is not under
    this namespace's credential prefix: a wire-contract mistake, not a
    runtime condition.
    """
    prefix = creds_prefix(ns)
    rest = key[len(prefix) :] if key.startswith(prefix) else ""
    if not rest:
        raise InvalidValueError(f"key {key!r} is not under the credential prefix {prefix!r}")
    return _check_segment(rest, "proxy key")


def record_id_from_key(ns: str, key: str) -> str:
    """The inverse of :func:`record_key`."""
    prefix = records_prefix(ns)
    rest = key[len(prefix) :] if key.startswith(prefix) else ""
    if not rest:
        raise InvalidValueError(f"key {key!r} is not under the record prefix {prefix!r}")
    return _check_segment(rest, "record id")
