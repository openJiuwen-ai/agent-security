"""The rotation state stored at ``/security_gateway/<ns>/rotation``.

The value carries both the cross-node lock-holder identity (so other nodes
know who to wait out / fail over) and the in-progress rotation metadata (so
an operator looking at ``etcdctl`` can answer "what is the cluster rotating
right now?" without grepping logs).

The struct is deliberately small and flat — every field is one of the four
named in multi-node-etcd-design.md §2.12 step 1, and there are deliberately
no embedded sub-objects. A future schema addition goes through
:func:`unmarshal_rotation`'s strict-mode check so we do not silently accept
a value written by a node that shipped ahead of us.

The wire format is Go's ``encoding/json`` output for the same struct, field
for field and in the same order, because the key is read by both
implementations.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

from .errors import InvalidValueError

__all__ = [
    "ROTATION_STATE_ABORTED",
    "ROTATION_STATE_ACQUIRING",
    "ROTATION_STATE_COMPLETED",
    "ROTATION_STATE_IN_PROGRESS",
    "RotationState",
    "format_rfc3339_nano",
    "parse_rfc3339_nano",
    "marshal_rotation",
    "unmarshal_rotation",
]

#: Written at the moment the lock is taken, before the holder has begun
#: re-encrypting anything.
ROTATION_STATE_ACQUIRING = "acquiring"

#: Ciphertext is being rewritten under the new DEK.
ROTATION_STATE_IN_PROGRESS = "in_progress"

#: Every credential was re-encrypted and the holder is about to release.
ROTATION_STATE_COMPLETED = "completed"

#: The holder gave up. The lock is still released; the state exists so an
#: operator can tell a clean abort from a holder that died mid-flight.
ROTATION_STATE_ABORTED = "aborted"

#: The exact field set of the wire value. A field that is not in here was
#: written by a node that shipped ahead of us, and dropping it silently is
#: how a cluster ends up with two opinions about who holds the lock.
_FIELDS = ("state", "holder", "target_dek_version", "started_at")


@dataclass
class RotationState:
    """The JSON value stored at ``/security_gateway/<ns>/rotation``.

    ``holder`` is informational — the authoritative holder is the etcd
    lease attached to the same key (see ``RotationLock.lease_id``), and
    the lease is the source of truth. ``target_dek_version`` is the DEK
    version the cluster is rotating *to* (the new version, not the old
    one).
    """

    state: str = ""
    holder: str = ""
    target_dek_version: int = 0
    started_at: datetime = datetime(1970, 1, 1, tzinfo=timezone.utc)


def marshal_rotation(state: RotationState | None) -> bytes:
    """Return the canonical JSON representation of ``state``."""
    if state is None:
        raise InvalidValueError("etcdstore: nil rotation state")
    payload = {
        "state": state.state,
        "holder": state.holder,
        "target_dek_version": int(state.target_dek_version),
        "started_at": format_rfc3339_nano(state.started_at),
    }
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def unmarshal_rotation(raw: bytes) -> RotationState:
    """Parse the JSON produced by :func:`marshal_rotation`."""
    if not raw:
        raise InvalidValueError("etcdstore: empty rotation state")
    try:
        document = json.loads(raw.decode("utf-8"))
    except ValueError as exc:
        raise InvalidValueError(f"etcdstore: unmarshal rotation state: {exc}") from exc
    if not isinstance(document, dict):
        raise InvalidValueError("etcdstore: unmarshal rotation state: not an object")
    unknown = sorted(set(document) - set(_FIELDS))
    if unknown:
        raise InvalidValueError(
            "etcdstore: unmarshal rotation state: unknown field(s) " + ", ".join(repr(name) for name in unknown)
        )

    state = document.get("state", "")
    holder = document.get("holder", "")
    version = document.get("target_dek_version", 0)
    started_at = document.get("started_at", "")
    if not isinstance(state, str):
        raise InvalidValueError("etcdstore: unmarshal rotation state: state is not a string")
    if not isinstance(holder, str):
        raise InvalidValueError("etcdstore: unmarshal rotation state: holder is not a string")
    if not isinstance(version, int) or isinstance(version, bool):
        raise InvalidValueError("etcdstore: unmarshal rotation state: target_dek_version is not an integer")
    if not isinstance(started_at, str):
        raise InvalidValueError("etcdstore: unmarshal rotation state: started_at is not a string")
    try:
        parsed = parse_rfc3339_nano(started_at)
    except ValueError as exc:
        raise InvalidValueError(f"etcdstore: unmarshal rotation state: started_at {started_at!r}: {exc}") from exc
    return RotationState(
        state=state,
        holder=holder,
        target_dek_version=version,
        started_at=parsed,
    )


def format_rfc3339_nano(value: datetime) -> str:
    """Format a timestamp the way Go's ``time.Time`` marshals to JSON."""
    if not isinstance(value, datetime):
        raise InvalidValueError("etcdstore: rotation state carries a non-timestamp")
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    text = value.strftime("%Y-%m-%dT%H:%M:%S")
    if value.microsecond:
        text += "." + f"{value.microsecond:06d}".rstrip("0")
    return text + "Z"


def parse_rfc3339_nano(text: str) -> datetime:
    """Parse an RFC3339 timestamp with up to nanosecond precision."""
    raw = text.strip()
    if raw.endswith(("Z", "z")):
        raw = raw[:-1] + "+00:00"
    head, dot, tail = raw.partition(".")
    if dot:
        digits = ""
        index = 0
        while index < len(tail) and tail[index].isdigit():
            digits += tail[index]
            index += 1
        raw = head + "." + digits[:6].ljust(6, "0") + tail[index:]
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise ValueError(f"not an RFC3339 timestamp: {text!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed
