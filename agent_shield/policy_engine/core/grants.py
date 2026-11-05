"""Grant subject check. The host owns the stored bytes, expiry, and revocation."""

from __future__ import annotations


def accept_grant(grant: dict, *, subject_id: str) -> bool:
    return isinstance(grant, dict) and grant.get("subject_id") == subject_id


def grant_provenance(grant: dict) -> dict | None:
    if not isinstance(grant, dict):
        return None
    provenance = grant.get("provenance")
    if not isinstance(provenance, dict):
        return None
    if any(not isinstance(provenance.get(key), str) for key in ("decision_id", "approved_at", "via")):
        return None
    return provenance
