"""Resolve administrator role grants before the existing policy compiler."""

from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Mapping

from .errors import InvalidRequest
from .model import AccessMode, Resource


@dataclass(frozen=True)
class RoleProfile:
    description: str
    grants: Mapping[str, AccessMode]


def resolve_grants(catalog, roles, direct_grants, limits):
    """Union positive sources, then apply sparse ceilings. No I/O or paths from users.

    Inputs have passed the configuration schema and resource boundary checks.
    Return the same effective mapping used by compilation and workspace checks,
    alongside an explanation that includes explicitly denied resources.
    """
    contributions = {}
    for source, grants in roles + [("user.grants", direct_grants)]:
        for rid, mode in grants.items():
            contributions.setdefault(rid, []).append({"source": source, "mode": mode.name.lower()})
    merged = {}
    for _, grants in roles + [("user.grants", direct_grants)]:
        for rid, mode in grants.items():
            merged[rid] = max(merged.get(rid, AccessMode.NONE), mode)
    effective = {rid: min(mode, limits.get(rid, mode)) for rid, mode in merged.items()}
    effective = {rid: mode for rid, mode in effective.items() if mode > AccessMode.NONE}
    _check_limit_aliases(catalog, effective, limits)
    explanation = {}
    for rid in sorted(set(merged) | set(limits)):
        explanation[rid] = {
            "sources": sorted(contributions.get(rid, []), key=lambda item: item["source"]),
            "granted": merged.get(rid, AccessMode.NONE).name.lower(),
            "limit": limits[rid].name.lower() if rid in limits else None,
            "effective": effective.get(rid, AccessMode.NONE).name.lower(),
        }
    return effective, explanation


def _check_limit_aliases(catalog: Mapping[str, Resource], effective, limits):
    # A parent's mount exposes a child even when the child's resource id is
    # denied. Equivalent paths under different ids have the same problem.
    for restricted, ceiling in limits.items():
        resource = catalog[restricted]
        if resource.kind not in ("directory", "file"):
            continue
        path = PurePosixPath(resource.backend_ref)
        for rid, mode in effective.items():
            other = catalog[rid]
            if rid == restricted or mode <= ceiling or other.kind not in ("directory", "file"):
                continue
            other_path = PurePosixPath(other.backend_ref)
            # Reject both parent exposures and stronger child exposures.
            if path == other_path or path in other_path.parents or other_path in path.parents:
                raise InvalidRequest(
                    "resource limit can be bypassed through an overlapping resource",
                    resource=restricted,
                    overlapping_resource=rid,
                )
