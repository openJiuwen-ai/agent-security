"""Immutable value objects for the Hypershell permission model.

The model follows ``docs/ARCHITECTURE.md``:

* permissions are attached to administrator-registered **resource ids**, never
  to host paths supplied by users;
* access levels form a finite lattice ``none < read < read_write``;
* the effective set is ``E = B ∩ G ∩ R ∩ T`` where ``R``/``T`` are optional
  and ``None`` means "inherit", while an explicit empty mapping means "empty
  set" (the two must never be confused -- property P-05).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Mapping

from .errors import InvalidRequest


class AccessMode(IntEnum):
    """Finite access lattice. Higher integer == strictly more access."""

    NONE = 0
    READ = 1
    READ_WRITE = 2

    @classmethod
    def parse(cls, value: object, *, field_name: str = "mode") -> "AccessMode":
        if isinstance(value, cls):
            return value
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise InvalidRequest(
                f"{field_name} must be a string access mode, got {type(value).__name__}",
                field=field_name,
            )
        if isinstance(value, int):
            try:
                return cls(value)
            except ValueError as exc:
                raise InvalidRequest(f"{field_name} has no access level {value}", field=field_name) from exc
        try:
            return _MODE_BY_NAME[value.strip().lower()]
        except KeyError as exc:
            raise InvalidRequest(f"unknown access mode {value!r}", field=field_name) from exc


_MODE_BY_NAME: dict[str, AccessMode] = {
    "none": AccessMode.NONE,
    "read": AccessMode.READ,
    "read_write": AccessMode.READ_WRITE,
    "readwrite": AccessMode.READ_WRITE,
    "rw": AccessMode.READ_WRITE,
    "ro": AccessMode.READ,
}


DIRECTORY = "directory"
FILE = "file"
SERVICE = "service"
MODEL = "model"
_KINDS = {DIRECTORY, FILE, SERVICE, MODEL}


@dataclass(frozen=True, slots=True)
class Resource:
    """One entry of the administrator-owned resource catalog."""

    id: str
    kind: str
    backend_ref: str
    max_mode: AccessMode = AccessMode.READ
    sandbox_target: str | None = None
    organization: str | None = None

    def __post_init__(self) -> None:
        if not self.id:
            raise InvalidRequest("resource id must not be empty")
        if self.kind not in _KINDS:
            raise InvalidRequest(f"unknown resource kind {self.kind!r}", resource=self.id)
        if not self.backend_ref:
            raise InvalidRequest(f"resource {self.id} has no backend_ref")
        if self.kind in (DIRECTORY, FILE):
            target = self.sandbox_target
            if not target or not target.startswith("/") or ".." in target.split("/"):
                raise InvalidRequest(f"resource {self.id} needs an absolute sandbox_target", resource=self.id)
        elif self.kind in (SERVICE, MODEL):
            if self.sandbox_target is not None:
                raise InvalidRequest(
                    f"service resource {self.id} must not declare a sandbox_target",
                    resource=self.id,
                )


@dataclass(frozen=True, slots=True)
class Layer:
    """One of the four permission layers.

    ``resources is None`` means the layer does not restrict (inherit);
    ``resources == {}`` means the layer allows nothing (explicit empty set).
    """

    resources: Mapping[str, AccessMode] | None = None
    quotas: Mapping[str, float] | None = None

    @property
    def is_unrestricted(self) -> bool:
        return self.resources is None


@dataclass(frozen=True, slots=True)
class LaunchRequest:
    """What the user asks for at launch time (untrusted input)."""

    resources: Mapping[str, AccessMode] = field(default_factory=dict)
    services: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "LaunchRequest":
        """Strict parser: unknown fields (host_path, mount, uid, ...) are rejected."""

        allowed = {"resources", "services"}
        unknown = set(data) - allowed
        if unknown:
            raise InvalidRequest(
                "unknown request fields: " + ", ".join(sorted(unknown)),
                unknown=sorted(unknown),
            )

        raw_resources = data.get("resources", [])
        if not isinstance(raw_resources, list):
            raise InvalidRequest("resources must be a list")

        resources: dict[str, AccessMode] = {}
        for idx, item in enumerate(raw_resources):
            if not isinstance(item, Mapping):
                raise InvalidRequest(f"resources[{idx}] must be an object")
            extra = set(item) - {"id", "mode"}
            if extra:
                raise InvalidRequest(
                    f"resources[{idx}] has unknown fields: {', '.join(sorted(extra))}",
                    unknown=sorted(extra),
                )
            rid = item.get("id")
            if not isinstance(rid, str) or not rid:
                raise InvalidRequest(f"resources[{idx}].id must be a non-empty string")
            if rid in resources:
                raise InvalidRequest(f"duplicate resource id {rid!r}")
            resources[rid] = AccessMode.parse(item.get("mode", "read"), field_name=f"resources[{idx}].mode")

        raw_services = data.get("services", [])
        if not isinstance(raw_services, list) or not all(isinstance(s, str) for s in raw_services):
            raise InvalidRequest("services must be a list of strings")

        return cls(resources=resources, services=tuple(raw_services))


@dataclass(frozen=True, slots=True)
class Mount:
    """A resolved bind mount inside the user's sandbox."""

    resource_id: str
    source: str
    target: str
    read_only: bool


@dataclass(frozen=True, slots=True)
class NetworkRule:
    """A resolved egress rule.

    ``kind`` is ``http_connect`` (through the controlled proxy) or
    ``direct_tcp`` (exact host:port, only for registered services).
    """

    resource_id: str
    kind: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class LaunchPlan:
    """Immutable, digest-addressed execution plan."""

    app_id: str
    compiler_version: str
    resources: Mapping[str, AccessMode]
    mounts: tuple[Mount, ...]
    network: tuple[NetworkRule, ...]
    quotas: Mapping[str, float]
    digest: str = ""

    def canonical(self) -> dict[str, Any]:
        """Deterministic projection used for SHA-256 (property P-08)."""

        return {
            "app_id": self.app_id,
            "compiler_version": self.compiler_version,
            "resources": {k: int(v) for k, v in sorted(self.resources.items())},
            "mounts": [
                {
                    "resource_id": m.resource_id,
                    "source": m.source,
                    "target": m.target,
                    "read_only": m.read_only,
                }
                for m in self.mounts
            ],
            "network": [
                {
                    "resource_id": n.resource_id,
                    "kind": n.kind,
                    "host": n.host,
                    "port": n.port,
                }
                for n in self.network
            ],
            "quotas": {k: self.quotas[k] for k in sorted(self.quotas)},
        }
