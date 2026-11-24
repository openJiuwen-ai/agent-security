"""Rule objects passed into the judge."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_shield.policy_engine.errors import PolicyError


@dataclass(frozen=True)
class BehaviorRule:
    id: str
    risk: str
    source: str
    note: str
    when: dict[str, Any]
    auto_intent: bool = False
    user_grantable: bool = False


@dataclass(frozen=True)
class ObjectRule:
    id: str
    source: str
    action: str
    object: str
    ops: tuple[str, ...] = ()
    pattern: tuple[str, ...] = ()
    path: str = ""
    hosts: tuple[str, ...] = ()
    cidrs: tuple[str, ...] = ()
    match: str = ""
    tokens: tuple[str, ...] = ()
    names: tuple[str, ...] = field(default_factory=tuple)
    enabled: bool = True
    user_grantable: bool = False

    def validate(self) -> None:
        if self.object == "domain" and not self.hosts and not self.cidrs:
            raise PolicyError("domain rule needs hosts or cidrs")
        if self.source != "user_grant":
            return
        if self.action != "allow":
            raise PolicyError("grant action must be allow")
        if self.object == "domain":
            host = self.hosts[0] if len(self.hosts) == 1 else ""
            if len(self.hosts) != 1 or self.cidrs or "*" in host:
                raise PolicyError("domain grant needs one exact host")
        if self.object in {"file", "domain"} and len(self.ops) != 1:
            raise PolicyError(f"{self.object} grant needs one op")
        if self.object == "command" and not self.tokens:
            raise PolicyError("command grant needs tokens")
        if self.object == "command" and any("*" in token for token in self.tokens):
            raise PolicyError("command grant cannot use *")
        if self.object == "file" and not self.path:
            raise PolicyError("file grant needs a path")
        if self.object in {"agentTools", "nativeTools"} and len(self.names) != 1:
            raise PolicyError(f"{self.object} grant needs one name")
