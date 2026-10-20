"""Network tool baselines, used only inside NetGuardComponent."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from ..models import PermissionLevel, PermissionResult


def _level(value: object) -> PermissionLevel | None:
    # Keep the tools/defaults value semantics established by W1a.
    if not isinstance(value, str):
        return None
    try:
        return PermissionLevel(value.strip().lower())
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class NetworkToolPolicy:
    """Prepared whole-tool policy, without routing or a component lifecycle."""

    tools: Mapping[str, tuple[PermissionLevel, str]]
    default: PermissionLevel | None

    def evaluate(self, tool_name: str) -> PermissionResult | None:
        baseline = self.tools.get(tool_name)
        if baseline is not None:
            level, label = baseline
        elif self.default is not None:
            level, label = self.default, "tiered_policy:defaults.*"
        else:
            return None
        return PermissionResult(level, label, "Network tool policy: " + level.value)


def build_tool_policy(config: Mapping[str, object]) -> NetworkToolPolicy:
    tools = config.get("tools")
    baselines = {}
    for name, raw in tools.items() if isinstance(tools, Mapping) else ():
        wrapped = isinstance(raw, Mapping)
        level = _level(raw.get("*") if wrapped else raw)
        if level is not None:
            baselines[name] = (level, f"tools.{name}" + (".*" if wrapped else ""))
    defaults = config.get("defaults")
    default = _level(defaults.get("*")) if isinstance(defaults, Mapping) else None
    return NetworkToolPolicy(MappingProxyType(baselines), default)
