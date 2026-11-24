"""Match agentTools and nativeTools rules."""

from __future__ import annotations

from agent_shield.policy_engine.matchers.command import argv_of, normalize_program
from agent_shield.policy_engine.matchers.paths import event_os
from agent_shield.policy_engine.models.types import ObjectRule


def matches_agent_tool(rule: ObjectRule, event: dict) -> bool:
    if rule.object != "agentTools":
        return False
    action = event.get("action") if isinstance(event.get("action"), dict) else {}
    if action.get("category") != "tool_call":
        return False
    raw = action.get("raw") if isinstance(action.get("raw"), dict) else {}
    name = raw.get("name")
    if not isinstance(name, str) or name.casefold() == "native":
        return False
    return name.casefold() in {item.casefold() for item in rule.names}


def matches_native_tool(rule: ObjectRule, effect: dict, event: dict) -> bool:
    if rule.object != "nativeTools":
        return False
    return native_program(effect, event) in _native_names(rule, event)


def native_program(effect: dict, event: dict) -> str:
    windows = event_os(event) == "windows"
    image = effect.get("image")
    if isinstance(image, str) and image.strip():
        return normalize_program(image, windows)
    argv = argv_of(effect)
    if effect.get("type") == "process.exec" and argv:
        return normalize_program(argv[0], windows)
    return ""


def _native_names(rule: ObjectRule, event: dict) -> set[str]:
    windows = event_os(event) == "windows"
    return {normalize_program(name, windows) for name in rule.names}
