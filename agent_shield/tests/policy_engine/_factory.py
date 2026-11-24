"""Event builders for PDP tests."""

from __future__ import annotations

import copy


def make_event(effects=None, **overrides) -> dict:
    event = {
        "spec": "agent-event/v1",
        "id": "evt_test",
        "time": "2026-10-19T00:00:00Z",
        "source": {
            "framework": "jiuwenswarm",
            "framework_version": "0.x",
            "session_id": "sess_test",
            "agent_id": "leader",
        },
        "workspace": {
            "root": "C:/Users/me/proj",
            "trusted_dirs": ["D:/shared"],
            "os": "windows",
        },
        "user_intent": None,
        "action": {
            "category": "tool_call",
            "raw": {"name": "bash", "args": {}},
            "effects": effects or [],
            "normalization": {"status": "ok", "warnings": []},
        },
        "host_capabilities": {"hitl": True, "auto_intent": True},
        "execution": {
            "plane": "host",
            "provider": "host",
            "intercept": False,
            "escaped": False,
            "escape_reason": "",
        },
    }
    if "normalization" in overrides:
        event["action"]["normalization"]["status"] = overrides.pop("normalization")
    if "execution" in overrides:
        event["execution"].update(overrides.pop("execution"))
    if "workspace" in overrides:
        event["workspace"].update(overrides.pop("workspace"))
    if "raw" in overrides:
        event["action"]["raw"].update(overrides.pop("raw"))
    if "category" in overrides:
        event["action"]["category"] = overrides.pop("category")
    event.update(overrides)
    return event


def fs(kind: str, path: str, **extra) -> dict:
    effect = {
        "type": kind,
        "path": path,
        "path_kind": extra.pop("path_kind", "file"),
        "device_class": extra.pop("device_class", None),
        "in_workspace": extra.pop("in_workspace", False),
        "in_trusted_dir": extra.pop("in_trusted_dir", False),
        "exists": extra.pop("exists", None),
    }
    if kind == "fs.delete":
        effect["force"] = extra.pop("force", False)
        effect["bulk"] = extra.pop("bulk", False)
    effect.update(extra)
    return effect


def exec_effect(argv, **meta) -> dict:
    return {
        "type": "process.exec",
        "argv": argv,
        "cwd": meta.pop("cwd", "C:/Users/me/proj"),
        "shell_meta": {
            "obfuscated": meta.pop("obfuscated", False),
            "unknown_structure": meta.pop("unknown_structure", False),
            "interpreter_sink": meta.pop("interpreter_sink", False),
            "privilege": meta.pop("privilege", False),
        },
        **meta,
    }


def snapshot(event: dict) -> dict:
    return copy.deepcopy(event)
