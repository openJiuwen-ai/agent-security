"""Convert an observed operation into the task policy event."""

from __future__ import annotations

import os
import re

from agent_shield.policy_engine.builtin.policy import Policy, load_builtin_policy
from agent_shield.policy_engine.events.command_effects import normalize_command
from agent_shield.policy_engine.events.envelope import build_event
from agent_shield.policy_engine.matchers.command import command_segments, normalize_program
from agent_shield.policy_engine.matchers.paths import normalize_path

_PSEUDO = ("nul", "con", "conin$", "conout$")
_READ_KINDS = {"open", "read"}
_WRITE_KINDS = {"create", "write", "mkdir"}
_DELETE_KINDS = {"delete", "rmdir"}


def operation_to_event(operation, context, *, cause=None, request_id=None, policy=None, runtime=False):
    active = policy or load_builtin_policy()
    resources = operation.get("resources") if isinstance(operation.get("resources"), list) else []
    workspace = context.get("workspace") or {"root": "", "trusted_dirs": [], "os": "posix"}
    if runtime and "accesses" in operation:
        effects = []
        device = resources[0] if operation.get("kind") == "device_open" and resources else None
        for path, access in operation["accesses"]:
            if not is_pseudo_device(path):
                # Loading an executable also reads its file. Program-start policy
                # receives the selected image and argv as a separate operation.
                action = "read" if access == "exec" else access
                effect = _file_effect("fs." + action, path, workspace, device)
                if action == "delete":
                    effect.update(force=False, bulk=bool(operation.get("bulk")))
                effects.append(effect)
        normalization = {"status": "ok", "warnings": []}
    else:
        effects, normalization = _effects(operation, resources, workspace, active, context)
    execution = context.get("execution") or {
        "plane": "host",
        "provider": "agent-security-dll",
        "intercept": True,
        "escaped": False,
        "escape_reason": "",
    }
    event = build_event(
        source=context.get("source") or {"framework": "other"},
        workspace=workspace,
        effects=effects,
        raw={"name": "native", "args": {"kind": operation.get("kind"), "request_id": request_id}},
        normalization=normalization,
        user_intent=context.get("user_intent"),
        host_capabilities=context.get("host_capabilities"),
        execution=execution,
        event_id=context.get("event_id"),
    )
    if cause is not None:
        event["cause"] = cause
    return event


def _effects(
    operation: dict,
    resources: list,
    workspace: dict,
    policy: Policy,
    context: dict,
) -> tuple[list[dict], dict]:
    kind = operation.get("kind")
    access = operation.get("access")
    if kind == "create_process":
        return _process_effects(resources, workspace, policy, context)
    if kind == "connect":
        effect = _connect_effect(resources)
        if operation.get("url"):
            effect["url"] = operation["url"]
        return [effect], {"status": "ok", "warnings": []}
    paths = [_resource_path(item) for item in resources if isinstance(item, dict)]
    if paths and all(is_pseudo_device(path) for path in paths if path):
        return [], {"status": "ok", "warnings": ["pseudo_device_exempt"]}
    if kind in {"copy", "move", "rename", "replace", "symlink", "hardlink"}:
        return _multi_file_effects(kind, resources, workspace), {"status": "ok", "warnings": []}
    if kind in {"device_open", "pipe_open"}:
        return [_device_effect(kind, access, resources, workspace)], {"status": "ok", "warnings": []}
    fs_type = _fs_type(kind, access)
    if fs_type is None:
        return [], {"status": "failed", "warnings": ["unknown_operation"]}
    effects = []
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        path = _resource_path(resource)
        if not path or is_pseudo_device(path):
            continue
        effect = _file_effect(fs_type, path, workspace, resource)
        if fs_type == "fs.delete":
            effect["force"] = False
            effect["bulk"] = False
        effects.append(effect)
    return effects, {"status": "ok", "warnings": []}


def _process_effects(resources: list, workspace: dict, policy: Policy, context: dict) -> tuple[list[dict], dict]:
    image = ""
    command_line = ""
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if resource.get("image"):
            image = str(resource["image"])
        if resource.get("command_line"):
            command_line = str(resource["command_line"])
    command = command_line or image
    cwd = context.get("cwd") or workspace.get("root") or ""
    if not command:
        return [], {"status": "failed", "warnings": ["missing_command"]}
    effects, normalization = normalize_command(
        command,
        cwd=cwd,
        workspace=workspace,
        policy=policy,
        stamp_tokens=bool(command_line.strip()),
    )
    _attach_process_identity(effects, normalization, command_line, image, workspace)
    native_argv = next(
        (
            resource.get("argv")
            for resource in resources
            if isinstance(resource, dict) and resource.get("argv")
        ),
        None,
    )
    if native_argv:
        windows = workspace.get("os") == "windows"
        for index, effect in enumerate(effects):
            argv = effect.get("argv") or []
            same_program = (
                index == 0
                or normalize_program(argv[0], windows) == normalize_program(image, windows)
            )
            if effect.get("type") == "process.exec" and argv and same_program:
                # Windows has already parsed these arguments. Whitespace-only
                # rule tokens must not retain quotes around the selected EXE.
                effect["command_tokens"] = list(native_argv)
                effect["command_line"] = command_line
    return effects, normalization


def _attach_process_identity(
    effects: list[dict],
    normalization: dict,
    command_line: str,
    image: str,
    workspace: dict,
) -> None:
    windows = (workspace.get("os") or "posix") == "windows"
    segments = command_segments(command_line) if command_line else []
    if not image:
        return
    normalized = normalize_path(image)
    for effect in effects:
        if effect.get("type") == "process.exec":
            effect["image"] = normalized
    if segments and normalize_program(segments[0][0], windows) != normalize_program(normalized, windows):
        warnings = normalization.setdefault("warnings", [])
        if "image_command_mismatch" not in warnings:
            warnings.append("image_command_mismatch")


def _connect_effect(resources: list) -> dict:
    host = None
    ip = None
    port = None
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        if resource.get("host"):
            host = resource.get("host")
        if resource.get("ip"):
            ip = resource.get("ip")
        if resource.get("port") is not None:
            port = resource.get("port")
    return {"type": "net.connect", "host": host, "ip": ip, "port": port}


def _multi_file_effects(kind: str, resources: list, workspace: dict) -> list[dict]:
    by_role: dict[str, list[str]] = {}
    for resource in resources:
        if not isinstance(resource, dict):
            continue
        path = _resource_path(resource)
        if not path:
            continue
        by_role.setdefault(str(resource.get("role") or "target"), []).append(path)
    effects: list[dict] = []
    if kind == "copy":
        effects.extend(_file_effect("fs.read", path, workspace) for path in by_role.get("source", []))
        effects.extend(_file_effect("fs.write", path, workspace) for path in by_role.get("target", []))
    elif kind in {"move", "rename"}:
        for path in by_role.get("source", []):
            effect = _file_effect("fs.delete", path, workspace)
            effect["force"] = False
            effect["bulk"] = False
            effects.append(effect)
        effects.extend(_file_effect("fs.write", path, workspace) for path in by_role.get("target", []))
    elif kind == "replace":
        for path in by_role.get("source", []):
            effect = _file_effect("fs.delete", path, workspace)
            effect["force"] = False
            effect["bulk"] = False
            effects.append(effect)
        for path in by_role.get("target", []):
            deleted = _file_effect("fs.delete", path, workspace)
            deleted["force"] = False
            deleted["bulk"] = False
            effects.append(deleted)
            effects.append(_file_effect("fs.write", path, workspace))
        effects.extend(_file_effect("fs.write", path, workspace) for path in by_role.get("backup", []))
    else:
        effects.extend(_file_effect("fs.read", path, workspace) for path in by_role.get("source", []))
        effects.extend(_file_effect("fs.write", path, workspace) for path in by_role.get("target", []))
    return effects


def _device_effect(kind: str, access: str | None, resources: list, workspace: dict) -> dict:
    resource = next((item for item in resources if isinstance(item, dict)), {})
    path = _resource_path(resource) or ""
    fs_type = "fs.write" if access == "write" else "fs.read"
    effect = _file_effect(fs_type, path, workspace, resource)
    effect["path_kind"] = "named_pipe" if kind == "pipe_open" else "device"
    effect["device_class"] = resource.get("device_class") or device_class_for(path)
    return effect


def _fs_type(kind: str | None, access: str | None) -> str | None:
    if access == "delete" or kind in _DELETE_KINDS:
        return "fs.delete"
    if access == "write" or kind in _WRITE_KINDS:
        return "fs.write"
    if access == "read" or kind in _READ_KINDS:
        return "fs.read"
    return None


def _file_effect(kind: str, path: str, workspace: dict, resource: dict | None = None) -> dict:
    from agent_shield.policy_engine.matchers.paths import is_within

    os_name = workspace.get("os") or "posix"
    root = workspace.get("root") or ""
    trusted = [item for item in workspace.get("trusted_dirs") or [] if isinstance(item, str)]
    normalized = normalize_path(path)
    effect = {
        "type": kind,
        "path": normalized,
        "path_kind": (resource or {}).get("path_kind") or "file",
        "device_class": (resource or {}).get("device_class"),
        "in_workspace": bool(root) and is_within(normalized, root, os_name=os_name),
        "in_trusted_dir": any(is_within(normalized, item, os_name=os_name) for item in trusted),
        "exists": (
            (resource or {}).get("exists", None)
            if isinstance(resource, dict) and "exists" in (resource or {})
            else None
        ),
    }
    return effect


def _resource_path(resource: dict) -> str:
    for key in ("path", "image"):
        value = resource.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


def is_pseudo_device(path: str) -> bool:
    folded = path.strip().replace("/", "\\").casefold()
    for name in _PSEUDO:
        if folded == name or folded in {f"\\\\.\\{name}", f"\\\\?\\{name}"}:
            return True
    return False


def device_class_for(path: str) -> str:
    folded = path.replace("/", "\\").casefold()
    if "physicaldrive" in folded:
        return "raw_disk"
    if folded.startswith(r"\\.\volume{"):
        return "volume"
    if "harddiskvolume" in folded or re.fullmatch(r"\\\\\.\\[a-z]:", folded):
        return "volume"
    if folded.startswith("\\\\.\\harddisk"):
        return "raw_disk"
    return "other"


def device_open_path(raw: str) -> str | None:
    """Identify device objects, keeping files below a volume on the file path."""
    name = raw.replace("/", "\\")
    for prefix in ("\\??\\", "\\\\?\\", "\\\\.\\"):
        if name.casefold().startswith(prefix):
            name = name[len(prefix):]
            if name.casefold().startswith("global\\"):
                name = name[7:]
            if name.casefold().startswith("globalroot\\"):
                name = name[10:]
            break
    else:
        if not name.casefold().startswith("\\device\\"):
            return None
    if name.casefold().startswith("\\device\\"):
        name = name[8:]
    if not name or name.casefold() in {"unc", "pipe", "mailslot", "globalroot"}:
        return None
    if "\\" in name and not re.fullmatch(r"harddisk\d+\\(?:dr\d+|partition\d+)", name, re.I):
        return None
    return os.path.join("\\\\.\\", name)
