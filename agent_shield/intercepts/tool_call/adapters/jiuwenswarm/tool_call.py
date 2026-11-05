"""Map a jiuwenswarm tool call onto an Agent Event."""

from __future__ import annotations

from agent_shield.policy_engine.events.command_effects import normalize_command
from agent_shield.policy_engine.events.envelope import build_event
from agent_shield.policy_engine.matchers.paths import is_within, normalize_path
from agent_shield.policy_engine.builtin.policy import Policy, load_builtin_policy

_READ = {"read", "read_file", "readfile"}
_WRITE = {"write", "write_file", "writefile", "edit", "strreplace", "search_replace"}
_DELETE = {"delete", "delete_file", "remove", "remove_file"}
_SHELL = {"bash", "shell", "powershell", "cmd", "exec", "run"}
_FETCH = {"fetch", "http", "web_fetch", "curl"}


def tool_call_to_event(
    tool_name: str,
    args: dict | None,
    *,
    context: dict,
    policy: Policy | None = None,
) -> dict:
    active = policy or load_builtin_policy()
    payload = args or {}
    workspace = context.get("workspace") or {"root": "", "trusted_dirs": [], "os": "posix"}
    name = (tool_name or "").replace("-", "_").casefold()
    effects, normalization = _effects_for(name, payload, workspace, active, context)
    execution = context.get("execution") or {
        "plane": "host",
        "provider": "host",
        "intercept": bool(context.get("intercept", False)),
        "escaped": bool(context.get("escaped", False)),
        "escape_reason": context.get("escape_reason") or "",
    }
    return build_event(
        source=context.get("source") or {"framework": "jiuwenswarm"},
        workspace=workspace,
        effects=effects,
        raw={"name": tool_name, "args": payload},
        normalization=normalization,
        user_intent=context.get("user_intent"),
        host_capabilities=context.get("host_capabilities"),
        execution=execution,
        event_id=context.get("event_id"),
    )


def _effects_for(name: str, args: dict, workspace: dict, policy: Policy, context: dict) -> tuple[list[dict], dict]:
    command = _string_arg(args, "command", "cmd", "script")
    if name in _SHELL or (command and name not in _READ | _WRITE | _DELETE | _FETCH):
        cwd = context.get("cwd") or workspace.get("root") or ""
        return normalize_command(command or "", cwd=cwd, workspace=workspace, policy=policy)
    path = _string_arg(args, "path", "file_path", "filePath", "target_file")
    if name in _READ and path:
        return [_fs("fs.read", path, workspace, args)], {"status": "ok", "warnings": []}
    if name in _WRITE and path:
        return [_fs("fs.write", path, workspace, args)], {"status": "ok", "warnings": []}
    if name in _DELETE and path:
        effect = _fs("fs.delete", path, workspace, args)
        effect["force"] = args.get("force") is True
        effect["bulk"] = False
        return [effect], {"status": "ok", "warnings": []}
    if name in _FETCH:
        return [_fetch(args)], {"status": "ok", "warnings": []}
    return [], {"status": "ok", "warnings": []}


def _fs(kind: str, path: str, workspace: dict, args: dict) -> dict:
    os_name = workspace.get("os") or "posix"
    root = workspace.get("root") or ""
    trusted = [item for item in workspace.get("trusted_dirs") or [] if isinstance(item, str)]
    cwd = args.get("cwd") or root
    normalized = _resolve(path, str(cwd), os_name)
    effect = {
        "type": kind,
        "path": normalized,
        "path_kind": args.get("path_kind") or "file",
        "device_class": args.get("device_class"),
        "in_workspace": bool(root) and is_within(normalized, root, os_name=os_name),
        "in_trusted_dir": any(is_within(normalized, item, os_name=os_name) for item in trusted),
        "exists": args.get("exists", None) if "exists" in args else None,
    }
    return effect


def _fetch(args: dict) -> dict:
    method = str(args.get("method") or "GET").upper()
    url = _string_arg(args, "url") or ""
    host = args.get("host") or _host(url)
    files = args.get("local_files") if isinstance(args.get("local_files"), list) else []
    secret = args.get("secret_like") is True
    body = args.get("has_body") is True or method not in {"GET", "HEAD"}
    if method in {"GET", "HEAD"} and not body:
        if not files and not secret:
            return {"type": "net.fetch", "method": method, "url": url, "host": host}
    return {
        "type": "net.egress",
        "method": method,
        "url": url,
        "host": host,
        "has_body": body,
        "secret_like": secret,
        "local_file_attached": bool(files),
        "local_files": files,
    }


def _resolve(path: str, cwd: str, os_name: str) -> str:
    normalized = normalize_path(path)
    windows_abs = os_name == "windows" and (normalized.startswith("//") or _has_drive(normalized))
    absolute = normalized.startswith("/") or windows_abs
    if absolute or not cwd:
        return normalized
    return normalize_path(normalize_path(cwd).rstrip("/") + "/" + normalized)


def _has_drive(path: str) -> bool:
    return len(path) >= 2 and path[0].isalpha() and path[1] == ":"


def _host(url: str) -> str | None:
    if "://" not in url:
        return None
    return url.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0] or None


def _string_arg(args: dict, *keys: str) -> str | None:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str):
            return value
    return None
