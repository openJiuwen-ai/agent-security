"""Decide whether a medium-risk event is already covered by the user's words.

This check does not call a model. It only looks at resources that were written
down: paths, hosts, and explicit flags such as --force.
"""

from __future__ import annotations

import re

from agent_shield.policy_engine.matchers.paths import event_os, glob_any, in_system_critical, path_scope
from agent_shield.policy_engine.builtin.policy import Policy
from agent_shield.policy_engine.matchers.command import argv_of, command_name, privilege_requested

_VERBS = {
    "read": ("读", "查看", "看看", "打开", "阅读", "read", "cat"),
    "write": ("改", "修改", "写", "写入", "编辑", "更新", "替换", "保存", "write", "edit", "update"),
    "delete": ("删", "删除", "移除", "去掉", "delete", "remove", "rm"),
    "exec": ("跑", "执行", "运行", "启动", "run", "exec"),
    "fetch": ("下载", "获取", "拉取", "fetch", "download"),
    "egress": ("上传", "发送", "提交", "外发", "upload", "post"),
    "push": ("推送", "push"),
    "schedule": ("定时", "计划任务", "cron", "schedule", "heartbeat"),
}


def allows_auto(event: dict, policy: Policy) -> bool:
    if not _auto_intent_enabled(event):
        return False
    normalization = (event.get("action") or {}).get("normalization") or {}
    if normalization.get("status", "ok") != "ok":
        return False
    text = _intent_text(event)
    if not text:
        return False
    effects = (event.get("action") or {}).get("effects") or []
    if not effects:
        return False
    return all(_effect_entailed(effect, text, event, policy) for effect in effects)


def _auto_intent_enabled(event: dict) -> bool:
    caps = event.get("host_capabilities")
    if not isinstance(caps, dict) or "auto_intent" not in caps:
        return True
    return caps.get("auto_intent") is True


def _intent_text(event: dict) -> str:
    intent = event.get("user_intent")
    if not isinstance(intent, dict):
        return ""
    text = intent.get("text")
    return text.strip() if isinstance(text, str) else ""


def _effect_entailed(effect: dict, text: str, event: dict, policy: Policy) -> bool:
    if not isinstance(effect, dict):
        return False
    if privilege_requested(effect, policy.privilege_names()):
        return False
    kind = effect.get("type")
    if kind == "process.exec":
        return _exec_entailed(effect, text)
    if kind in {"fs.read", "fs.write", "fs.delete"}:
        return _fs_entailed(effect, text, event, policy)
    if kind in {"net.fetch", "net.egress", "net.connect"}:
        return _net_entailed(effect, text)
    if kind == "schedule.create":
        return _has_verb(text, "schedule")
    return False


def _exec_entailed(effect: dict, text: str) -> bool:
    meta = effect.get("shell_meta") if isinstance(effect.get("shell_meta"), dict) else {}
    argv = argv_of(effect)
    raw = effect.get("raw_command") if isinstance(effect.get("raw_command"), str) else ""
    if meta.get("obfuscated") is True:
        return bool(raw) and raw in text
    if _is_force_push(argv):
        return _has_force(text) and _has_verb(text, "push")
    if meta.get("interpreter_sink") is True:
        return _has_remote(text, effect)
    if argv == ["__compound__"]:
        return _has_remote(text, effect) if meta.get("interpreter_sink") is True else False
    rendered = " ".join(argv).strip()
    if rendered and rendered.casefold() in text.casefold():
        return True
    name = command_name(argv[0]) if argv else ""
    if argv and name and name in text.casefold():
        if _has_verb(text, "exec"):
            return _cwd_is_named_or_simple(effect, text)
    return False


def _cwd_is_named_or_simple(effect: dict, text: str) -> bool:
    argv = argv_of(effect)
    extras = [item for item in argv[1:] if item.startswith("-")]
    return not extras and bool(re.search(re.escape(command_name(argv[0])), text, re.IGNORECASE))


def _fs_entailed(effect: dict, text: str, event: dict, policy: Policy) -> bool:
    path = str(effect.get("path") or "")
    os_name = event_os(event)
    if glob_any(path, policy.catalog("sensitive_globs"), os_name=os_name):
        return False
    if in_system_critical(path, policy.os_catalog("system_critical", os_name), os_name=os_name):
        return False
    if path and _path_named(path, text, os_name=os_name):
        return True
    verb = {"fs.read": "read", "fs.write": "write", "fs.delete": "delete"}[effect["type"]]
    return path_scope(path, event) == "workspace" and _has_verb(text, verb)


def _net_entailed(effect: dict, text: str) -> bool:
    host = effect.get("host")
    url = effect.get("url")
    ip = effect.get("ip")
    haystack = text.casefold()
    if isinstance(host, str) and host and host.casefold() in haystack:
        return True
    if isinstance(url, str) and url and url.casefold() in haystack:
        return True
    if isinstance(ip, str) and ip and ip in text:
        return True
    return False


def _is_force_push(argv: list[str]) -> bool:
    if not argv or command_name(argv[0]) != "git":
        return False
    folded = [item.casefold() for item in argv]
    if "push" not in folded:
        return False
    if any(item in {"--force", "--force-with-lease", "-f"} for item in folded):
        return True
    return any(item.startswith("--force-with-lease=") or item.startswith("+refs/") for item in folded)


def _has_force(text: str) -> bool:
    if "强制" in text or "强推" in text:
        return True
    return re.search(r"(--force|force-with-lease|\bforce\b|\+refs/)", text, re.IGNORECASE) is not None


def _has_remote(text: str, effect: dict) -> bool:
    if "远程脚本" in text or "远程执行" in text:
        return True
    lowered = text.casefold()
    if any(token in lowered for token in ("curl", "wget", "irm", "iex", "| bash", "|bash")):
        return True
    for item in argv_of(effect):
        if "://" in item and item.casefold() in lowered:
            return True
    raw = effect.get("raw_command")
    if isinstance(raw, str) and "://" in raw:
        for match in re.findall(r"https?://[^\s\"']+", raw):
            if match.casefold() in lowered:
                return True
    return False


def _has_verb(text: str, verb: str) -> bool:
    haystack = text.casefold()
    return any(word.casefold() in haystack for word in _VERBS[verb])


def _path_named(path: str, text: str, *, os_name: str) -> bool:
    forward = path.replace("\\", "/")
    backward = path.replace("/", "\\")
    if os_name == "windows":
        haystack = text.casefold()
        return forward.casefold() in haystack or backward.casefold() in haystack
    return forward in text or backward in text
