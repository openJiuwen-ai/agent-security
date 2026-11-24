"""Type phrases and the concrete target shown to the user."""

from __future__ import annotations

from agent_shield.policy_engine.matchers.network import endpoint_host, endpoint_ip
from agent_shield.policy_engine.matchers.command import argv_of

_FILE = {"fs.read": ("文件读取", "读取"), "fs.write": ("文件写入", "写入"), "fs.delete": ("文件删除", "删除")}
_NET = {"net.connect": ("网络连接", "连接"), "net.fetch": ("网络拉取", "拉取"), "net.egress": ("网络外发", "向外发送到")}


def object_phrase(kind: str) -> str:
    return {
        "file": "文件",
        "domain": "网络",
        "command": "命令执行",
        "agentTools": "工具调用",
        "nativeTools": "本机程序启动",
    }.get(kind, "")


def file_phrase(effect_type: str) -> str:
    return _FILE.get(effect_type, ("", ""))[0]


def domain_phrase(effect_type: str) -> str:
    return _NET.get(effect_type, ("", ""))[0]


def content_for_effect(effect: dict) -> str:
    kind = effect.get("type")
    if kind in _FILE:
        return f"{_FILE[kind][1]} {effect.get('path') or ''}".strip()
    if kind in _NET:
        target = endpoint_host(effect) or endpoint_ip(effect) or ""
        return f"{_NET[kind][1]} {target}".strip()
    if kind == "process.exec":
        return "执行 " + _command_text(effect)
    return ""


def command_text(effect: dict) -> str:
    return _command_text(effect)


def _command_text(effect: dict) -> str:
    stored = effect.get("command_tokens")
    if isinstance(stored, list) and stored and all(isinstance(item, str) and item for item in stored):
        return " ".join(stored)
    line = effect.get("command_line")
    if isinstance(line, str) and line.strip():
        return line.strip()
    return " ".join(argv_of(effect))
