"""Command tokenization, program names, privilege signals, and command-rule matching.

Quotes do not merge tokens. A command line splits on whitespace only.
"""

from __future__ import annotations

import re

SEPARATORS = {"&&", "||", ";", "|"}


def tokenize(text: str) -> list[str]:
    return text.split()


def command_segments(command_line: str) -> list[list[str]]:
    current: list[str] = []
    segments: list[list[str]] = []
    for token in tokenize(command_line):
        if token in SEPARATORS:
            if current:
                segments.append(current)
                current = []
            continue
        current.append(token)
    if current:
        segments.append(current)
    return segments


def normalize_program(token: str, windows: bool) -> str:
    name = token.replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if windows and name.endswith(".exe"):
        return name[:-4]
    return name


def command_rule_matches(rule: str, command_tokens: list[str], windows: bool) -> bool:
    tokens = tokenize(rule)
    if not tokens or not command_tokens:
        return False
    if len(tokens) > len(command_tokens):
        return False
    for index, token in enumerate(tokens):
        if token == "*":
            continue
        actual = command_tokens[index]
        if index == 0:
            if normalize_program(token, windows) != normalize_program(actual, windows):
                return False
        elif token != actual:
            return False
    return True


def command_object_matches(
    rule: str,
    *,
    action: str,
    command_tokens: list[str],
    shell_argv: list[str],
    windows: bool,
    has_command_line: bool,
) -> bool:
    if has_command_line:
        return command_rule_matches(rule, command_tokens, windows)
    if action == "allow":
        return False
    return command_rule_matches(rule, shell_argv, windows)


def command_name(argv0: str) -> str:
    name = str(argv0).replace("\\", "/").rsplit("/", 1)[-1].casefold()
    if name.endswith(".exe"):
        name = name[:-4]
    return name


def argv_of(effect: dict) -> list[str]:
    argv = effect.get("argv")
    if not isinstance(argv, list):
        return []
    return [str(item) for item in argv]


def privilege_requested(effect: dict, privilege_names: set[str]) -> bool:
    if effect.get("type") == "privilege.escalate":
        return True
    meta = effect.get("shell_meta") if isinstance(effect.get("shell_meta"), dict) else {}
    if meta.get("privilege") is True:
        return True
    if effect.get("type") != "process.exec":
        return False
    argv = argv_of(effect)
    if argv and _argv_privilege(argv, privilege_names):
        return True
    raw = effect.get("raw_command")
    if isinstance(raw, str) and raw and _raw_privilege(raw, privilege_names):
        return True
    return False


def _argv_privilege(argv: list[str], privilege_names: set[str]) -> bool:
    name = command_name(argv[0])
    if name in privilege_names:
        return True
    lowered = [item.casefold() for item in argv]
    if name == "chmod" and any(_setuid_token(item) for item in lowered):
        return True
    if name == "chown" and any(_chown_root(item) for item in lowered):
        return True
    joined = " ".join(lowered)
    if "start-process" in joined and "runas" in joined:
        return True
    return False


def _chown_root(item: str) -> bool:
    return item == "root" or item.startswith("root:") or item.startswith("root.")


def _setuid_token(token: str) -> bool:
    if "/" in token or "\\" in token:
        return False
    return token in {"u+s", "g+s", "a+s", "+s"} or token.endswith("+s")


def _raw_privilege(raw: str, privilege_names: set[str]) -> bool:
    lowered = raw.casefold()
    for name in privilege_names:
        if re.search(rf"(^|[\s;&|(]){re.escape(name)}([\s;&)|]|$)", lowered):
            return True
    if "start-process" in lowered and "runas" in lowered:
        return True
    if re.search(r"\bchmod\b[^\n|;&]*\+[sS]", raw):
        return True
    if re.search(r"\bchown\b[^\n|;&]*\broot\b", lowered):
        return True
    return False
