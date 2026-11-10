# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Bounded, conservative read-only evidence for control-plane error handling.

This recognizes a subset of existing read commands; absence of extracted writes
is not evidence. It never resolves paths, evaluates variables or launches code.
"""

import re

from .path_extract import (
    _CMD_WORD_RE,
    _POSIX_WORD_RE,
    _SHELL_WORD_RE,
    ShellPathUnresolvedShellError,
    _shell_profiles,
    _shell_segments,
)

_MAX_CHARS = 32768
_MAX_STEPS = 1024
_COMMON_READ_COMMANDS = frozenset({"cd", "cat", "ls", "dir", "type", "head", "tail", "pwd"})
_PS_READ_COMMANDS = frozenset({"get-content", "gc", "get-childitem", "gci", "get-location"})
_SEPARATORS = frozenset({"", "&&", "||", ";", "\r", "\n", "|", "|&"})
_VARIABLE = re.compile(r"\$(?:[A-Za-z_]\w*(?::[A-Za-z_]\w*)?|\{[A-Za-z_]\w*(?::[A-Za-z_]\w*)?\})")


def _opens_shell_quote(char: str, shell_type: str, quote: str) -> bool:
    """True when this character starts a quote that the read-only scan tracks."""
    if char == '"':
        return True
    if char != "'" or shell_type == "cmd":
        return False
    return not quote


def _readonly_word_stops(char: str, shell_type: str, quote: str) -> bool:
    """True for command substitution or an unquoted shell metacharacter."""
    command_subst = char == "`" and shell_type in {"bash", "sh"}
    bare_metachar = not quote and char in "(){}[]#;&|<>@"
    return command_subst or bare_metachar


def _read_word(word: str, shell_type: str) -> bool:
    if shell_type == "cmd" and any(char in word for char in "%!^"):
        return False  # CMD expansion can insert new command syntax before parsing.
    escape = {"bash": "\\", "sh": "\\", "powershell": "`", "cmd": "^"}[shell_type]
    quote = ""
    index = 0
    while index < len(word):
        char = word[index]
        if char in "\r\n":
            return False
        if quote == "'":
            if char == "'":
                quote = ""
        elif char == escape:
            index += 1
            if index == len(word) or word[index] in "\r\n":
                return False
        elif _opens_shell_quote(char, shell_type, quote):
            quote = "" if quote == char else char
        elif char == "$" and shell_type != "cmd":
            variable = _VARIABLE.match(word, index)
            if variable is None:
                return False
            if shell_type == "powershell" and not variable.group().lower().startswith(("$env:", "${env:")):
                # Opaque PowerShell values can be script blocks or have active
                # conversions during binding. Environment values are strings.
                return False
            index = variable.end() - 1
            if shell_type == "powershell" and word[index + 1:index + 2] in {".", "["}:
                return False
        elif _readonly_word_stops(char, shell_type, quote):
            return False
        index += 1
    return not quote


def _read_segment(segment: str, shell_type: str, budget: list[int]) -> bool:
    pattern = _CMD_WORD_RE if shell_type == "cmd" else (
        _POSIX_WORD_RE if shell_type in {"bash", "sh"} else _SHELL_WORD_RE
    )
    words: list[str] = []
    end = 0
    for match in pattern.finditer(segment):
        budget[0] -= 1
        if budget[0] < 0 or segment[end:match.start()].strip(" \t"):
            return False
        words.append(match.group())
        end = match.end()
    if segment[end:].strip(" \t") or not words:
        return False
    allowed = _COMMON_READ_COMMANDS | (_PS_READ_COMMANDS if shell_type == "powershell" else frozenset())
    executable = words[0].lower() if shell_type in {"cmd", "powershell"} else words[0]
    if executable not in allowed:
        return False  # No path-qualified programs, interpreters or indirect execution.
    input_target = False
    for word in words[1:]:
        if word == "<" and not input_target:
            input_target = True
            continue
        if word in {"<", ">", ">>"} or not _read_word(word, shell_type):
            return False
        input_target = False
    return not input_target


def _readonly_profiles(shell_type: str) -> tuple[str, ...]:
    """Unknown shells must be read-only in every dialect that could run them.

    Path extraction keeps a host-specific ``auto`` view. Read-only evidence
    cannot: a POSIX reading of ``$DEPS`` is not proof on PowerShell.
    """
    if shell_type == "auto":
        return ("cmd", "powershell", "sh")
    return _shell_profiles("", shell_type)


def is_read_only_shell(command: str, shell_type: str) -> bool:
    """True only for a complete bounded call in the supported read-only subset."""
    if not command or len(command) > _MAX_CHARS:
        return False
    if any(
        (char.isspace() or ord(char) < 32) and char not in " \t\r\n"
        for char in command
    ):
        return False
    budget = [_MAX_STEPS]
    for profile in _readonly_profiles(shell_type):
        if profile not in {"bash", "sh", "cmd", "powershell"}:
            return False
        try:
            segments = _shell_segments(command, profile)
        except ShellPathUnresolvedShellError:
            return False
        if not segments:
            return False
        for segment, separator in segments:
            budget[0] -= 1
            if budget[0] < 0 or separator not in _SEPARATORS:
                return False
            if not _read_segment(segment, profile, budget):
                return False
    return True
