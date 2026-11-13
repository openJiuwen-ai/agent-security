# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.


"""Literal shell launch plans for command identity and native execution."""

import os
import pathlib
import re
import shlex
import shutil
from enum import Enum


class ShellType(str, Enum):
    AUTO = "auto"
    CMD = "cmd"
    POWERSHELL = "powershell"
    BASH = "bash"
    SH = "sh"


_POWERSHELL_TOKENS = (
    "powershell ",
    "powershell.exe ",
    "pwsh ",
    "pwsh.exe ",
    "get-childitem",
    "set-location",
    "remove-item",
    "test-path",
    "join-path",
    "select-object",
    "where-object",
    "foreach-object",
    "invoke-webrequest",
    "invoke-restmethod",
    "out-file",
    "start-process",
    "$env:",
    "$psversiontable",
    "$null",
    "$true",
    "$false",
)

_PS_VARIABLE_PATTERN = re.compile(r"(^|[\s;(])\$[A-Za-z_][A-Za-z0-9_]*")

_POWERSHELL_EXECUTABLE_PATTERN = re.compile(
    r"^\s*(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)\b", re.IGNORECASE
)

_POWERSHELL_COMMAND_ARG_PATTERN = re.compile(r"(?is)(?:^|\s)-(?:command|c)\s+(?P<script>.+)\s*$")

_POWERSHELL_CANDIDATES = ("pwsh", "powershell", "powershell.exe")

_POSIX_COMMANDS = frozenset(
    {
        "bash",
        "sh",
        "ls",
        "grep",
        "egrep",
        "fgrep",
        "cat",
        "head",
        "tail",
        "find",
        "rm",
        "cp",
        "mv",
        "touch",
        "chmod",
        "chown",
        "sed",
        "awk",
        "gawk",
        "cut",
        "sort",
        "uniq",
        "wc",
        "du",
        "df",
        "pwd",
        "which",
        "mkdir",
    }
)

_QUOTED_WINDOWS_PATH_PATTERN = re.compile(r"(?P<quote>['\"])(?P<path>[A-Za-z]:\\[^'\"]+)(?P=quote)")

_UNQUOTED_WINDOWS_PATH_PATTERN = re.compile(r"(?<![\w/])(?P<path>[A-Za-z]:\\[^\s|&;]+)")

_UNIX_ABS_PATH_PATTERN = re.compile(r"(?:^|[\s\"'(=,])(/[a-zA-Z0-9_.][^\s\"'|&;()*?]*)")


def _looks_like_powershell(command: str) -> bool:
    lowered = (command or "").strip().lower()
    if not lowered:
        return False
    if any(token in lowered for token in _POWERSHELL_TOKENS):
        return True
    if "@'" in command or '@"' in command:
        return True
    if _looks_like_posix(command):
        return False
    return bool(_PS_VARIABLE_PATTERN.search(command))


def _available_powershell() -> str:
    if os.name == "nt":
        system_root = os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows"
        system_powershell = (
            pathlib.Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        )
        if system_powershell.exists():
            return str(system_powershell)

    for candidate in _POWERSHELL_CANDIDATES:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return "powershell"


def _is_wsl_bash_path(path: str) -> bool:
    normalized = os.path.normcase(os.path.normpath(path))
    system_root = os.path.normcase(os.path.normpath(os.environ.get("SystemRoot") or r"C:\Windows"))
    return normalized == os.path.join(system_root, "system32", "bash.exe") or (
        "\\microsoft\\windowsapps\\bash.exe" in normalized
    )


def _git_bash_candidates() -> list[pathlib.Path]:
    candidates: list[pathlib.Path] = []
    env_path = os.environ.get("GIT_BASH") or os.environ.get("GIT_BASH_PATH")
    if env_path:
        candidates.append(pathlib.Path(env_path))

    for root in (
        os.environ.get("ProgramFiles"),
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("LocalAppData")
        and str(pathlib.Path(os.environ["LocalAppData"]) / "Programs"),
    ):
        if root:
            candidates.append(pathlib.Path(root) / "Git" / "bin" / "bash.exe")

    git_path = shutil.which("git")
    if git_path:
        git_exe = pathlib.Path(git_path)
        # Typical layout: C:\Program Files\Git\cmd\git.exe -> ..\bin\bash.exe
        candidates.append(git_exe.parent.parent / "bin" / "bash.exe")

    return candidates


def _available_git_bash() -> str | None:
    if os.name != "nt":
        return None
    for candidate in _git_bash_candidates():
        if candidate.exists():
            return str(candidate)
    return None


def _available_bash(*, allow_wsl: bool = True) -> str | None:
    if os.name == "nt":
        git_bash = _available_git_bash()
        if git_bash:
            return git_bash
    resolved = shutil.which("bash")
    if resolved and (allow_wsl or not _is_wsl_bash_path(resolved)):
        return resolved
    return None


def _available_sh() -> str | None:
    if os.name == "nt":
        for bash_path in (_available_git_bash(),):
            if bash_path:
                sh_path = pathlib.Path(bash_path).parent.parent / "usr" / "bin" / "sh.exe"
                if sh_path.exists():
                    return str(sh_path)
    return shutil.which("sh")


def _strip_matching_quotes(value: str) -> str:
    stripped = value.strip()
    if len(stripped) >= 2 and stripped[0] == stripped[-1] and stripped[0] in {'"', "'"}:
        return stripped[1:-1]
    return stripped


def _unwrap_powershell_command(command: str) -> str | None:
    """Extract the script from an explicit powershell -Command wrapper.

    Agents often emit commands such as ``powershell -Command "Get-Item ..."``.
    When the local shell runner has already selected PowerShell, executing that
    wrapper would start a nested PowerShell process and load the user's profile.
    On Windows machines with broken Conda profile hooks this fails before the
    intended script runs, so we execute the inner script directly.
    """
    if not _POWERSHELL_EXECUTABLE_PATTERN.match(command or ""):
        return None
    remainder = _POWERSHELL_EXECUTABLE_PATTERN.sub("", command, count=1).strip()
    match = _POWERSHELL_COMMAND_ARG_PATTERN.search(remainder)
    if not match:
        return None
    script = _strip_matching_quotes(match.group("script"))
    return script or None


def _split_shell_segments(command: str) -> list[str]:
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(command):
        char = command[index]
        if char in {'"', "'"}:
            quote = None if quote == char else char if quote is None else quote
        if quote is None and command.startswith(("&&", "||"), index):
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 2
            continue
        if quote is None and char in {"|", ";", "\n", "\r"}:
            segment = "".join(current).strip()
            if segment:
                segments.append(segment)
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    segment = "".join(current).strip()
    if segment:
        segments.append(segment)
    return segments


def _segment_base_command(segment: str) -> str:
    try:
        tokens = shlex.split(segment, posix=False)
    except ValueError:
        return ""
    if not tokens:
        return ""
    base = (
        _strip_matching_quotes(tokens[0])
        .rsplit("/", maxsplit=1)[-1]
        .rsplit("\\", maxsplit=1)[-1]
        .lower()
    )
    return base.removesuffix(".exe")


def _looks_like_posix(command: str) -> bool:
    return any(
        _segment_base_command(segment) in _POSIX_COMMANDS
        for segment in _split_shell_segments(command or "")
    )


def _normalize_windows_paths_for_bash(command: str) -> str:
    def replace_path(match: re.Match[str]) -> str:
        value = match.group("path").replace("\\", "/")
        quote = match.groupdict().get("quote")
        return f"{quote}{value}{quote}" if quote else value

    normalized = _QUOTED_WINDOWS_PATH_PATTERN.sub(replace_path, command)
    return _UNQUOTED_WINDOWS_PATH_PATTERN.sub(replace_path, normalized)


def resolve_execution_plan(
    command: str, shell_type: ShellType
) -> tuple[list[str] | str, bool, str]:
    """Resolve command execution plan based on shell_type.

    Returns:
        (args_or_cmd, use_shell, resolved_shell_name):
        - args_or_cmd: arg list for create_subprocess_exec, or str for create_subprocess_shell
        - use_shell: True → create_subprocess_shell, False → create_subprocess_exec
        - resolved_shell_name: resolved shell name (for logging)
    """
    is_windows = os.name == "nt"

    if is_windows:
        if shell_type == ShellType.AUTO:
            powershell_command = _unwrap_powershell_command(command)
            if powershell_command is not None:
                exe = _available_powershell()
                return (
                    [exe, "-NoProfile", "-NonInteractive", "-Command", powershell_command],
                    False,
                    "powershell",
                )
            if _looks_like_powershell(command):
                exe = _available_powershell()
                return (
                    [exe, "-NoProfile", "-NonInteractive", "-Command", command],
                    False,
                    "powershell",
                )
            if _looks_like_posix(command):
                exe = _available_bash(allow_wsl=False)
                if exe:
                    return (
                        [exe, "-lc", _normalize_windows_paths_for_bash(command)],
                        False,
                        "bash",
                    )
            return command, True, "cmd"
        if shell_type == ShellType.POWERSHELL:
            exe = _available_powershell()
            command = _unwrap_powershell_command(command) or command
            return (
                [exe, "-NoProfile", "-NonInteractive", "-Command", command],
                False,
                "powershell",
            )
        if shell_type == ShellType.CMD:
            return command, True, "cmd"
        if shell_type in {ShellType.BASH, ShellType.SH}:
            exe = (
                _available_bash(allow_wsl=False)
                if shell_type == ShellType.BASH
                else _available_sh()
            )
            if not exe:
                raise ValueError(f"shell '{shell_type.value}' is not available on this system")
            return (
                [
                    exe,
                    "-lc" if shell_type == ShellType.BASH else "-c",
                    _normalize_windows_paths_for_bash(command),
                ],
                False,
                shell_type.value,
            )
        raise ValueError(f"unsupported shell_type for Windows: {shell_type.value}")

    # Non-Windows: auto and sh both use create_subprocess_shell (OS default /bin/sh)
    if shell_type in {ShellType.AUTO, ShellType.SH}:
        return command, True, "sh"
    if shell_type == ShellType.BASH:
        exe = shutil.which("bash") or "/bin/bash"
        return [exe, "-lc", command], False, "bash"
    if shell_type == ShellType.POWERSHELL:
        exe = shutil.which("pwsh") or shutil.which("powershell")
        if not exe:
            raise ValueError("shell 'powershell' is not available on this system")
        return [exe, "-NoProfile", "-NonInteractive", "-Command", command], False, "powershell"
    if shell_type == ShellType.CMD:
        raise ValueError("shell_type 'cmd' is only supported on Windows")
    raise ValueError(f"unsupported shell_type: {shell_type.value}")
