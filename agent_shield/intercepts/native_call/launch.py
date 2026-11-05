"""Locate the Windows process guard binaries and start a hooked process.

A task that asked for interception must not fall back to a bare host process.
The process guard fails closed when the pipe, architecture, or injection is unavailable.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


class ProcessGuardUnavailable(RuntimeError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class PreflightResult:
    ok: bool
    reason: str
    intercept: bool


_BINARIES = ("process_guard.exe", "process_guard_hook_x64.dll", "process_guard_hook_x86.dll")
_FAIL_EXIT = 83
_TOOL_CALL_ID_MAX = 127
_TOOL_NAME_MAX = 255


def preflight() -> PreflightResult:
    reason = _availability(None)
    if reason != "ok":
        return PreflightResult(False, reason, False)
    return PreflightResult(True, "ok", True)


def wrap(
    argv: list[str],
    *,
    decide=None,
    delete_mode: str = "trash",
    decision_timeout_s: float = 300,
    process_timeout_s: float | None = None,
    bin_dir: str | None = None,
    tool_call_id: str | None = None,
    tool_name: str | None = None,
) -> int:
    """Start argv inside the process guard. The returned code is the child's exit code."""
    _validate_tool_cause(tool_call_id, tool_name)
    reason = _availability(bin_dir)
    if reason != "ok":
        raise ProcessGuardUnavailable(reason)
    if decide is None:
        raise ProcessGuardUnavailable("decide_required")
    if delete_mode not in {"trash", "permanent"}:
        raise ProcessGuardUnavailable("invalid_delete_mode")
    if decision_timeout_s <= 0:
        raise ProcessGuardUnavailable("invalid_decision_timeout")
    if not argv:
        raise ProcessGuardUnavailable("empty_command")
    binaries = _binaries(bin_dir)
    if binaries is None:
        raise ProcessGuardUnavailable("process_guard_binary_missing")
    from agent_shield.intercepts.native_call.decide_pipe import DecidePipe

    pipe = DecidePipe(decide)
    pipe.start()
    try:
        try:
            command = [
                binaries["process_guard.exe"],
                "--decide-pipe",
                pipe.name,
                "--hook-dll",
                binaries["process_guard_hook_x64.dll"],
                "--hook-dll-x86",
                binaries["process_guard_hook_x86.dll"],
                "--delete-mode",
                delete_mode,
                "--decision-timeout-ms",
                str(int(decision_timeout_s * 1000)),
            ]
            if tool_call_id is not None:
                command.extend(["--tool-call-id", tool_call_id, "--tool-name", tool_name or ""])
            command.append("--")
            command.extend(argv)
            completed = subprocess.run(
                command,
                check=False,
                timeout=process_timeout_s,
            )
        except subprocess.TimeoutExpired as exc:
            raise ProcessGuardUnavailable("process_guard_timeout") from exc
    finally:
        pipe.close()
    if completed.returncode == _FAIL_EXIT:
        raise ProcessGuardUnavailable("process_guard_start_failed")
    return completed.returncode


def _validate_tool_cause(tool_call_id: str | None, tool_name: str | None) -> None:
    if tool_call_id is None and tool_name is None:
        return
    if _tool_text(tool_call_id, _TOOL_CALL_ID_MAX) is None or _tool_text(tool_name, _TOOL_NAME_MAX) is None:
        raise ProcessGuardUnavailable("invalid_tool_cause")


def _tool_text(value: str | None, limit: int) -> str | None:
    if not isinstance(value, str) or value == "" or any(ord(char) < 32 for char in value):
        return None
    if len(value.encode("utf-8")) > limit:
        return None
    return value


def _availability(bin_dir: str | None) -> str:
    if sys.platform != "win32":
        return "unsupported_platform"
    machine = platform.machine().casefold()
    if machine not in {"amd64", "x86_64"}:
        return "unsupported_architecture"
    if _binaries(bin_dir) is None:
        return "process_guard_binary_missing"
    return "ok"


def _binaries(bin_dir: str | None = None) -> dict[str, str] | None:
    if bin_dir is not None:
        root = Path(bin_dir)
        if not all((root / name).is_file() for name in _BINARIES):
            return None
        return {name: str(root / name) for name in _BINARIES}
    try:
        from importlib.resources import files

        packaged = files("agent_security_windows_process_guard").joinpath("bin", "win_amd64")
    except (ModuleNotFoundError, TypeError):
        return None
    if not all(packaged.joinpath(name).is_file() for name in _BINARIES):
        return None
    return {name: str(packaged.joinpath(name)) for name in _BINARIES}
