"""Locate the optional Windows binary distribution or its in-tree build."""

from pathlib import Path


def guard_binary_directory() -> Path:
    try:
        from agent_security_dll import binary_directory
    except ModuleNotFoundError as exc:
        if exc.name != "agent_security_dll":
            raise
        # Source checkouts can use the build scripts' wheel staging directory.
        return Path(__file__).resolve().parents[2] / (
            "native/windows-process-guard/python/src/agent_security_dll/bin/win_amd64"
        )
    return binary_directory()
