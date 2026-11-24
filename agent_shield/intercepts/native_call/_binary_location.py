"""Locate the optional Windows binary distribution or its in-tree build."""

from pathlib import Path
from functools import lru_cache
import importlib.util


def guard_binary_directory() -> Path:
    try:
        from agent_security_dll import binary_directory
    except ModuleNotFoundError as exc:
        if exc.name != "agent_security_dll":
            raise
        # Source checkouts can use the build scripts' wheel staging directory.
        return Path(__file__).resolve().parents[3] / (
            "foundation/agent-security-dll/build"
        )
    return binary_directory()


@lru_cache(maxsize=1)
def guard_loader():
    """Use the common loader from the wheel or this source checkout."""
    try:
        import agent_security_dll
        return agent_security_dll
    except ModuleNotFoundError as exc:
        if exc.name != "agent_security_dll":
            raise
    path = Path(__file__).resolve().parents[3] / "foundation/agent-security-dll/src/agent_security_dll/__init__.py"
    if not path.is_file():
        raise ModuleNotFoundError("Install agent-security-dll to validate the native bundle")
    spec = importlib.util.spec_from_file_location("_foundation_guard_loader", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
