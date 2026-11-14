"""Packaged Windows binaries for the agent-security guards."""

from pathlib import Path

__version__ = "0.1.0"


def binary_directory() -> Path:
    """Return the filesystem directory containing the installed Windows binaries."""
    return Path(__file__).resolve().parent / "bin" / "win_amd64"
