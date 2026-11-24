"""The values the vault's messages carry, rendered the Go's way.

A duration prints as ``30s`` and a list of generations as ``[1 2]``, so
the operator reading one side's log and then the other's sees the same
line on both.
"""

from __future__ import annotations

from typing import Sequence

__all__ = ["format_duration", "format_held_versions"]


def format_duration(seconds: float) -> str:
    """Render a duration the way the Go renders one."""
    if seconds <= 0:
        return "0s"
    if seconds < 1e-6:
        return f"{_trim(seconds * 1e9)}ns"
    if seconds < 1e-3:
        return f"{_trim(seconds * 1e6)}µs"
    if seconds < 1:
        return f"{_trim(seconds * 1e3)}ms"
    if seconds < 60:
        return f"{_trim(seconds)}s"
    minutes = int(seconds // 60)
    rest = seconds - minutes * 60
    if rest == 0:
        return f"{minutes}m"
    return f"{minutes}m{_trim(rest)}s"


def format_held_versions(versions: Sequence[int]) -> str:
    """Render the generations a snapshot holds, the Go's way."""
    return "[" + " ".join(str(int(v)) for v in versions) + "]"


def _trim(value: float) -> str:
    """A number without the trailing zeros a float would print."""
    text = f"{value:.6f}".rstrip("0").rstrip(".")
    return text or "0"
