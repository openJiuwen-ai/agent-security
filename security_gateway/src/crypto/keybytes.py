"""A defensive wrapper around key material.

It deep-copies on construction and copies on reads, so a caller cannot
mutate the buffer behind the wrapper or read the buffer out of it.

``zero()`` is the only way to invalidate the material: there is no
``__del__``, because key material must be wiped at a point the program
decides, not at a point the garbage collector happens to pick.

**The material is pinned where it is made.** A key that reaches the swap
file or a core dump is a key on disk. The limit on how much may be
locked is the operating system's, so this is best effort: when it does
not work, the log says so.
"""

from __future__ import annotations

import logging
import os

from ..platform import memlock

LOG = logging.getLogger(__name__)


class KeyBytes:
    """Sensitive key material, copied in and copied out."""

    __slots__ = ("_b",)

    def __init__(self, src: bytes) -> None:
        """Deep-copy ``src``."""
        self._b = bytearray(src)
        self._lock()

    @classmethod
    def random(cls, n: int) -> "KeyBytes":
        """Create a KeyBytes of length ``n`` filled with random bytes."""
        return cls(os.urandom(n))

    def bytes(self) -> bytes:
        """Return a deep copy of the key material."""
        return bytes(self._b)

    def __len__(self) -> int:
        return len(self._b)

    def __bytes__(self) -> bytes:
        return bytes(self._b)

    def is_zero(self) -> bool:
        """Report whether every byte is zero."""
        return not any(self._b)

    def zero(self) -> None:
        """Clear the buffer, marking the key material as invalidated."""
        self._b[:] = bytes(len(self._b))
        try:
            memlock.unlock(self._b)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            LOG.warning("could not release the pinned key material: %s", exc)

    def hex(self) -> str:
        """Return the hex encoding of the key bytes."""
        return bytes(self._b).hex()

    def __repr__(self) -> str:
        # Never print the material, not even in a traceback.
        return f"KeyBytes(len={len(self._b)})"

    def _lock(self) -> None:
        """Pin the pages holding the key, so the kernel cannot swap them out."""
        try:
            memlock.lock(self._b)
        except Exception as exc:  # noqa: BLE001 - reported, not fatal
            LOG.warning(
                "could not lock the key material in memory: %s (%s)",
                exc, memlock.report())

