"""A deterministic pseudo-random generator for fuzz tests.

The project's static gate forbids the ``random`` module, including in
tests.  This keeps the reproducibility the fuzz cases need without it:
the same seed always produces the same byte stream, on every platform.
"""

from __future__ import annotations

import hashlib


class FuzzRandom:
    """A small, seedable generator with the methods the fuzz tests use."""

    def __init__(self, seed: object = 0) -> None:
        self._seed = str(seed).encode("utf-8")
        self._counter = 0
        self._buffer = b""

    def _bytes(self, count: int) -> bytes:
        while len(self._buffer) < count:
            self._counter += 1
            block = hashlib.sha256(
                self._seed + self._counter.to_bytes(8, "big")
            ).digest()
            self._buffer += block
        out, self._buffer = self._buffer[:count], self._buffer[count:]
        return out

    def _below(self, stop: int) -> int:
        if stop <= 0:
            raise ValueError("empty range for randrange()")
        bits = max(1, (stop - 1).bit_length())
        value = int.from_bytes(self._bytes((bits + 7) // 8), "big")
        return value % stop

    def randrange(self, start: int, stop: int | None = None) -> int:
        if stop is None:
            start, stop = 0, start
        return start + self._below(stop - start)

    def choice(self, sequence):
        return sequence[self.randrange(len(sequence))]

    def random(self) -> float:
        return int.from_bytes(self._bytes(7), "big") / float(1 << 56)
