"""PBKDF2-HMAC key derivation.

The Go original is ``internal/credmgr/crypto/pbkdf2.go``. The salt
length, the iteration count and the derived key length are fixed by the
format: a change to any of them changes the derived key.

The PRF is SHA-256 for the AES mode and SM3 for the SM4 mode. SM3 needs
OpenSSL to provide it, so a build without it must say so when the
derivation is attempted rather than halfway through it.
"""

from __future__ import annotations

import hashlib

from .errors import (
    HashUnavailableError,
    InvalidKeyLengthError,
    InvalidSaltLengthError,
    NilHashFuncError,
)
from .keybytes import KeyBytes
from .mode import KEK_SIZE, PBKDF2_ITERATIONS, SALT_SIZE

# The PRFs this module knows how to use.
HASH_SHA256 = "sha256"
HASH_SM3 = "sm3"
HASH_NAMES = (HASH_SHA256, HASH_SM3)


def hash_available(hash_name: str) -> bool:
    """Report whether the PRF is usable in this Python build."""
    try:
        hashlib.new(hash_name)
    except (ValueError, TypeError):
        return False
    return True


def pbkdf2_hmac(
    password: bytes,
    salt: bytes,
    hash_name: str = HASH_SHA256,
    iterations: int = PBKDF2_ITERATIONS,
    dklen: int = KEK_SIZE,
) -> KeyBytes:
    """Derive a key from ``password`` and ``salt``.

    The salt must be exactly 16 bytes; the iteration count and the
    derived key length default to the values the store's format fixes.
    """
    if not hash_name:
        raise NilHashFuncError("crypto: hash function must not be nil")
    if len(salt) != SALT_SIZE:
        raise InvalidSaltLengthError(
            f"crypto: invalid salt size: must be {SALT_SIZE} bytes: "
            f"got {len(salt)} bytes"
        )
    if hash_name not in HASH_NAMES:
        raise NilHashFuncError(
            f"crypto: unsupported hash function: {hash_name}"
        )
    if not hash_available(hash_name):
        raise HashUnavailableError(
            f"crypto: the {hash_name} hash is not available in this Python "
            "build; the SM4 mode needs it"
        )
    derived = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations, dklen)
    if len(derived) != dklen:
        raise InvalidKeyLengthError(
            f"crypto: derived key length: got {len(derived)}, want {dklen}"
        )
    return KeyBytes(derived)
