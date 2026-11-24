"""The cipher mode and the sizes that belong to it.

Every other module in the package sizes its buffers from these, so a
wrong number here is a wrong number everywhere.
"""

from __future__ import annotations

from enum import IntEnum

from .errors import InvalidModeError

# FormatByteSize is the size of the format version prefix byte.
FORMAT_BYTE_SIZE = 1

# DEKSize is the required data-encryption-key size in bytes (16 bytes,
# 128-bit AES or SM4 symmetric key).
DEK_SIZE = 16

# ShardSize is the byte length of one KEK shard (S1, S2 and S3 are each
# ShardSize bytes). The 16-byte KEK is derived by PBKDF2 over the XOR of
# all three shards. S3 is compiled into the binary, S1 is a local file,
# S2 lives in the SQLite key metadata table. All three are required: no
# single shard or pair alone can reconstruct the KEK.
SHARD_SIZE = 32

# NonceSize is the GCM nonce size in bytes: 12 bytes (96 bits).
NONCE_SIZE = 12

# TagSize is the GCM authentication tag size in bytes: 16 bytes (128 bits).
TAG_SIZE = 16

# AESKeySize is the required key size for AES-128: 16 bytes.
AES_KEY_SIZE = 16

# SM4KeySize is the required key size for SM4: 16 bytes (128 bits).
SM4_KEY_SIZE = 16

# WrappedDEKSize is the exact byte length of a wrapped DEK: nonce(12) +
# ciphertext(16) + tag(16) = 44 bytes.
WRAPPED_DEK_SIZE = NONCE_SIZE + DEK_SIZE + TAG_SIZE  # 44

# SaltSize is the required salt length in bytes (fixed at compile time).
SALT_SIZE = 16

# KEKSize is the key-encryption-key length in bytes.
KEK_SIZE = 16

# PBKDF2Iterations is the iteration count for PBKDF2-HMAC key derivation.
PBKDF2_ITERATIONS = 10000


class Mode(IntEnum):
    """The cipher a store's data encryption key is encrypted with.

    Fixed at initialisation: a store cannot change its cipher
    afterwards.
    """

    AES = 0x01
    SM4 = 0x02

    def __str__(self) -> str:
        if self is Mode.AES:
            return "aes"
        if self is Mode.SM4:
            return "sm"
        return f"unknown({int(self)})"


MODE_AES = Mode.AES
MODE_SM4 = Mode.SM4

# The mode names a configuration file may use.
MODE_NAMES = ("aes", "sm")

# The PRF each mode derives its KEK with.
MODE_HASH = {Mode.AES: "sha256", Mode.SM4: "sm3"}


def parse_mode(s: str) -> Mode:
    """Convert a human-readable mode name into a Mode value."""
    if s == "aes":
        return Mode.AES
    if s == "sm":
        return Mode.SM4
    raise InvalidModeError(f"crypto: invalid mode: {s}")


def mode_str(m: Mode | int) -> str:
    """Return the human-readable name of a mode."""
    try:
        return str(Mode(m))
    except ValueError:
        return f"unknown({int(m) & 0xFF})"
