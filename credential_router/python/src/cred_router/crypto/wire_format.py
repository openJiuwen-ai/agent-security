"""The on-disk formats of encrypted material.

The Go original is ``internal/credmgr/crypto/wire_format.go``. Two
shapes are defined here, and both are fixed by the format, not by taste:

    a credential   format(1) || nonce(12) || ciphertext || tag(16)
    a wrapped DEK  nonce(12) || ciphertext(16) || tag(16)   = 44 bytes

The credential's format byte is the cipher mode, so a reader told which
cipher to use can refuse a blob written under another one instead of
guessing.
"""

from __future__ import annotations

from .aead import aes_decrypt, aes_encrypt, sm4_decrypt, sm4_encrypt
from .errors import (
    InvalidCiphertextError,
    InvalidDekSizeError,
    InvalidModeError,
    InvalidWrappedDekLengthError,
    UnsupportedCipherFormatError,
)
from .mode import (
    DEK_SIZE,
    FORMAT_BYTE_SIZE,
    NONCE_SIZE,
    TAG_SIZE,
    WRAPPED_DEK_SIZE,
    Mode,
)


def _encrypt_raw(mode: Mode, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt without the format byte."""
    if mode is Mode.AES:
        return aes_encrypt(key, plaintext)
    if mode is Mode.SM4:
        return sm4_encrypt(key, plaintext)
    raise InvalidModeError(f"crypto: invalid mode: {mode}")


def _decrypt_raw(mode: Mode, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    if mode is Mode.AES:
        return aes_decrypt(key, nonce, ciphertext)
    if mode is Mode.SM4:
        return sm4_decrypt(key, nonce, ciphertext)
    raise InvalidModeError(f"crypto: invalid mode: {mode}")


def encrypt_credential(mode: Mode, key: bytes, plaintext: bytes) -> bytes:
    """Encrypt a plaintext credential under the given mode and DEK."""
    nonce, ct = _encrypt_raw(mode, key, plaintext)
    return bytes([int(mode)]) + nonce + ct


def decrypt_credential(mode: Mode, key: bytes, blob: bytes) -> bytes:
    """Decrypt a credential blob, verifying that the format byte matches.

    Raises :class:`InvalidModeError` for an unrecognised mode and
    :class:`UnsupportedCipherFormatError` for a blob written under
    another cipher.
    """
    if mode is not Mode.AES and mode is not Mode.SM4:
        raise InvalidModeError(f"crypto: invalid mode: {mode}")
    if len(blob) < FORMAT_BYTE_SIZE + NONCE_SIZE + TAG_SIZE:
        raise InvalidCiphertextError(
            f"crypto: invalid ciphertext: blob too short: {len(blob)} bytes"
        )
    if Mode(blob[0]) is not mode:
        raise UnsupportedCipherFormatError(
            f"crypto: unsupported cipher format: got 0x{blob[0]:02x}, "
            f"want {mode}"
        )
    nonce = blob[FORMAT_BYTE_SIZE:FORMAT_BYTE_SIZE + NONCE_SIZE]
    ct = blob[FORMAT_BYTE_SIZE + NONCE_SIZE:]
    return _decrypt_raw(mode, key, nonce, ct)


def wrap_dek(mode: Mode, kek: bytes, dek: bytes) -> bytes:
    """Encrypt a DEK under the given mode and KEK."""
    if len(dek) != DEK_SIZE:
        raise InvalidDekSizeError(
            f"crypto: invalid DEK size: got {len(dek)}, want {DEK_SIZE}"
        )
    nonce, ct = _encrypt_raw(mode, kek, dek)
    return nonce + ct


def unwrap_dek(mode: Mode, kek: bytes, wrapped: bytes) -> bytes:
    """Decrypt a 44-byte wrapped DEK and return the 16-byte DEK."""
    if len(wrapped) != WRAPPED_DEK_SIZE:
        raise InvalidWrappedDekLengthError(
            f"crypto: invalid wrapped DEK length: got {len(wrapped)}, "
            f"want {WRAPPED_DEK_SIZE}"
        )
    nonce = wrapped[:NONCE_SIZE]
    ct = wrapped[NONCE_SIZE:]
    dek = _decrypt_raw(mode, kek, nonce, ct)
    if len(dek) != DEK_SIZE:
        raise InvalidDekSizeError(
            f"crypto: unwrapped DEK invalid size: {len(dek)}"
        )
    return dek


def probe_unwrap_dek(mode: Mode, kek: bytes, dek: bytes, wrapped: bytes) -> None:
    """Check that ``wrapped`` decrypts to ``dek`` under ``kek``.

    Two facts at once: the wrapped DEK decrypts cleanly with the given
    KEK (no corruption), and the unwrapped bytes match the DEK already
    loaded (no stale wrap from a prior key version). Raises on any
    failure.
    """
    if len(wrapped) != WRAPPED_DEK_SIZE:
        raise InvalidWrappedDekLengthError(
            f"crypto: invalid wrapped DEK length: got {len(wrapped)}, "
            f"want {WRAPPED_DEK_SIZE}"
        )
    unwrapped = unwrap_dek(mode, kek, wrapped)
    if unwrapped != dek:
        raise InvalidCiphertextError(
            "crypto: ProbeUnwrapDEK: plaintext mismatch"
        )
