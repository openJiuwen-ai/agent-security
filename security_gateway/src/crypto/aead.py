"""AES-128-GCM and SM4-GCM.

The Go original is ``internal/credmgr/crypto/aead.go``. Both build a
standard GCM AEAD over a 128-bit block cipher and return the ciphertext
with the tag appended, so the bytes on disk are the Go binary's. SM4 and
GCM are both standardised: the same key, nonce and plaintext produce the
same ciphertext and tag in either implementation.
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .errors import (
    InvalidCiphertextError,
    InvalidKeySizeError,
    InvalidNonceSizeError,
)
from .mode import AES_KEY_SIZE, NONCE_SIZE, SM4_KEY_SIZE, TAG_SIZE


def _encrypt(algorithm_cls, key: bytes, plaintext: bytes, key_size: int,
              name: str) -> tuple[bytes, bytes]:
    if len(key) != key_size:
        raise InvalidKeySizeError(
            f"crypto: invalid key size: got {len(key)}, want {key_size}"
        )
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithm_cls(key), modes.GCM(nonce)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    # Go's Seal appends the tag to the ciphertext; keep the same shape.
    return nonce, ciphertext + encryptor.tag


def _decrypt(algorithm_cls, key: bytes, nonce: bytes, ciphertext: bytes,
             key_size: int) -> bytes:
    if len(key) != key_size:
        raise InvalidKeySizeError(
            f"crypto: invalid key size: got {len(key)}, want {key_size}"
        )
    if len(nonce) != NONCE_SIZE:
        raise InvalidNonceSizeError(
            f"crypto: invalid nonce size: got {len(nonce)}, want {NONCE_SIZE}"
        )
    if len(ciphertext) < TAG_SIZE:
        raise InvalidCiphertextError(
            "crypto: invalid ciphertext: ciphertext too short: got "
            f"{len(ciphertext)} bytes, need at least {TAG_SIZE}"
        )
    tag = ciphertext[-TAG_SIZE:]
    body = ciphertext[:-TAG_SIZE]
    decryptor = Cipher(
        algorithm_cls(key), modes.GCM(nonce, tag)
    ).decryptor()
    try:
        return decryptor.update(body) + decryptor.finalize()
    except InvalidTag as exc:
        raise InvalidCiphertextError(
            f"crypto: authentication failed: {exc}"
        ) from exc


def aes_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with AES-128-GCM.

    Returns the 12-byte nonce and the ciphertext with the 16-byte tag
    appended. The key must be exactly 16 bytes.
    """
    return _encrypt(algorithms.AES, key, plaintext, AES_KEY_SIZE, "aes")


def aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt an AES-128-GCM ciphertext whose tag is appended."""
    return _decrypt(algorithms.AES, key, nonce, ciphertext, AES_KEY_SIZE)


def sm4_encrypt(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt with SM4-GCM.

    Returns the 12-byte nonce and the ciphertext with the 16-byte tag
    appended. The key must be exactly 16 bytes.
    """
    return _encrypt(algorithms.SM4, key, plaintext, SM4_KEY_SIZE, "sm4")


def sm4_decrypt(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt an SM4-GCM ciphertext whose tag is appended."""
    return _decrypt(algorithms.SM4, key, nonce, ciphertext, SM4_KEY_SIZE)
