"""Cryptographic primitives for the store and the router.

Everything here is byte-compatible with the Go package
``internal/credmgr/crypto``: the same key, nonce and plaintext produce
the same ciphertext and tag in either implementation, so one
implementation reads the other's files.
"""

from __future__ import annotations

from .aead import aes_decrypt, aes_encrypt, sm4_decrypt, sm4_encrypt
from .errors import (
    CryptoError,
    HashUnavailableError,
    InvalidCiphertextError,
    InvalidDekSizeError,
    InvalidKeyLengthError,
    InvalidKeySizeError,
    InvalidModeError,
    InvalidNonceSizeError,
    InvalidSaltLengthError,
    InvalidWrappedDekLengthError,
    NilHashFuncError,
    UnsupportedCipherFormatError,
)
from .keybytes import KeyBytes
from .mode import (
    AES_KEY_SIZE,
    DEK_SIZE,
    FORMAT_BYTE_SIZE,
    KEK_SIZE,
    MODE_AES,
    MODE_HASH,
    MODE_NAMES,
    MODE_SM4,
    NONCE_SIZE,
    PBKDF2_ITERATIONS,
    SALT_SIZE,
    SHARD_SIZE,
    SM4_KEY_SIZE,
    TAG_SIZE,
    WRAPPED_DEK_SIZE,
    Mode,
    mode_str,
    parse_mode,
)
from .pbkdf2 import (
    HASH_NAMES,
    HASH_SHA256,
    HASH_SM3,
    hash_available,
    pbkdf2_hmac,
)
from .wire_format import (
    decrypt_credential,
    encrypt_credential,
    probe_unwrap_dek,
    unwrap_dek,
    wrap_dek,
)

__all__ = [
    "AES_KEY_SIZE",
    "CryptoError",
    "DEK_SIZE",
    "FORMAT_BYTE_SIZE",
    "HASH_NAMES",
    "HASH_SHA256",
    "HASH_SM3",
    "HashUnavailableError",
    "InvalidCiphertextError",
    "InvalidDekSizeError",
    "InvalidKeyLengthError",
    "InvalidKeySizeError",
    "InvalidModeError",
    "InvalidNonceSizeError",
    "InvalidSaltLengthError",
    "InvalidWrappedDekLengthError",
    "KEK_SIZE",
    "KeyBytes",
    "MODE_AES",
    "MODE_HASH",
    "MODE_NAMES",
    "MODE_SM4",
    "Mode",
    "NONCE_SIZE",
    "NilHashFuncError",
    "PBKDF2_ITERATIONS",
    "SALT_SIZE",
    "SHARD_SIZE",
    "SM4_KEY_SIZE",
    "TAG_SIZE",
    "WRAPPED_DEK_SIZE",
    "aes_decrypt",
    "aes_encrypt",
    "decrypt_credential",
    "encrypt_credential",
    "hash_available",
    "mode_str",
    "parse_mode",
    "pbkdf2_hmac",
    "probe_unwrap_dek",
    "sm4_decrypt",
    "sm4_encrypt",
    "unwrap_dek",
    "wrap_dek",
    "UnsupportedCipherFormatError",
]
