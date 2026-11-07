"""Error types for the crypto package.

The hierarchy replaces the Go implementation's sentinel errors and
``errors.Is``: catch the base class to mean "any crypto failure", or a
subclass to mean "this particular failure". The names mirror the Go
sentinels one for one.
"""

from __future__ import annotations


class CryptoError(Exception):
    """Base class for every failure raised by this package."""


class InvalidKeySizeError(CryptoError):
    """The key is not the length the cipher requires."""


class InvalidNonceSizeError(CryptoError):
    """The nonce is not 12 bytes."""


class InvalidCiphertextError(CryptoError):
    """The ciphertext is too short to carry an authentication tag."""


class UnsupportedCipherFormatError(CryptoError):
    """The format byte does not match the cipher the caller expected."""


class InvalidModeError(CryptoError):
    """The cipher mode is not one of the supported modes."""


class InvalidWrappedDekLengthError(CryptoError):
    """A wrapped DEK is not exactly 44 bytes."""


class InvalidDekSizeError(CryptoError):
    """A DEK is not exactly 16 bytes."""


class InvalidSaltLengthError(CryptoError):
    """The PBKDF2 salt is not exactly 16 bytes."""


class InvalidKeyLengthError(CryptoError):
    """The derived key length is not the expected 16 bytes."""


class NilHashFuncError(CryptoError):
    """No PRF was supplied for the key derivation."""


class HashUnavailableError(CryptoError):
    """The requested PRF is not available in this Python build.

    SM3 needs OpenSSL to provide it: a build without it must fail loudly
    here rather than halfway through a key derivation.
    """
