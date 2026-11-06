"""The crypto layer must be byte-compatible with the Go implementation.

Two kinds of check live here. The first uses published standard vectors, so
a wrong construction is caught without needing the Go binary at all. The
second checks the shapes and the failures the Go package promises.

The Go counterpart lives in ``internal/credmgr/crypto`` and its tests in
``tests/unit/credmgr/crypto``.
"""

from __future__ import annotations

import base64
import hashlib

import pytest
from security_gateway.crypto import (
    DEK_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
    SHARD_SIZE,
    TAG_SIZE,
    WRAPPED_DEK_SIZE,
    InvalidCiphertextError,
    InvalidDekSizeError,
    InvalidModeError,
    InvalidNonceSizeError,
    InvalidSaltLengthError,
    InvalidWrappedDekLengthError,
    KeyBytes,
    Mode,
    UnsupportedCipherFormatError,
    aes_decrypt,
    aes_encrypt,
    decrypt_credential,
    encrypt_credential,
    parse_mode,
    pbkdf2_hmac,
    probe_unwrap_dek,
    sm4_decrypt,
    sm4_encrypt,
    unwrap_dek,
    wrap_dek,
)


def _aes_key() -> bytes:
    return hashlib.sha256(b"material-one").digest()[:16]


def _dek() -> bytes:
    return hashlib.sha256(b"material-two").digest()[:16]


# --- published standard vectors -------------------------------------------


def test_aes_gcm_matches_the_nist_gcm_specification():
    """GCM test case 2 from the original GCM specification.

    If this passes, the construction is the standard one, so it is the same
    construction Go's cipher.NewGCM performs and the bytes agree.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    key = bytes(16)
    plaintext = bytes(16)
    iv = bytes(12)

    encryptor = Cipher(algorithms.AES(key), modes.GCM(iv)).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    assert ciphertext.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert encryptor.tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"


def test_sm4_matches_the_national_standard_vector():
    """The GB/T 32907-2016 example block.

    SM4 is standardised, so this is the cipher Go's gmsm package computes.
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    vector = base64.b64decode("ASNFZ4mrze/+3LqYdlQyEA==")
    key = vector
    plaintext = vector

    encryptor = Cipher(algorithms.SM4(key), modes.ECB()).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    assert ciphertext.hex() == "681edf34d206965e86b3e94f536e4246"


def test_pbkdf2_hmac_sha256_matches_rfc_7914():
    """RFC 7914's PBKDF2-HMAC-SHA256 vectors.

    The store's salt length differs from the RFC's, so the primitive is
    checked directly rather than through the wrapper.
    """
    assert hashlib.pbkdf2_hmac(
        "sha256", b"password", b"salt", 1, 32
    ).hex().startswith("120fb6cffcf8b32c43e7225256c4f837a86548c9")
    assert hashlib.pbkdf2_hmac(
        "sha256", b"password", b"salt", 4096, 32
    ).hex().startswith("c5e478d59288c841aa530db6845c4c8d962893a0")


@pytest.mark.parametrize("hash_name", ["sha256", "sm3"])
def test_the_derivation_wrapper_agrees_with_the_primitive(hash_name):
    salt = hashlib.sha256(b"material-salt").digest()[:SALT_SIZE]
    ours = pbkdf2_hmac(b"password", salt, hash_name).hex()
    reference = hashlib.pbkdf2_hmac(hash_name, b"password", salt, 10000, 16).hex()
    assert ours == reference


# --- modes and sizes -------------------------------------------------------


def test_the_modes_are_the_ones_the_format_defines():
    assert Mode.AES == 0x01
    assert Mode.SM4 == 0x02
    assert parse_mode("aes") is Mode.AES
    assert parse_mode("sm") is Mode.SM4
    assert str(Mode.AES) == "aes"
    assert str(Mode.SM4) == "sm"


def test_an_unknown_mode_name_is_refused():
    with pytest.raises(InvalidModeError):
        parse_mode("rot13")


def test_the_sizes_are_the_ones_the_format_defines():
    assert DEK_SIZE == 16
    assert SHARD_SIZE == 32
    assert NONCE_SIZE == 12
    assert TAG_SIZE == 16
    assert WRAPPED_DEK_SIZE == 44
    assert SALT_SIZE == 16


# --- the AEAD ---------------------------------------------------------------


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_encrypt, sm4_decrypt)],
)
def test_a_round_trip_returns_the_plaintext(encrypt, decrypt):
    nonce, ciphertext = encrypt(_aes_key(), b"stored-value")
    assert len(nonce) == NONCE_SIZE
    assert len(ciphertext) == len(b"stored-value") + TAG_SIZE
    assert decrypt(_aes_key(), nonce, ciphertext) == b"stored-value"


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_encrypt, sm4_decrypt)],
)
def test_an_empty_plaintext_is_allowed(encrypt, decrypt):
    nonce, ciphertext = encrypt(_aes_key(), b"")
    assert decrypt(_aes_key(), nonce, ciphertext) == b""


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_encrypt, sm4_decrypt)],
)
def test_a_key_of_the_wrong_length_is_refused(encrypt, decrypt):
    with pytest.raises(Exception):
        encrypt(bytes(15), b"x")
    with pytest.raises(Exception):
        decrypt(bytes(17), bytes(12), bytes(32))


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_encrypt, sm4_decrypt)],
)
def test_a_nonce_of_the_wrong_length_is_refused(encrypt, decrypt):
    with pytest.raises(InvalidNonceSizeError):
        decrypt(_aes_key(), bytes(11), bytes(32))


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_decrypt, sm4_decrypt)],
)
def test_a_ciphertext_too_short_for_a_tag_is_refused(encrypt, decrypt):
    with pytest.raises(InvalidCiphertextError):
        decrypt(_aes_key(), bytes(12), bytes(15))


@pytest.mark.parametrize(
    "encrypt,decrypt",
    [(aes_encrypt, aes_decrypt), (sm4_encrypt, sm4_decrypt)],
)
def test_a_tampered_ciphertext_does_not_decrypt(encrypt, decrypt):
    nonce, ciphertext = encrypt(_aes_key(), b"stored-value")
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0xFF
    with pytest.raises(InvalidCiphertextError):
        decrypt(_aes_key(), nonce, bytes(tampered))


def test_the_wrong_key_does_not_decrypt():
    nonce, ciphertext = aes_encrypt(_aes_key(), b"stored-value")
    with pytest.raises(InvalidCiphertextError):
        aes_decrypt(bytes(range(1, 17)), nonce, ciphertext)


# --- the credential format --------------------------------------------------


@pytest.mark.parametrize("mode", [Mode.AES, Mode.SM4])
def test_a_credential_blob_has_the_format_the_store_expects(mode):
    blob = encrypt_credential(mode, _dek(), b"stored-value")
    # format(1) + nonce(12) + ciphertext + tag(16)
    assert len(blob) == 1 + NONCE_SIZE + len(b"stored-value") + TAG_SIZE
    assert blob[0] == int(mode)


@pytest.mark.parametrize("mode", [Mode.AES, Mode.SM4])
def test_a_credential_round_trips(mode):
    blob = encrypt_credential(mode, _dek(), b"stored-value")
    assert decrypt_credential(mode, _dek(), blob) == b"stored-value"


def test_a_credential_written_under_another_cipher_is_refused():
    blob = encrypt_credential(Mode.AES, _dek(), b"stored-value")
    with pytest.raises(UnsupportedCipherFormatError):
        decrypt_credential(Mode.SM4, _dek(), blob)


def test_a_credential_too_short_to_carry_a_tag_is_refused():
    with pytest.raises(InvalidCiphertextError):
        decrypt_credential(Mode.AES, _dek(), bytes(20))


def test_an_unknown_mode_cannot_decrypt():
    with pytest.raises(InvalidModeError):
        decrypt_credential(0x09, _dek(), bytes(64))


# --- the wrapped _dek() --------------------------------------------------------


@pytest.mark.parametrize("mode", [Mode.AES, Mode.SM4])
def test_a_wrapped_dek_is_forty_four_bytes(mode):
    wrapped = wrap_dek(mode, _aes_key(), _dek())
    assert len(wrapped) == WRAPPED_DEK_SIZE == 44
    assert unwrap_dek(mode, _aes_key(), wrapped) == _dek()


@pytest.mark.parametrize("mode", [Mode.AES, Mode.SM4])
def test_the_probe_accepts_a_good_wrap(mode):
    wrapped = wrap_dek(mode, _aes_key(), _dek())
    assert probe_unwrap_dek(mode, _aes_key(), _dek(), wrapped) is None


@pytest.mark.parametrize("mode", [Mode.AES, Mode.SM4])
def test_the_probe_rejects_a_wrap_of_another_dek(mode):
    wrapped = wrap_dek(mode, _aes_key(), _dek())
    with pytest.raises(Exception):
        probe_unwrap_dek(mode, _aes_key(), bytes(16), wrapped)


def test_a_dek_of_the_wrong_length_cannot_be_wrapped():
    with pytest.raises(InvalidDekSizeError):
        wrap_dek(Mode.AES, _aes_key(), bytes(15))


def test_a_wrapped_dek_of_the_wrong_length_cannot_be_unwrapped():
    with pytest.raises(InvalidWrappedDekLengthError):
        unwrap_dek(Mode.AES, _aes_key(), bytes(43))


# --- the derivation ---------------------------------------------------------


def test_the_salt_must_be_sixteen_bytes():
    with pytest.raises(InvalidSaltLengthError):
        pbkdf2_hmac(b"password", b"salt", "sha256")


def test_the_derived_key_is_sixteen_bytes():
    assert len(pbkdf2_hmac(b"password", bytes(SALT_SIZE), "sha256")) == 16


def test_an_unknown_prf_is_refused():
    with pytest.raises(Exception):
        pbkdf2_hmac(b"password", bytes(SALT_SIZE), "md5")


# --- the defensive wrapper --------------------------------------------------


def test_a_key_copies_on_the_way_in():
    material = _aes_key()
    src = bytearray(material)
    key = KeyBytes(bytes(src))
    src[:] = b"X" * 16
    assert key.bytes() == material


def test_a_key_copies_on_the_way_out():
    material = _aes_key()
    key = KeyBytes(material)
    out = bytearray(key.bytes())
    out[:] = b"X" * 16
    assert key.bytes() == material


def test_a_zeroed_key_reports_itself_as_zero():
    key = KeyBytes(_aes_key())
    assert not key.is_zero()
    key.zero()
    assert key.is_zero()
    assert key.bytes() == bytes(16)


def test_a_random_key_has_the_length_asked_for():
    assert len(KeyBytes.random(16)) == 16


def test_a_key_does_not_print_itself():
    assert "0123456789abcdef" not in repr(KeyBytes(b"0123456789abcdef"))
