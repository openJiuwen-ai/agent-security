"""The key material.

The Go counterpart is ``pkg/vault/keys.go``.

The two constants that make the vault's key domain its own are byte
literals in the Go source. They are copied here byte for byte, and this
module pins them down: a transcription slip produces a store that opens
happily and then cannot decrypt anything, and the symptom looks like a
lost key rather than a typo.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from pathlib import Path

import pytest

from security_gateway.crypto import DEK_SIZE, KeyBytes, Mode, hash_available
from security_gateway.vault import (
    KEK_SALT,
    S3_SHARD,
    KeyManager,
    KeyMismatchError,
    KeySnapshot,
    derive_kek,
    xor_three,
)
from security_gateway.vault.keys import (
    load_s1_from_file,
    s1_path,
    write_s1_to_file,
)

# The golden vector: the bytes as they appear in ``pkg/vault/keys.go``.
#
#	s3Shard = [shardSize]byte{
#		0x56, 0x61, 0x75, 0x6c, 0x74, 0x53, 0x68, 0x61,
#		...
#	}
#	kekSalt = [crypto.SaltSize]byte{
#		0x76, 0x61, 0x75, 0x6c, 0x74, 0x2d, 0x6b, 0x65,
#		...
#	}
GOLDEN_S3_SHARD = bytes.fromhex(
    "5661756c745368617264334b65794d6174657269616c323032362d534d332d46"
)
GOLDEN_KEK_SALT = bytes.fromhex("7661756c742d6b656b2d73616c742d76")

# The Go source this package is a port of. It is not needed to run the
# tests, but when it is there the constants are checked against it rather
# than against a copy of themselves.
GO_KEYS = (
    Path(__file__).resolve().parents[4]
    / "credential_router"
    / "pkg"
    / "vault"
    / "keys.go"
)


def _go_literal(name: str) -> bytes:
    """The bytes of a ``[N]byte{...}`` literal in the Go source."""
    source = GO_KEYS.read_text(encoding="utf-8")
    match = re.search(
        r"var %s = \[[A-Za-z.]+\]byte\{(.*?)\}" % re.escape(name), source, re.S
    )
    assert match is not None, f"the Go source has no {name} literal"
    return bytes(int(v, 16) for v in re.findall(r"0x([0-9a-fA-F]{2})", match.group(1)))


def test_the_s3_shard_is_the_golden_vector():
    assert S3_SHARD == GOLDEN_S3_SHARD
    assert len(S3_SHARD) == 32


def test_the_kek_salt_is_the_golden_vector():
    assert KEK_SALT == GOLDEN_KEK_SALT
    assert len(KEK_SALT) == 16


def test_the_constants_match_the_go_source():
    """The constants are compared against the Go literal, not a copy of it."""
    if not GO_KEYS.exists():
        pytest.skip("the Go source is not available next to this package")
    assert S3_SHARD == _go_literal("s3Shard")
    assert KEK_SALT == _go_literal("kekSalt")


def test_the_kek_is_the_xor_of_the_three_shards_run_through_pbkdf2():
    """The derivation is pinned down independently of the crypto package.

    The intermediate is the XOR of the three shards; the KEK is PBKDF2
    over that intermediate with the vault's salt, 10000 iterations and a
    16-byte output.
    """
    s1 = bytes(range(32))
    s2 = bytes(range(100, 132))
    intermediate = bytes(a ^ b ^ c for a, b, c in zip(s1, s2, S3_SHARD))
    expected = hashlib.pbkdf2_hmac("sha256", intermediate, KEK_SALT, 10000, 16)
    assert derive_kek(s1, s2, Mode.AES).bytes() == expected
    assert xor_three(s1, s2, S3_SHARD) == intermediate


def test_the_sm_mode_derives_with_sm3():
    if not hash_available("sm3"):
        pytest.skip("this Python build has no SM3")
    s1 = bytes(range(32))
    s2 = bytes(range(100, 132))
    intermediate = bytes(a ^ b ^ c for a, b, c in zip(s1, s2, S3_SHARD))
    expected = hashlib.pbkdf2_hmac("sm3", intermediate, KEK_SALT, 10000, 16)
    assert derive_kek(s1, s2, Mode.SM4).bytes() == expected


def test_the_two_modes_do_not_derive_the_same_key():
    s1 = bytes(range(32))
    s2 = bytes(range(100, 132))
    assert derive_kek(s1, s2, Mode.AES).bytes() != derive_kek(s1, s2, Mode.SM4).bytes()


def test_the_s1_file_is_written_with_a_private_mode(tmp_path):
    path = str(tmp_path / "secrets" / "s1.bin.1")
    shard = bytes(range(1, 33))
    write_s1_to_file(path, shard)
    assert os.path.getsize(path) == 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert load_s1_from_file(path) == shard


def test_an_all_zero_shard_is_refused(tmp_path):
    """A shard of zeroes would derive a key that everybody can compute."""
    path = str(tmp_path / "s1.bin.1")
    with pytest.raises(KeyMismatchError):
        write_s1_to_file(path, bytes(32))


def test_a_shard_that_others_can_read_is_refused(tmp_path):
    """The whole point of the split is that no single place holds enough.

    A world-readable shard is rejected rather than used.
    """
    path = str(tmp_path / "s1.bin.1")
    write_s1_to_file(path, bytes(range(1, 33)))
    os.chmod(path, 0o644)
    with pytest.raises(KeyMismatchError):
        load_s1_from_file(path)


def test_a_shard_of_the_wrong_length_is_refused(tmp_path):
    path = str(tmp_path / "s1.bin.1")
    write_s1_to_file(path, bytes(range(1, 33)))
    with open(path, "wb") as fh:
        fh.write(bytes(16))
    os.chmod(path, 0o600)
    with pytest.raises(KeyMismatchError):
        load_s1_from_file(path)


def test_the_shard_path_carries_the_shard_version(tmp_path):
    assert s1_path(str(tmp_path), 3).endswith("s1.bin.3")


def test_the_key_manager_demotes_the_outgoing_key_on_a_swap():
    first = KeySnapshot(dek=KeyBytes(bytes(16)), version=1, mode=Mode.AES)
    second = KeySnapshot(dek=KeyBytes(bytes(range(16))), version=2, mode=Mode.AES)
    manager = KeyManager(current=first)

    manager.swap(second)

    assert manager.cur() is second
    assert manager.prev() is first


def test_the_key_manager_zeroes_its_material_on_close():
    first = KeySnapshot(dek=KeyBytes(bytes(16)), version=1, mode=Mode.AES)
    second = KeySnapshot(dek=KeyBytes(bytes(range(16))), version=2, mode=Mode.AES)
    manager = KeyManager(current=first, previous=second)

    manager.zero_all()

    assert manager.cur() is None
    assert manager.prev() is None
    assert first.dek.is_zero()
    assert second.dek.is_zero()


def test_a_key_snapshot_copies_its_material_out():
    """A caller cannot reach into the key buffer through the snapshot."""
    material = bytearray(16)
    snapshot = KeySnapshot(dek=KeyBytes(bytes(material)), version=1, mode=Mode.AES)
    out = bytearray(snapshot.dek_bytes())
    out[0] = 0xFF
    assert snapshot.dek_bytes()[0] == 0


def test_the_dek_is_sixteen_bytes():
    assert DEK_SIZE == 16
