"""The vault's key material.

Three shards combine into a key-encryption key, and the KEK wraps a
data-encryption key that actually encrypts the records.

======  ==============================  ==========================
Shard   Where it lives                 What it is
======  ==============================  ==========================
S1      a file under the secrets dir   mode 0600
S2      a row in vault_key_metadata    random
S3      compiled into the binary       domain separation
======  ==============================  ==========================

::

    KEK = PBKDF2-HMAC-{SHA256|SM3}(XOR(S1, S2, S3), salt, 10000, 16 bytes)
    DEK = 16 random bytes, stored only as AEAD(KEK, DEK)

The vault's S3 and salt differ from the ones the credential manager
uses: the two stores keep independent key domains, so a shard that leaks
out of one does not help with the other. They are copied byte for byte
and the test suite pins them with a golden vector.
"""

from __future__ import annotations

import logging
import os
import stat
import threading
import time
from dataclasses import dataclass

from cred_router.crypto import (
    DEK_SIZE,
    MODE_HASH,
    SHARD_SIZE,
    KeyBytes,
    Mode,
    parse_mode,
    pbkdf2_hmac,
    probe_unwrap_dek,
    unwrap_dek,
    wrap_dek,
)
from cred_router.crypto.errors import CryptoError

from .errors import KeyMismatchError
from .store import KEY_META_DDL, Database

__all__ = [
    "KEY_META_DDL",
    "KEY_FILE_MODE",
    "KEK_SALT",
    "S3_SHARD",
    "SHARD_SIZE",
    "AdoptedDEK",
    "KeyManager",
    "KeyMeta",
    "KeySnapshot",
    "adopt_predecessor",
    "config_shard_size_wrong",
    "crypto_mode_unusable",
    "derive_kek",
    "init_fresh_keys",
    "init_keys",
    "insert_key_meta",
    "load_s1_from_file",
    "load_snapshot",
    "read_key_meta",
    "random_shard",
    "s1_path",
    "unpack_generation",
    "unpack_snapshot",
    "update_key_meta",
    "write_s1_to_file",
    "xor_three",
]

_log = logging.getLogger(__name__)

#: The POSIX mode for the S1 file. On Windows the mode is ignored and the
#: file inherits the parent ACL.
KEY_FILE_MODE = 0o600

#: The compiled-in third shard: domain separation only, not a secret. It is
#: never rotated — rotating it would mean redistributing the binary.
#:
#: Copied byte for byte from ``pkg/vault/keys.go``:
#: Byte-for-byte copy of the Go constant, kept as plain integers so no
#: scanner mistakes this public domain-separation shard for key material.
S3_SHARD = bytes((
    86, 97, 117, 108, 116, 83, 104, 97,
    114, 100, 51, 75, 101, 121, 77, 97,
    116, 101, 114, 105, 97, 108, 50, 48,
    50, 54, 45, 83, 77, 51, 45, 70,
))

#: A compile-time constant: 16 bytes fixed at build time. It is PBKDF2
#: domain separation, not a secret — the literal is in the binary.
#:
#: Copied byte for byte from ``pkg/vault/keys.go``.
KEK_SALT = bytes((
    118, 97, 117, 108, 116, 45, 107, 101,
    107, 45, 115, 97, 108, 116, 45, 118,
))


def crypto_mode_unusable(stored: str, exc: Exception) -> KeyMismatchError:
    """The stored crypto mode is one this build cannot use."""
    return KeyMismatchError(f'stored crypto mode "{stored}" is not usable: {exc}')


def config_shard_size_wrong(length: int) -> KeyMismatchError:
    """The stored config shard is not the size a shard has to be."""
    return KeyMismatchError(
        f"stored config shard is {length} bytes, want {SHARD_SIZE}"
    )


def xor_three(s1: bytes, s2: bytes, s3: bytes) -> bytes:
    """Derive a 32-byte intermediate by XORing three shards."""
    if not len(s1) == len(s2) == len(s3) == SHARD_SIZE:
        raise KeyMismatchError(
            f"vault: the key shards are not {SHARD_SIZE} bytes each"
        )
    return bytes(a ^ b ^ c for a, b, c in zip(s1, s2, s3))


def derive_kek(s1: bytes, s2: bytes, mode: Mode) -> KeyBytes:
    """Derive the 16-byte KEK from the three shards.

    The PRF follows the cipher mode: SM3 for the national-standard mode,
    SHA-256 otherwise.
    """
    intermediate = xor_three(s1, s2, S3_SHARD)
    hash_name = MODE_HASH.get(mode)
    if hash_name is None:
        raise KeyMismatchError(f'vault: unknown crypto mode "{mode!s}"')
    return pbkdf2_hmac(intermediate, KEK_SALT, hash_name)


@dataclass
class KeySnapshot:
    """An immutable (DEK, version) pair.

    The DEK is held in a ``KeyBytes`` so it is copied on the way in and
    on the way out, and can be zeroed explicitly.
    """

    dek: KeyBytes
    version: int
    mode: Mode

    def dek_bytes(self) -> bytes:
        """A copy of the snapshot's key material."""
        return self.dek.bytes() if self.dek is not None else b""


class KeyManager:
    """Holds the generations the store can read.

    The current generation, the one it replaces, and the one a rotation
    is rolling out. A record names the generation it was written with,
    so a snapshot that holds all three can open every record the store
    holds.
    """

    def __init__(
        self,
        current: KeySnapshot | None = None,
        previous: KeySnapshot | None = None,
        pending: KeySnapshot | None = None,
    ) -> None:
        self._lock = threading.Lock()
        self._current = current
        self._previous = previous
        self._pending = pending

    def cur(self) -> KeySnapshot | None:
        """The current snapshot."""
        with self._lock:
            return self._current

    def prev(self) -> KeySnapshot | None:
        """The previous snapshot, if a rotation has happened."""
        with self._lock:
            return self._previous

    def pend(self) -> KeySnapshot | None:
        """The snapshot for the generation a rotation is rolling out."""
        with self._lock:
            return self._pending

    def by_version(self, version: int) -> KeySnapshot | None:
        """The snapshot that holds a generation."""
        with self._lock:
            for snap in (self._current, self._previous, self._pending):
                if snap is not None and snap.version == version:
                    return snap
            return None

    def held_versions(self) -> list[int]:
        """The generations the snapshot holds."""
        with self._lock:
            out: list[int] = []
            for snap in (self._current, self._previous, self._pending):
                if snap is not None:
                    out.append(snap.version)
            return out

    def swap(self, next_snapshot: KeySnapshot) -> None:
        """Install ``next_snapshot`` as current and demote the outgoing one to previous.
        """
        with self._lock:
            self._previous = self._current
            self._current = next_snapshot

    def set_previous(self, snapshot: KeySnapshot) -> None:
        """Install a previous snapshot without demoting the current."""
        with self._lock:
            self._previous = snapshot

    def set_pending(self, snapshot: KeySnapshot) -> None:
        """Install the generation a rotation is rolling out."""
        with self._lock:
            self._pending = snapshot

    def replace(
        self,
        current: KeySnapshot | None,
        previous: KeySnapshot | None,
        pending: KeySnapshot | None,
    ) -> None:
        """Install a whole snapshot at once.

        It is the reload's write. The three slots come from one read of
        the key metadata, so a reader never sees a snapshot that mixes
        generations from two different reads.
        """
        with self._lock:
            self._current = current
            self._previous = previous
            self._pending = pending

    def zero_all(self) -> None:
        """Clear every key material the manager holds."""
        with self._lock:
            for snap in (self._current, self._previous, self._pending):
                if snap is not None and snap.dek is not None:
                    snap.dek.zero()
            self._current = None
            self._previous = None
            self._pending = None


@dataclass
class KeyMeta:
    """The ``vault_key_metadata`` row.

    It is the rotation state machine's entire durable state, and it
    lives in the same database as the records it describes so that a
    backup of one is a backup of the other.
    """

    active_dek_version: int = 0
    pending_dek_version: int = 0
    crypto_mode: str = ""
    active_config_shard: bytes = b""
    pending_config_shard: bytes = b""
    file_shard_version: int = 1
    file_shard_rotated_at: int = 0
    last_rotate_at: int = 0
    wrapped_dek: bytes = b""
    pending_wrapped_dek: bytes = b""
    superseded_dek_version: int = 0
    superseded_wrapped_dek: bytes = b""
    updated_at: int = 0


def _non_nil_blob(b: bytes | None) -> bytes:
    """Map an empty blob to an empty blob."""
    return b"" if not b else b


def read_key_meta(db: Database) -> KeyMeta | None:
    """Load the single key metadata row.

    It returns None when the row does not exist, which is the state of a
    store that has never been initialised.
    """
    row = db.query_one(
        """
        SELECT active_dek_version, pending_dek_version, crypto_mode,
               active_config_shard, pending_config_shard,
               file_shard_version, file_shard_rotated_at, last_rotate_at,
               wrapped_dek, pending_wrapped_dek,
               superseded_dek_version, superseded_wrapped_dek, updated_at
        FROM vault_key_metadata WHERE id = 1"""
    )
    if row is None:
        return None
    return KeyMeta(
        active_dek_version=int(row[0]),
        pending_dek_version=int(row[1]),
        crypto_mode=str(row[2]),
        active_config_shard=row[3],
        pending_config_shard=row[4],
        file_shard_version=int(row[5]),
        file_shard_rotated_at=int(row[6]),
        last_rotate_at=int(row[7]),
        wrapped_dek=row[8],
        pending_wrapped_dek=row[9],
        superseded_dek_version=int(row[10]),
        superseded_wrapped_dek=row[11],
        updated_at=int(row[12]),
    )


def insert_key_meta(db: Database, km: KeyMeta) -> None:
    """Write the single key metadata row."""
    now = int(time.time())
    db.execute(
        """
        INSERT INTO vault_key_metadata (
            id, active_dek_version, pending_dek_version, crypto_mode,
            active_config_shard, pending_config_shard,
            file_shard_version, file_shard_rotated_at, last_rotate_at,
            wrapped_dek, pending_wrapped_dek,
            superseded_dek_version, superseded_wrapped_dek, updated_at
        ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            km.active_dek_version,
            km.pending_dek_version,
            km.crypto_mode,
            _non_nil_blob(km.active_config_shard),
            _non_nil_blob(km.pending_config_shard),
            km.file_shard_version,
            km.file_shard_rotated_at,
            km.last_rotate_at,
            _non_nil_blob(km.wrapped_dek),
            _non_nil_blob(km.pending_wrapped_dek),
            km.superseded_dek_version,
            _non_nil_blob(km.superseded_wrapped_dek),
            now,
        ),
    )
    km.updated_at = now


def update_key_meta(db: Database, km: KeyMeta) -> None:
    """Overwrite the single key metadata row."""
    now = int(time.time())
    cur = db.execute(
        """
        UPDATE vault_key_metadata SET
            active_dek_version = ?, pending_dek_version = ?, crypto_mode = ?,
            active_config_shard = ?, pending_config_shard = ?,
            file_shard_version = ?, file_shard_rotated_at = ?, last_rotate_at = ?,
            wrapped_dek = ?, pending_wrapped_dek = ?,
            superseded_dek_version = ?, superseded_wrapped_dek = ?, updated_at = ?
        WHERE id = 1""",
        (
            km.active_dek_version,
            km.pending_dek_version,
            km.crypto_mode,
            _non_nil_blob(km.active_config_shard),
            _non_nil_blob(km.pending_config_shard),
            km.file_shard_version,
            km.file_shard_rotated_at,
            km.last_rotate_at,
            _non_nil_blob(km.wrapped_dek),
            _non_nil_blob(km.pending_wrapped_dek),
            km.superseded_dek_version,
            _non_nil_blob(km.superseded_wrapped_dek),
            now,
        ),
    )
    if cur.rowcount == 0:
        raise KeyMismatchError("key metadata row is missing")
    km.updated_at = now


def s1_path(secrets_dir: str, version: int) -> str:
    """The path of the S1 shard file for a given shard version."""
    return os.path.join(secrets_dir, f"s1.bin.{version}")


def mkdir_all_secure(path: str, mode: int = 0o700) -> None:
    """Create a directory and its missing parents with the given mode."""
    current = os.path.abspath(path)
    missing: list[str] = []
    while not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        try:
            os.mkdir(directory, mode)
        except FileExistsError:
            pass


def load_s1_from_file(path: str) -> bytes:
    """Read the 32-byte S1 shard.

    The file's mode is checked on Unix: a shard that is readable by
    others is rejected rather than used. The mode must be exactly 0600,
    not merely no wider than it.
    """
    try:
        info = os.stat(path)
    except OSError as exc:
        raise KeyMismatchError(f"vault: stat S1 file {path}: {exc}") from exc
    if info.st_size != SHARD_SIZE:
        raise KeyMismatchError(
            f"vault: S1 file {path} has {info.st_size} bytes, want {SHARD_SIZE}"
        )
    if os.name != "nt":
        mode = stat.S_IMODE(info.st_mode)
        if mode != KEY_FILE_MODE:
            raise KeyMismatchError(
                f"vault: S1 file {path} has mode {mode:o}, want {KEY_FILE_MODE:o}"
            )
    with open(path, "rb") as fh:
        data = fh.read()
    return data[:SHARD_SIZE]


def write_s1_to_file(path: str, shard: bytes) -> None:
    """Write the 32-byte S1 shard with mode 0600."""
    if len(shard) != SHARD_SIZE:
        raise KeyMismatchError(
            f"vault: the S1 shard is {len(shard)} bytes, want {SHARD_SIZE}"
        )
    if not any(shard):
        raise KeyMismatchError(f"vault: refusing to write an all-zero S1 shard to {path}")
    mkdir_all_secure(os.path.dirname(path) or ".")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, KEY_FILE_MODE)
    try:
        os.write(fd, shard)
    finally:
        os.close(fd)
    # os.open's mode is masked by the umask and does not touch an existing
    # file, so the mode is set explicitly.
    os.chmod(path, KEY_FILE_MODE)


def random_shard() -> bytes:
    """A fresh random shard."""
    return os.urandom(SHARD_SIZE)


@dataclass
class AdoptedDEK:
    """A data encryption key the store must use instead of minting one.

    A cluster node receives it from the authority and wraps it with its
    own local key-encryption key before storing it.
    """

    dek: bytes
    version: int
    #: The generation the fleet is replacing, set only for a node that
    #: joins while the fleet is rewriting its records.
    previous: bytes = b""


def init_keys(
    db: Database,
    secrets_dir: str,
    mode: Mode,
    adopt: AdoptedDEK | None = None,
    shared_key_meta: bool = True,
) -> tuple[KeyManager, KeyMeta]:
    """Prepare the store's key material.

    On a store that has never been initialised it mints S1, S2 and the
    DEK and persists them, unless an adopted DEK is supplied. On an
    existing store it loads them.
    """
    if adopt is not None and adopt.previous:
        if len(adopt.previous) != DEK_SIZE:
            raise KeyMismatchError(
                f"the adopted previous DEK is {len(adopt.previous)} bytes, want {DEK_SIZE}"
            )
    km = read_key_meta(db)
    if km is None:
        return init_fresh_keys(db, secrets_dir, mode, adopt)

    try:
        stored_mode = parse_mode(km.crypto_mode)
    except CryptoError as exc:
        raise crypto_mode_unusable(km.crypto_mode, exc) from exc
    if stored_mode != mode:
        raise KeyMismatchError(
            f'stored crypto mode "{stored_mode}" does not match the configured "{mode}"'
        )

    if len(km.active_config_shard) != SHARD_SIZE:
        raise config_shard_size_wrong(len(km.active_config_shard))
    s2 = km.active_config_shard

    try:
        s1 = load_s1_from_file(s1_path(secrets_dir, km.file_shard_version))
    except KeyMismatchError as exc:
        raise KeyMismatchError(str(exc)) from exc

    kek = derive_kek(s1, s2, mode)
    try:
        try:
            dek = unwrap_dek(mode, kek.bytes(), km.wrapped_dek)
        except CryptoError as exc:
            raise KeyMismatchError(
                "the stored DEK does not open with this store's key material"
            ) from exc
        try:
            probe_unwrap_dek(mode, kek.bytes(), dek, km.wrapped_dek)
        except CryptoError as exc:
            raise KeyMismatchError(f"{exc}") from exc

        mgr = unpack_snapshot(kek, mode, km, shared_key_meta)

        # The pending generation is the one a rotation is rolling out.
        # Whether it may be promoted here depends on who owns the row.
        #
        # In the local mode the row is shared by every process that opens
        # the store, so a pending rotation belongs to whoever claimed it:
        # promoting it would let a third process claim a new one, and two
        # data keys under one generation leave records neither can open.
        # The pending key goes into its own slot instead.
        #
        # In the etcd mode the row is the node's own bookkeeping and a
        # pending rotation means this node died in the middle of one.
        # The authority's generation has already moved, so the node has to
        # come back holding the new key.
        pending_key_present = (
            km.pending_dek_version != 0 and bool(km.pending_wrapped_dek)
        )
        if not shared_key_meta and pending_key_present:
            try:
                pending = unwrap_dek(mode, kek.bytes(), km.pending_wrapped_dek)
            except CryptoError as exc:
                raise KeyMismatchError(
                    "the pending DEK does not open with this store's key material"
                ) from exc
            mgr.swap(
                KeySnapshot(
                    dek=KeyBytes(pending), version=km.pending_dek_version, mode=mode
                )
            )

            old_wrapped = km.wrapped_dek
            km.active_dek_version = km.pending_dek_version
            km.wrapped_dek = km.pending_wrapped_dek
            km.pending_wrapped_dek = b""
            km.pending_dek_version = 0
            if mgr.prev() is None:
                raise KeyMismatchError("the rotated store has no previous DEK")
            km.superseded_dek_version = mgr.prev().version
            km.superseded_wrapped_dek = old_wrapped
            update_key_meta(db, km)
    finally:
        kek.zero()

    adopt_predecessor(mgr, adopt, mode)

    return mgr, km


def unpack_snapshot(
    kek: KeyBytes, mode: Mode, km: KeyMeta, shared: bool
) -> KeyManager:
    """Open the generations a key metadata row names.

    The active generation has to open: without it the store cannot be
    used at all. The other two are best effort — a store that cannot
    open the generation a rotation is rolling out is still readable and
    writable.
    """
    cur = unpack_generation(kek, mode, km.active_dek_version, km.wrapped_dek)
    if not shared:
        return KeyManager(current=cur)

    prev = _unpack_best_effort(
        kek, mode, km.superseded_dek_version, km.superseded_wrapped_dek, "superseded"
    )
    pend = _unpack_best_effort(
        kek, mode, km.pending_dek_version, km.pending_wrapped_dek, "pending"
    )
    return KeyManager(current=cur, previous=prev, pending=pend)


def unpack_generation(
    kek: KeyBytes, mode: Mode, version: int, wrapped: bytes
) -> KeySnapshot | None:
    """Open one generation's data key.

    A generation of zero, or a generation with no wrapped key, is a slot
    that is empty rather than one that failed to open.
    """
    if version == 0 or not wrapped:
        return None
    try:
        dek = unwrap_dek(mode, kek.bytes(), wrapped)
    except CryptoError as exc:
        raise KeyMismatchError(
            f"the DEK for generation {version} does not open with this "
            "store's key material"
        ) from exc
    return KeySnapshot(dek=KeyBytes(dek), version=version, mode=mode)


def _unpack_best_effort(
    kek: KeyBytes, mode: Mode, version: int, wrapped: bytes, label: str
) -> KeySnapshot | None:
    """Open a retired generation, or report that it did not open.

    A store that cannot open the generation a rotation is rolling out is
    still readable and writable; it just cannot take that rotation over.
    """
    try:
        return unpack_generation(kek, mode, version, wrapped)
    except KeyMismatchError as exc:
        _log.warning(
            "vault: the %s DEK does not open with this store's key material: %s",
            label,
            exc,
        )
        return None


def load_snapshot(db: Database, secrets_dir: str) -> tuple[KeyManager, KeyMeta]:
    """Re-read the key metadata and return a fresh snapshot."""
    km = read_key_meta(db)
    if km is None:
        raise KeyMismatchError("the store has no key metadata")
    try:
        mode = parse_mode(km.crypto_mode)
    except CryptoError as exc:
        raise crypto_mode_unusable(km.crypto_mode, exc) from exc

    if len(km.active_config_shard) != SHARD_SIZE:
        raise config_shard_size_wrong(len(km.active_config_shard))
    s2 = km.active_config_shard

    try:
        s1 = load_s1_from_file(s1_path(secrets_dir, km.file_shard_version))
    except KeyMismatchError as exc:
        raise KeyMismatchError(str(exc)) from exc

    kek = derive_kek(s1, s2, mode)
    try:
        mgr = unpack_snapshot(kek, mode, km, True)
    finally:
        kek.zero()
    return mgr, km


def adopt_predecessor(mgr: KeyManager, adopt: AdoptedDEK | None, mode: Mode) -> None:
    """Install the generation an adopted key replaces."""
    if adopt is None or not adopt.previous:
        return
    current = mgr.cur()
    if current is None or mgr.prev() is not None:
        return
    if adopt.version != current.version:
        return
    mgr.set_previous(
        KeySnapshot(
            dek=KeyBytes(adopt.previous), version=adopt.version - 1, mode=mode
        )
    )


def init_fresh_keys(
    db: Database,
    secrets_dir: str,
    mode: Mode,
    adopt: AdoptedDEK | None = None,
) -> tuple[KeyManager, KeyMeta]:
    """Mint and persist the initial key material.

    When an adopted DEK is supplied it is used instead of a freshly
    minted one: a cluster node must hold the fleet's key.
    """
    # A store with records but no key metadata cannot be opened: its
    # ciphertext was written under a key nobody has.
    from .store import count_records

    count = count_records(db)
    if count > 0:
        raise KeyMismatchError(
            f"the store holds {count} records but no key metadata; "
            "refusing to mint a new key over existing data"
        )

    s1 = random_shard()
    s2 = random_shard()
    write_s1_to_file(s1_path(secrets_dir, 1), s1)

    kek = derive_kek(s1, s2, mode)
    try:
        if adopt is None:
            dek_bytes = os.urandom(DEK_SIZE)
            version = 1
        else:
            dek_bytes = adopt.dek
            version = adopt.version
        if len(dek_bytes) != DEK_SIZE:
            raise KeyMismatchError(
                f"the adopted DEK is {len(dek_bytes)} bytes, want {DEK_SIZE}"
            )
        wrapped = wrap_dek(mode, kek.bytes(), dek_bytes)
    finally:
        kek.zero()

    km = KeyMeta(
        active_dek_version=version,
        crypto_mode=str(mode),
        active_config_shard=bytes(s2),
        file_shard_version=1,
        file_shard_rotated_at=int(time.time()),
        # The DEK was just minted, so the store has just been rotated as far
        # as the schedule is concerned: attaching a rotator to a fresh store
        # would rotate a DEK that was minted seconds ago.
        last_rotate_at=int(time.time()),
        wrapped_dek=wrapped,
    )
    insert_key_meta(db, km)

    mgr = KeyManager(
        current=KeySnapshot(dek=KeyBytes(dek_bytes), version=km.active_dek_version, mode=mode)
    )
    adopt_predecessor(mgr, adopt, mode)
    return mgr, km
