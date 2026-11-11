"""The helper of the cross-process vault test.

The Go counterpart is ``pkg/vault/multiprocess_test.go``: it re-executes the
test binary with a role in the environment.  This one is a plain script that
is started with a role and a directory in ``argv``, because a Python test is
not a binary that can re-execute itself with a flag.

It holds the pieces the test and its children both need: opening a store on
a directory, minting a wrapped DEK, claiming a pending rotation, and building
a record of the test schema's shape.

The module is importable — the test imports it by path — and it is also
runnable as a script.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

#: The environment variable that tells the child where the store lives.
DIR_ENV = "CRED_ROUTER_VAULT_MULTIPROCESS_DIR"

#: The environment variable that tells the child what to do.
ROLE_ENV = "CRED_ROUTER_VAULT_MULTIPROCESS_ROLE"

#: The roles.
ROLE_CLAIM = "claim"
ROLE_WRITE = "write"
ROLE_OPEN = "open"

#: The marker files the parent and the children coordinate through.
CLAIMED_FILE = "claimed"
PROCEED_FILE = "proceed"
GO_FILE = "go"


def test_schema():
    """The schema the Go tests use.

    One plaintext field and one encrypted one — the same shape as
    ``tests/unit/vault/conftest.py``'s ``make_test_schema``.
    """
    from security_gateway.vault.schema import FieldDef, Schema, Type

    return Schema(
        version=1,
        fields=[
            FieldDef(name="endpoint", type=Type.STRING),
            FieldDef(name="api_key", type=Type.STRING, encrypted=True),
        ],
    )


def open_store(directory: str):
    """Open a store on a directory."""
    from security_gateway.vault.vault import Config, Vault

    return Vault.open(
        Config(data_dir=directory, multi_process=True),
        test_schema(),
        _allow_duplicate=True,
    )


def multi_process_record(record_id: str, endpoint: str, secret: str):
    """Build a record of the shape the test schema declares."""
    from security_gateway.vault.record import Record, Value

    return Record(
        id=record_id,
        fields={
            "endpoint": Value.new_string(endpoint),
            "api_key": Value.new_string(secret),
        },
    )


def key_meta(vault):
    """The key metadata row of a store."""
    from security_gateway.vault.keys import read_key_meta

    km = read_key_meta(vault.db)
    if km is None:
        raise AssertionError("the store has no key metadata")
    return km


def mint_wrapped_dek(vault) -> bytes:
    """Mint a data key and wrap it the way the store does.

    It does not claim anything: it is the test's stand-in for the half of a
    rotation that happens before the claim lands.
    """
    from security_gateway.crypto import DEK_SIZE, KeyBytes, parse_mode, wrap_dek
    from security_gateway.vault.keys import derive_kek, load_s1_from_file, s1_path

    km = key_meta(vault)
    mode = parse_mode(km.crypto_mode)
    s1 = load_s1_from_file(s1_path(vault.secrets_dir, km.file_shard_version))
    kek = derive_kek(s1, km.active_config_shard, mode)
    try:
        dek = KeyBytes.random(DEK_SIZE)
        wrapped = wrap_dek(mode, kek.bytes(), dek.bytes())
    finally:
        kek.zero()
    return wrapped


def claim_pending(vault) -> int:
    """Claim a pending rotation the way the rotator does.

    It sets ``pending_dek_version`` to the next generation and stores the
    wrapped DEK for it, guarded by "pending_dek_version = 0".  It leaves the
    store in the state a rotator is in between claiming a rotation and
    committing it, which is the state another process has to cope with.

    It returns the claimed generation.
    """
    km = key_meta(vault)
    wrapped = mint_wrapped_dek(vault)
    target = km.active_dek_version + 1
    cur = vault.db.execute(
        """
        UPDATE vault_key_metadata
           SET pending_dek_version = ?, pending_wrapped_dek = ?, updated_at = ?
         WHERE id = 1 AND pending_dek_version = 0""",
        (target, wrapped, int(time.time())),
    )
    if cur.rowcount != 1:
        raise AssertionError(f"the pending claim touched {cur.rowcount} rows, want 1")
    return target


def wait_for_file(path: Path, timeout: float = 30.0) -> None:
    """Wait for a file to appear.

    It is how the children coordinate: the marker file is the whole
    protocol, and it works across processes because they share the
    directory.
    """
    deadline = time.monotonic() + timeout
    while True:
        if path.exists():
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"the marker {path} never appeared")
        time.sleep(0.01)


def main(argv: list[str]) -> int:
    """Run the helper in one of its two roles."""
    role = os.environ.get(ROLE_ENV, "")
    directory = os.environ.get(DIR_ENV, "")
    if not role or not directory:
        sys.stderr.write(f"usage: {argv[0]} (needs {ROLE_ENV} and {DIR_ENV})\n")
        return 2

    if role == ROLE_CLAIM:
        # Claim a pending rotation the way the rotator does, then say so,
        # then wait: the write has to land while the rotation is in flight.
        vault = open_store(directory)
        try:
            claim_pending(vault)
            (Path(directory) / CLAIMED_FILE).write_text("1")
            wait_for_file(Path(directory) / PROCEED_FILE)
        finally:
            vault.close()
        return 0

    if role == ROLE_WRITE:
        # Write a record while the rotation is in flight. It must be
        # stamped with the pending generation, and it must be readable
        # afterwards — the key for that generation is in the store, and
        # this process has to find it.
        wait_for_file(Path(directory) / CLAIMED_FILE)
        vault = open_store(directory)
        try:
            vault.put(
                multi_process_record(
                    "cross-process", "https://x.example.com", "secret-x"
                )
            )
        finally:
            vault.close()
        return 0

    if role == ROLE_OPEN:
        # Open together with the other children on a brand-new directory.
        # The initialization lock has to make exactly one of them mint the
        # key; the rest load what it wrote.
        wait_for_file(Path(directory) / GO_FILE)
        vault = open_store(directory)
        vault.close()
        return 0

    sys.stderr.write(f"unknown helper role {role!r}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
