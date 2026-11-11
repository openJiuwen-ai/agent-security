"""The write barrier and the key snapshot.

The Go counterpart is ``tests/unit/vault/concurrency_test.go`` and
``TestPutDuringRotationKeepsEveryRecordReadable`` in
``tests/unit/vault/vault_test.go``.

The window these tests protect against is a handful of instructions wide,
so it cannot be found by racing two threads and hoping. The write is held
open at exactly the point where a concurrent key rotation would change the
key underneath it, and the rotation is run against it.
"""

from __future__ import annotations

import os
import threading
import time

import pytest
from security_gateway.crypto import DEK_SIZE, KeyBytes, Mode
from security_gateway.vault import (
    NotFoundError,
    Record,
    StaleGenerationError,
    UndecryptableError,
    Value,
    set_put_before_write_hook,
)
from security_gateway.vault.keys import KeySnapshot

from .conftest import call_rotate_dek, put_record


def _new_snapshot(version: int) -> KeySnapshot:
    return KeySnapshot(
        dek=KeyBytes(os.urandom(DEK_SIZE)), version=version, mode=Mode.AES
    )


def test_a_write_across_a_key_swap_does_not_orphan_the_record(vault):
    """What happens when a key rotation lands between a write's encryption
    and the write itself.

    The write has already encrypted its value under the old key by the time
    the rotation swaps in the new one. If the row is then labelled with the
    new generation while its ciphertext is still under the old one, the
    rotation's straggler check will not see it — the row claims to be
    current — and no key will ever be able to open it again.
    """
    entered = threading.Event()
    release = threading.Event()
    failures: list[BaseException] = []

    def hook():
        entered.set()
        if not release.wait(10):
            raise TimeoutError("the test never released the write")

    set_put_before_write_hook(hook)
    try:

        def writer():
            try:
                vault.put(
                    Record(
                        id="cred-1",
                        fields={"api_key": Value.new_string("sk-secret")},
                    )
                )
            except BaseException as exc:  # noqa: BLE001 - reported below
                failures.append(exc)

        put_thread = threading.Thread(target=writer)
        put_thread.start()
        assert entered.wait(10), "the write never reached the hook"

        # The rotation's third step: swap the key. The swap happens outside
        # the write barrier, so it lands while the write is still open.
        vault.keys.swap(_new_snapshot(2))

        # The rotation's fifth step: the final straggler check, under the
        # write barrier. It has to wait for the write to finish, or it
        # would not see the row the write is about to land.
        observed: dict[str, int] = {}

        def checker():
            with vault.wmu:
                observed["stragglers"] = vault.count_stragglers(2)

        check_thread = threading.Thread(target=checker)
        check_thread.start()
        time.sleep(0.05)
        assert "stragglers" not in observed, (
            "the straggler check ran while a write was still open"
        )

        release.set()
        put_thread.join(10)
        check_thread.join(10)
        assert not failures, failures
        assert observed["stragglers"] == 1, (
            "the rotation's straggler check did not see the row the write "
            "landed, so the row would never be re-encrypted"
        )
    finally:
        set_put_before_write_hook(None)
        release.set()


def test_a_record_written_under_the_outgoing_key_is_still_readable(vault):
    """The decryption falls back to the previous key.

    That fallback is what makes an in-flight rotation readable: a record
    that has not been re-encrypted yet is still under the old key.
    """
    vault.put(Record(id="cred-1", fields={"api_key": Value.new_string("sk-secret")}))

    vault.keys.swap(_new_snapshot(2))

    got = vault.get("cred-1")
    assert got.get_string("api_key") == "sk-secret"


def _corrupt_ciphertext(vault, id: str) -> None:
    """Damage a record's ciphertext, leaving its container readable.

    The encrypted field is written last, so the last byte lands inside its
    authentication tag: the container still decodes and the data does not
    open.
    """
    row = vault.db.query_one("SELECT data FROM vault_record WHERE id = ?", (id,))
    assert row is not None
    data = bytearray(row[0])
    data[-1] ^= 0xFF
    vault.db.execute("UPDATE vault_record SET data = ? WHERE id = ?", (bytes(data), id))


def test_a_record_whose_generation_the_store_does_not_hold_is_stale(vault):
    """The store is behind: the record names a generation that is not in the
    key metadata either.

    That is a different fact from a record whose ciphertext is damaged, and
    the two are reported as different errors: the first is fixed by
    bringing the store's keys up to date, the second by restoring the data.
    """
    vault.put(Record(id="cred-1", fields={"api_key": Value.new_string("sk-secret")}))

    # The row names a generation the store has never held — a record from
    # a store that is newer than this one — and no key this store holds
    # opens its ciphertext.
    _corrupt_ciphertext(vault, "cred-1")
    vault.db.execute(
        "UPDATE vault_record SET dek_version = ? WHERE id = ?", (99, "cred-1")
    )

    with pytest.raises(StaleGenerationError) as excinfo:
        vault.get("cred-1")
    assert not isinstance(excinfo.value, NotFoundError)
    assert "cred-1" in str(excinfo.value)


def test_a_record_whose_generation_is_held_but_damaged_is_undecryptable(vault):
    """The generation is the one the store holds, and the ciphertext still
    does not open under it: the data is damaged, and no reload will help.
    """
    vault.put(Record(id="cred-1", fields={"api_key": Value.new_string("sk-secret")}))
    _corrupt_ciphertext(vault, "cred-1")

    with pytest.raises(UndecryptableError) as excinfo:
        vault.get("cred-1")
    assert not isinstance(excinfo.value, NotFoundError)


def test_a_write_during_a_rotation_leaves_every_record_readable(vault):
    """The Go counterpart is ``TestPutDuringRotationKeepsEveryRecordReadable``."""
    for i in range(20):
        put_record(vault, f"seed-{i}")

    stop = threading.Event()
    failures: list[BaseException] = []

    def writer():
        i = 0
        while not stop.is_set():
            id = f"writer-{i % 10}"
            try:
                vault.put(
                    Record(id=id, fields={"api_key": Value.new_string("sk-" + id)})
                )
            except BaseException as exc:  # noqa: BLE001 - reported below
                failures.append(exc)
            i += 1

    thread = threading.Thread(target=writer)
    thread.start()
    try:
        time.sleep(0.02)
        call_rotate_dek(vault)
    finally:
        stop.set()
        thread.join(10)

    for i in range(20):
        got = vault.get(f"seed-{i}")
        # The seeded records carry the helper's value, not the writer
        # thread's: the rotation must leave every one of them readable.
        assert got.get_string("api_key") == f"secret-for-seed-{i}"

    status = vault.status()
    assert status.straggler_count == 0
