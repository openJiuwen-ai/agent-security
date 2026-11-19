"""A rotation interrupted at any record must finish after a restart.

The re-encryption pass is intentionally restartable: the pending key is
durable before the first record is touched.  A process that dies halfway
through must leave the store readable and let the next open (or a
takeover) finish the same generation.  This exercises every cut point,
not just "after converge".
"""

from __future__ import annotations

import random
import time

import pytest

from security_gateway.vault import (
    Config,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
    rotate,
)
from security_gateway.vault.errors import VaultError

pytestmark = pytest.mark.slow


def _schema() -> Schema:
    return Schema(
        version=1,
        fields=[
            FieldDef(name="name", type=Type.STRING),
            FieldDef(name="secret", type=Type.STRING, encrypted=True),
        ],
    )


def _record(i: int) -> Record:
    return Record(
        id=f"record-{i}",
        fields={
            "name": Value.new_string(f"name-{i}"),
            "secret": Value.new_string(f"secret-{i}"),
        },
    )


@pytest.mark.parametrize("seed", range(6))
def test_a_rotation_cut_at_any_record_finishes_after_reopen(
    monkeypatch: pytest.MonkeyPatch, tmp_path, seed: int
) -> None:
    directory = tmp_path / f"store-{seed}"
    vault = Vault.open(Config(data_dir=str(directory)), _schema())
    try:
        for i in range(20):
            vault.put(_record(i))

        fail_after = random.Random(seed).randrange(0, 20)
        calls = 0
        original = rotate.update_record_cipher

        def crash_after_a_while(*args, **kwargs):
            nonlocal calls
            calls += 1
            if calls > fail_after:
                raise OSError("the process died while re-encrypting")
            return original(*args, **kwargs)

        monkeypatch.setattr(rotate, "update_record_cipher", crash_after_a_while)
        with pytest.raises((OSError, VaultError)):
            rotate.rotate_dek(vault)
    finally:
        vault.close()

    monkeypatch.setattr(rotate, "update_record_cipher", original)
    reopened = Vault.open(Config(data_dir=str(directory)), _schema())
    try:
        # The failed process left a fresh pending lease.  In a real restart
        # the lease has expired; age it here instead of sleeping.
        with reopened.db.transaction(immediate=True):
            reopened.db.execute(
                "UPDATE vault_key_metadata SET updated_at = ?",
                (int(time.time()) - 3600,),
            )
        rotate.takeover_pending(reopened)
        for i in range(20):
            assert reopened.get(f"record-{i}") == _record(i)
        assert reopened.status().dek_version == 2
    finally:
        reopened.close()


def test_a_future_lease_timestamp_is_not_taken_over(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    """A clock that jumped ahead must not make a live rotation look stale.

    The lease check is deliberately conservative: a timestamp in the
    future means "the writer's clock is ahead of mine", not "the writer
    is dead".  Taking it over while the writer is still alive would let
    two processes rotate the same generation.
    """
    from security_gateway.vault import RotationInProgressError

    directory = tmp_path / "store-future"
    vault = Vault.open(Config(data_dir=str(directory)), _schema())
    try:
        vault.put(_record(0))
        original = rotate.update_record_cipher
        monkeypatch.setattr(
            rotate,
            "update_record_cipher",
            lambda *a, **k: (_ for _ in ()).throw(OSError("crash")),
        )
        with pytest.raises((OSError, VaultError)):
            rotate.rotate_dek(vault)
        monkeypatch.setattr(rotate, "update_record_cipher", original)

        with vault.db.transaction(immediate=True):
            vault.db.execute(
                "UPDATE vault_key_metadata SET updated_at = ?",
                (int(time.time()) + 3600,),
            )
        with pytest.raises(RotationInProgressError):
            rotate.takeover_pending(vault)

        with vault.db.transaction(immediate=True):
            vault.db.execute(
                "UPDATE vault_key_metadata SET updated_at = ?",
                (int(time.time()) - 3600,),
            )
        rotate.takeover_pending(vault)
        assert vault.get("record-0") == _record(0)
        assert vault.status().dek_version == 2
    finally:
        vault.close()
