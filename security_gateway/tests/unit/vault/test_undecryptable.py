"""An unreadable record is not an absent record.

The Go counterpart is ``tests/unit/credmgr/vault/store_vault_test.go``. That
file exercises the credential manager's own store — a different subsystem
from this package, with its own keystore — but the invariant it pins down
is the one this package has to honour too:

    "an undecryptable credential still reports as ErrCredentialNotFound" —
    which the Go test then shows to be false, and which is why the Go
    credential manager returns a distinct ``UndecryptableError``.

Reporting an unreadable row as "not found" made a credential answer like a
retired one, log nothing, and get cached as a tombstone — so the credential
vanished from use while still showing up in listings.
"""

from __future__ import annotations

import pytest

from security_gateway.crypto import KeyBytes, Mode
from security_gateway.vault import (
    ContainerField,
    NotFoundError,
    Type,
    UndecryptableError,
    encode_container,
)
from security_gateway.vault.keys import KeySnapshot
from security_gateway.vault.store import RecordRow, put_record


def _row_with_garbage_ciphertext(vault, record_id: str) -> None:
    """A row whose encrypted field holds bytes no key can open."""
    encoded = encode_container(
        [
            ContainerField(
                name="endpoint",
                type=Type.STRING,
                encrypted=False,
                data=b"https://api.example.com/v1",
            ),
            ContainerField(
                name="api_key",
                type=Type.STRING,
                encrypted=True,
                data=bytes([0xFF, 0xFE, 0xFD, 0xFC, 0xFB]),
            ),
        ]
    )
    put_record(
        vault.db,
        RecordRow(id=record_id, schema_version=1, data=encoded, dek_version=1),
    )


def test_a_row_that_no_key_can_open_is_not_reported_as_missing(vault):
    _row_with_garbage_ciphertext(vault, "cred-1")

    # A previous snapshot as well, so the dual-snapshot path is exercised:
    # both the current and the previous key have to fail.
    vault.keys.set_previous(
        KeySnapshot(dek=KeyBytes(bytes(16)), version=0, mode=Mode.AES)
    )

    with pytest.raises(UndecryptableError) as excinfo:
        vault.get("cred-1")
    assert not isinstance(excinfo.value, NotFoundError)
    assert "cred-1" in str(excinfo.value)


def test_a_row_that_is_really_absent_is_reported_as_missing(vault):
    """The two answers stay apart."""
    with pytest.raises(NotFoundError):
        vault.get("cred-does-not-exist")
