"""The errors the vault raises.

Catch the base class to mean "any vault failure", or a specific
subclass to mean "this particular failure". The distinction between the
types is load-bearing: the vaultsvc layer maps them onto wire error
codes, so a caller can tell "absent" from "present but unreadable" by
the type alone, never by matching on the message.
"""

from __future__ import annotations


class VaultError(Exception):
    """The base of every error this package raises.

    Each subclass carries a ``code`` naming it on the wire and a
    ``default`` sentinel text. A detail is composed as ``"<sentinel>:
    <detail>"`` unless it is already a whole message: one starting with
    ``"vault: "``, or one passed with ``whole=True``.
    """

    code = "vault_error"
    default = ""

    def __init__(self, detail: str | None = None, *, whole: bool = False) -> None:
        if detail is None:
            super().__init__(self.default or self.__class__.__name__)
        elif whole:
            super().__init__(detail)
        elif self.default and not detail.startswith("vault: "):
            super().__init__(f"{self.default}: {detail}")
        else:
            super().__init__(detail)


class NotFoundError(VaultError):
    """No record with the requested id exists.

    It does *not* mean the record could not be opened — see
    :class:`UndecryptableError`.
    """

    code = "not_found"
    default = "vault: record not found"


class InvalidError(VaultError):
    """The request, the schema or the stored bytes are not valid.

    The base of the two "you built it wrong" errors below; a caller that
    does not care which one it is can catch this.
    """

    code = "invalid"


class InvalidSchemaError(InvalidError):
    """A schema that fails validation.

    Raised for a schema with a non-positive version, no fields, a field
    name outside the permitted subset, a duplicate name or an unknown
    type.
    """

    code = "invalid"
    default = "vault: invalid schema"


class InvalidRecordError(InvalidError):
    """A record that does not conform to the schema.

    Also raised for stored bytes that are not a well-formed container: a
    value that cannot be decoded is not something a caller can act on
    differently from a value that was written wrong.
    """

    code = "invalid"
    default = "vault: invalid record"


class ConflictError(VaultError):
    """A write that collides with existing state.

    The vault's own writes are last-write-wins, so this is rare; it
    exists because a write that changes nothing is a bug in the caller,
    not a silent no-op.
    """

    code = "conflict"
    default = "vault: conflict"


class SchemaMismatchError(VaultError):
    """The schema does not match the one the store was initialised with.

    The store refuses to open in this state rather than reading data it
    cannot interpret.
    """

    code = "schema_mismatch"
    default = "vault: schema mismatch"


class UndecryptableError(VaultError):
    """A record exists but no key this store holds can open it.

    Deliberately not :class:`NotFoundError`: the two are different
    facts, and treating them alike lets a caller cache a negative answer
    for a live secret.
    """

    code = "undecryptable"
    default = "vault: record exists but cannot be decrypted"


class StaleGenerationError(VaultError):
    """A record names a generation this store does not hold.

    Distinct from :class:`UndecryptableError`: a stale generation is
    fixed by bringing the store's keys up to date, an undecryptable
    record is damaged data and no reload will help.
    """

    code = "stale_generation"
    default = "vault: record is under a generation this store does not hold"


class KeyMismatchError(VaultError):
    """The key material does not match this store.

    Distinct from data corruption: correcting the key material makes the
    store readable again, while corrupted data does not.
    """

    code = "key_mismatch"
    default = "vault: key material does not match this store"


class StoreNotReadyError(VaultError):
    """The store has not been initialised by the host leader yet."""

    code = "not_ready"
    default = "vault: store is not ready"


class RotationInProgressError(VaultError):
    """A key rotation is already running."""

    code = "rotation_in_progress"
    default = "vault: rotation already in progress"


class ClosedError(VaultError):
    """The store was closed."""

    code = "closed"
    default = "vault: closed"


class UnsupportedError(VaultError):
    """An operation that does not apply to this store.

    The local mode's takeover, for instance, is meaningless for a store
    whose authority owns the pending generation.
    """

    code = "unsupported"
    default = "vault: operation not supported by this store"


__all__ = [
    "ClosedError",
    "ConflictError",
    "InvalidError",
    "InvalidRecordError",
    "InvalidSchemaError",
    "KeyMismatchError",
    "NotFoundError",
    "RotationInProgressError",
    "SchemaMismatchError",
    "StaleGenerationError",
    "StoreNotReadyError",
    "UndecryptableError",
    "UnsupportedError",
    "VaultError",
]
