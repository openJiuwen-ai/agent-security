"""Batch reads and deletes over a vault.

The vault itself is a single-record API; these helpers batch the SQL
where the backend allows it and keep the per-record error rules in one
place. A missing id is not an error, but a record that cannot be
decrypted still is.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from .errors import InvalidRecordError
from .record import Record
from .store import delete_records
from .vault import Vault

__all__ = ["BatchDeleteResult", "batch_delete", "batch_get"]


@dataclass
class BatchDeleteResult:
    """What a batch delete actually removed, and what was already gone."""

    deleted: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        """Whether every id in the batch existed."""
        return not self.missing


def batch_get(vault: Vault, ids: Sequence[str]) -> dict[str, Record]:
    """Return the records that exist, in input order.

    Missing ids are skipped; duplicate ids are read once. A record that
    cannot be decrypted raises, exactly as :meth:`Vault.get` does.
    """
    unique = list(dict.fromkeys(ids))
    found = vault.get_many(unique)
    return {record_id: found[record_id] for record_id in unique if record_id in found}


def batch_delete(vault: Vault, ids: Sequence[str]) -> BatchDeleteResult:
    """Delete every id once and report what was deleted and what was gone.

    Missing ids are recorded in ``missing`` instead of raising; duplicate
    ids are processed once.
    """
    unique = list(dict.fromkeys(ids))
    for record_id in unique:
        if not record_id:
            raise InvalidRecordError("id is empty")

    result = BatchDeleteResult()
    if vault.authority is None:
        # One DELETE ... IN for the whole batch. The transaction makes the
        # returned id set and the rows actually removed the same event.
        with vault.wmu:
            with vault.db.transaction(immediate=True):
                deleted = delete_records(vault.db, unique)
        result.deleted = [record_id for record_id in unique if record_id in deleted]
        result.missing = [record_id for record_id in unique if record_id not in deleted]
        return result

    # One Txn comparing every record's mod revision: either all rows go
    # or, when one changed underneath us, none do and the caller retries.
    deleted, missing = vault.authority.store.delete_records_cas(unique)
    result.deleted = deleted
    result.missing = missing
    return result
