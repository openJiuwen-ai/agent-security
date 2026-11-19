"""What was stored, checked against what was declared.

Two things have to agree about a record: the container that was written
into the database, and the schema the host declares in code. The checks
that compare them live here rather than in the vault module because
they are the reconciliation between two things, not the store's own
behaviour.

Two of them are about a schema against another schema — whether the
declared one is newer than the stored one, and whether the change is
one the old code can still read. The third turns a stored row back
into the fields it carries, and names the record it cannot parse.
"""

from __future__ import annotations

from .codec import ContainerField, decode_container
from .errors import InvalidRecordError, SchemaMismatchError
from .schema import FieldDef, Schema
from .store import RecordRow

__all__ = [
    "is_additive",
    "verify_against_schema",
]


def verify_against_schema(
    record_id: str,
    sch: Schema,
    defs: dict[str, FieldDef],
    fields: list[ContainerField],
) -> None:
    """Check a stored record's fields against its schema."""
    for f in fields:
        definition = defs.get(f.name)
        if definition is None:
            raise SchemaMismatchError(
                f'record "{record_id}" has field "{f.name}", which schema v{sch.version} does not declare'
            )
        if f.encrypted != definition.encrypted:
            raise SchemaMismatchError(
                f'record "{record_id}" field "{f.name}" is marked encrypted='
                f'{f.encrypted} but schema v{sch.version} says {definition.encrypted}'
            )
        if f.type != definition.type:
            raise SchemaMismatchError(
                f'record "{record_id}" field "{f.name}" has type {f.type} '
                f'but schema v{sch.version} says {definition.type}'
            )


def is_additive(old: Schema, new: Schema) -> bool:
    """Whether ``new`` can be written by a host that only knows ``old``.

    Every field of ``old`` must still be present in ``new``, unchanged.
    """
    old_fields = old.field_lookup()
    new_fields = new.field_lookup()
    for name, old_field in old_fields.items():
        new_field = new_fields.get(name)
        if new_field is None:
            return False
        if new_field.type != old_field.type or (
            new_field.encrypted != old_field.encrypted
        ):
            return False
    return True


def _decode_row(row: RecordRow) -> list[ContainerField]:
    """The container of a stored row, named if it is damaged."""
    try:
        return decode_container(row.data)
    except InvalidRecordError as exc:
        raise InvalidRecordError(
            f'decode record "{row.id}": {exc}', whole=True
        ) from exc
