"""The credentials table: one row per registered credential.

The Go original is ``internal/credmgr/store/credentials.go``.

Two rules in this file are worth more than the SQL they wrap.

**The server mints the proxy key.** A client never supplies one. The
proxy key is the bearer credential the proxy looks a credential up by,
so a client that could choose it could also collide with — or guess —
somebody else's.  It is therefore ``cr_pk_`` followed by 32 bytes of
randomness in unpadded base64url.

**Every write is guarded by ``row_version``.** The table has no locks a
caller can hold, so an optimistic compare-and-swap on a version column
is what stands between two writers.  The guard is checked against the
version the caller *read*, not the one it hopes is current, which is why
an update that finds no row has to go and look: "the row is gone" and
"the row moved on" are different answers.
"""

from __future__ import annotations

import base64
import secrets
import sqlite3
from dataclasses import dataclass

from .clock import now as _now
from .errors import (
    ConflictError,
    InvalidError,
    NotFoundError,
    StoreError,
    UniquenessConflictError,
    is_uniqueness_constraint_for,
)

__all__ = [
    "Credential",
    "CredentialMethods",
    "generate_proxy_key",
]

#: The prefix every proxy key carries. It makes a leaked key recognisable
#: in a log and in a support ticket.
PROXY_KEY_PREFIX = "cr_pk_"

#: The columns of a credential row, in the order the scanner expects.
CREDENTIAL_COLUMNS = (
    "id, user_id, api_base, key_tag, proxy_key, api_key_cipher, auth_type, "
    "row_version, kek_version, dek_version, created_at, updated_at"
)


@dataclass
class Credential:
    """One row of the credentials table.

    ``api_key_cipher`` is ``None`` only in the sense of "not supplied":
    the column itself is NOT NULL, so a stored row always carries bytes.
    ``None`` is what an update reads as "leave the ciphertext alone".
    """

    id: int = 0
    user_id: str = ""
    api_base: str = ""
    key_tag: str = ""
    proxy_key: str = ""
    api_key_cipher: bytes | None = None
    auth_type: str = ""
    row_version: int = 0
    kek_version: int = 0
    dek_version: int = 0
    created_at: int = 0
    updated_at: int = 0


def generate_proxy_key() -> str:
    """Return a fresh, collision-resistant proxy lookup key."""
    raw = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")
    return PROXY_KEY_PREFIX + raw.rstrip("=")


def _scan_credential(row: tuple) -> Credential:
    """Build a :class:`Credential` from a result row."""
    return Credential(
        id=int(row[0]),
        user_id=str(row[1]),
        api_base=str(row[2]),
        key_tag=str(row[3]),
        proxy_key=str(row[4]),
        api_key_cipher=bytes(row[5]) if row[5] is not None else b"",
        auth_type=str(row[6]),
        row_version=int(row[7]),
        kek_version=int(row[8]),
        dek_version=int(row[9]),
        created_at=int(row[10]),
        updated_at=int(row[11]),
    )


class CredentialMethods:
    """The credential CRUD, mixed into :class:`~.store.Store`."""

    def insert_credential(self, credential: Credential) -> Credential:
        """Insert a new credential."""
        if credential is None:
            raise InvalidError("no credential was given")
        now = _now()
        credential.created_at = now
        credential.updated_at = now
        credential.row_version = 1
        if credential.kek_version == 0:
            credential.kek_version = 1
        if credential.dek_version == 0:
            credential.dek_version = 1
        if not credential.proxy_key:
            credential.proxy_key = generate_proxy_key()

        with self.admin_db() as conn:  # type: ignore[attr-defined]
            try:
                cur = conn.execute(
                    """
                    INSERT INTO credentials
                        (user_id, api_base, key_tag, proxy_key, api_key_cipher,
                         auth_type, row_version, kek_version, dek_version,
                         created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        credential.user_id,
                        credential.api_base,
                        credential.key_tag,
                        credential.proxy_key,
                        credential.api_key_cipher,
                        credential.auth_type,
                        credential.row_version,
                        credential.kek_version,
                        credential.dek_version,
                        credential.created_at,
                        credential.updated_at,
                    ),
                )
            except sqlite3.IntegrityError as exc:
                if is_uniqueness_constraint_for(exc, "proxy_key"):
                    # A collision on the generated key: transient and
                    # self-healing, because the next insert mints a new
                    # key.  Still a conflict, not a hard error.
                    raise UniquenessConflictError("proxy_key collision", column="proxy_key", cause=exc) from exc
                if is_uniqueness_constraint_for(exc, "user_id"):
                    raise UniquenessConflictError(
                        f"user_id={credential.user_id!r} "
                        f"api_base={credential.api_base!r} "
                        f"key_tag={credential.key_tag!r} already registered",
                        column="user_id",
                        cause=exc,
                    ) from exc
                if "UNIQUE constraint failed" in str(exc):
                    raise ConflictError(f"the credential violates a uniqueness constraint: {exc}", cause=exc) from exc
                raise InvalidError(f"the credential does not satisfy the schema: {exc}", cause=exc) from exc
            except sqlite3.Error as exc:
                raise StoreError(f"insert credential: {exc}", cause=exc) from exc
            except UnicodeEncodeError as exc:
                # A TEXT column holds Unicode; bytes that are not valid
                # UTF-8 cannot be stored, and storing them as something
                # else would change what the column means.
                raise InvalidError(f"the credential holds text that cannot be stored: {exc}", cause=exc) from exc
            credential.id = int(cur.lastrowid or 0)
        return credential

    def get_credential_by_user_url_tag(self, user_id: str, api_base: str, key_tag: str) -> Credential:
        """Return the credential matching the unique key.

        Raises :class:`~.errors.NotFoundError` when there is no such
        row.
        """
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                f"SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE user_id = ? AND api_base = ? AND key_tag = ?",
                (user_id, api_base, key_tag),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"user_id={user_id!r} api_base={api_base!r} key_tag={key_tag!r}")
        return _scan_credential(row)

    def get_credential_by_proxy_key(self, proxy_key: str) -> Credential:
        """Return the credential matching the proxy lookup key.

        Raises :class:`~.errors.NotFoundError` when there is no such
        row.
        """
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                f"SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE proxy_key = ?",
                (proxy_key,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"proxy_key={proxy_key!r}")
        return _scan_credential(row)

    def get_credential_by_id(self, cred_id: int) -> Credential:
        """Return a credential by its primary key.

        Raises :class:`~.errors.NotFoundError` when there is no such
        row.
        """
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                f"SELECT {CREDENTIAL_COLUMNS} FROM credentials WHERE id = ?",
                (cred_id,),
            ).fetchone()
        if row is None:
            raise NotFoundError(f"id={cred_id}")
        return _scan_credential(row)

    def list_credentials(self, limit: int = 0, offset: int = 0) -> list[Credential]:
        """Return the credentials, ordered by id.

        A limit of zero means "all of them"; a negative limit or offset
        is a caller bug and is refused rather than silently corrected.
        """
        if limit < 0:
            raise InvalidError(f"limit must be >= 0, got {limit}")
        if offset < 0:
            raise InvalidError(f"offset must be >= 0, got {offset}")
        query = f"SELECT {CREDENTIAL_COLUMNS} FROM credentials ORDER BY id"
        args: tuple[object, ...] = ()
        if limit > 0:
            query += " LIMIT ?"
            args = (limit,)
            if offset > 0:
                query += " OFFSET ?"
                args = (limit, offset)
        elif offset > 0:
            query += " LIMIT -1 OFFSET ?"
            args = (offset,)
        with self.proxy_db() as conn:  # type: ignore[attr-defined]
            rows = conn.execute(query, args).fetchall()
        return [_scan_credential(row) for row in rows]

    def update_credential(self, cred_id: int, c: Credential) -> Credential:
        """Update the ciphertext and/or the auth type of a credential.

        ``row_version`` is the optimistic guard: it must equal the
        version the caller read. A mismatch is a conflict, an absent row
        a not-found.
        """
        if c is None:
            raise InvalidError("no credential was given")
        if c.kek_version == 0:
            c.kek_version = 1
        if c.dek_version == 0:
            c.dek_version = 1
        now = _now()
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            cur = conn.execute(
                """
                UPDATE credentials
                 SET api_key_cipher=COALESCE(?, api_key_cipher),
                     auth_type=COALESCE(NULLIF(?, ''), auth_type),
                     kek_version=?,
                     dek_version=?,
                     row_version=row_version+1,
                     updated_at=?
                 WHERE id=? AND row_version=?
                """,
                (
                    c.api_key_cipher,
                    c.auth_type,
                    c.kek_version,
                    c.dek_version,
                    now,
                    cred_id,
                    c.row_version,
                ),
            )
            if cur.rowcount == 0:
                # Either the row is gone or its version moved on.
                row = conn.execute(
                    "SELECT row_version FROM credentials WHERE id = ?",
                    (cred_id,),
                ).fetchone()
                if row is None:
                    raise NotFoundError(f"id={cred_id}")
                raise ConflictError(f"id={cred_id} expected row_version={c.row_version} got={int(row[0])}")
            c.row_version += 1
            c.updated_at = now
            c.id = cred_id
        return c

    def delete_credential(self, cred_id: int, expected_row_version: int) -> None:
        """Delete a credential, guarded by its expected row version.

        A version that does not match is a conflict — somebody else
        wrote to the row, or the row is gone — and the delete is
        refused.
        """
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            cur = conn.execute(
                "DELETE FROM credentials WHERE id = ? AND row_version = ?",
                (cred_id, expected_row_version),
            )
            if cur.rowcount == 0:
                raise ConflictError(f"id={cred_id}")

    def count_stragglers_by_dek_version(self, target_dek: int) -> int:
        """Count the rows still below ``target_dek``."""
        with self.admin_db() as conn:  # type: ignore[attr-defined]
            row = conn.execute(
                "SELECT COUNT(*) FROM credentials WHERE dek_version < ?",
                (target_dek,),
            ).fetchone()
        return int(row[0]) if row else 0
