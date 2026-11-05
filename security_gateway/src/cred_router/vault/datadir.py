"""The store's data directory, and the check that keeps it safe.

Whoever can write in the data directory can replace the database, and
the store would then hand out the secrets that the replacement holds.
The check is here rather than in the vault module because it is about a
directory on disk and not about the store's behaviour.
"""

from __future__ import annotations

import os
import stat

from .errors import InvalidError

__all__ = ["check_data_dir"]


def check_data_dir(data_dir: str) -> None:
    """Refuse a data directory that other users can write to."""
    path = os.path.abspath(data_dir)
    current = path
    while True:
        try:
            info = os.stat(current)
        except OSError as exc:
            raise InvalidError(f"vault: look at the data directory {current!r}: {exc}") from exc
        if not stat.S_ISDIR(info.st_mode):
            raise InvalidError(f"vault: {current!r} is not a directory")
        mode = stat.S_IMODE(info.st_mode)
        sticky = bool(info.st_mode & stat.S_ISVTX)
        if mode & 0o022 != 0 and not sticky:
            raise InvalidError(
                f"vault: the data directory {current!r} is writable by others "
                f"(mode {mode:04o}); anyone who can write there can replace the "
                "database and have the store hand out their own secrets"
            )
        parent = os.path.dirname(current)
        if parent == current:
            return
        current = parent
