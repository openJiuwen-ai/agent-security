"""The process-level single-instance guard.

An exclusive lock on a lock file, plus a ``<pid>:<unix-seconds>``
pidfile that lets a later start reap a stale lock left by a dead
previous process.

The lock primitive is ``fcntl.flock`` on Unix; Windows is not a
supported deployment and says so.
"""

from __future__ import annotations

import errno
import os
import time
from pathlib import Path
from typing import IO

try:  # pragma: no cover - exercised by the platform, not by the tests
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

#: The mode the lock file is created with.
LOCK_FILE_MODE = 0o600

#: The mode the pidfile is created with. 0644 is intentional: the
#: stale-PID reaping path reads it back on a later start.
PID_FILE_MODE = 0o644


class SingleInstanceError(Exception):
    """Another instance holds the lock."""


def _try_lock(f: IO[bytes]) -> bool:
    """Take an exclusive, non-blocking lock."""
    if fcntl is None:
        raise SingleInstanceError(
            "the single-instance lock needs fcntl, which this platform "
            "does not provide"
        )
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            return False
        raise


def _unlock(f: IO[bytes]) -> None:
    if fcntl is None:
        return
    try:
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    except OSError:
        pass


def _process_alive(pid: int) -> bool:
    """Report whether a process with that pid exists."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # It exists; it simply belongs to somebody else.
        return True
    except OSError:
        return False
    return True


def acquire_single_instance_lock(lock_file: IO[bytes]) -> None:
    """Take an exclusive lock on an open lock file.

    If the lock is contended, check whether the previous holder left a
    stale pidfile and, if that process is gone, reap the lock and retry
    once.
    """
    if _try_lock(lock_file):
        return

    data_dir = Path(lock_file.name).parent
    pid_path = data_dir / "router.pid"
    try:
        raw = pid_path.read_text()
    except OSError:
        raw = ""
    if raw:
        head = raw.strip().split(":", 1)[0]
        try:
            pid = int(head)
        except ValueError:
            pid = -1
        if pid > 0 and not _process_alive(pid):
            # The previous holder is gone. Its lock is stale.
            _unlock(lock_file)
            if _try_lock(lock_file):
                return

    raise SingleInstanceError("another instance is running (lock held)")


def write_pid_file(path: str | os.PathLike[str], pid: int | None = None) -> None:
    """Write the ``<pid>:<unix-seconds>`` pidfile."""
    if pid is None:
        pid = os.getpid()
    line = f"{pid}:{int(time.time())}\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(line)
    try:
        os.chmod(path, PID_FILE_MODE)
    except OSError:
        pass


def open_lock_file(path: str | os.PathLike[str]) -> IO[bytes]:
    """Open (creating if needed) the lock file with the right mode."""
    fd = os.open(path, os.O_RDWR | os.O_CREAT, LOCK_FILE_MODE)
    os.close(fd)
    try:
        os.chmod(path, LOCK_FILE_MODE)
    except OSError:
        pass
    # Opened by path rather than by descriptor so that the file object
    # keeps the path in its name; the guard reads it back to find the
    # pidfile next to it.
    return open(path, "r+b")

