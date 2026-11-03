"""Keep sensitive memory from reaching the disk.

A key that lives only in memory can still end up on disk two ways: the
kernel can swap the page out, and a crash can write it into a core dump.
Locking the pages stops the first; forbidding core dumps the second.

The limits are the operating system's: how much may be locked is
``RLIMIT_MEMLOCK``, and the default on many systems is small.  So
everything here is best effort and says what it could not do.

**The unit of locking is a page, not a byte.**  The kernel locks every
page the range touches, so unlocking one key can unpin another key that
happens to sit on the same page.
"""

from __future__ import annotations

import ctypes
import os
import resource
import sys
from typing import Any

__all__ = [
    "MemlockError",
    "core_dump_limit",
    "disable_core_dumps",
    "human_size",
    "lock",
    "lock_all",
    "lock_limit_bytes",
    "locked_bytes",
    "protection_status",
    "report",
    "unlock",
]

#: ``MCL_CURRENT`` — lock the pages already mapped.
MCL_CURRENT = 1

#: ``MCL_FUTURE`` — lock the pages mapped later.
MCL_FUTURE = 2


class MemlockError(Exception):
    """The kernel would not do what was asked.

    It carries the kernel's own error: a limit that is too small reads
    differently from a kernel that has no such facility.
    """


def _libc() -> Any:
    """The C library, with the errno convention the kernel uses."""
    global _libc_handle
    if _libc_handle is None:
        _libc_handle = ctypes.CDLL("libc.so.6", use_errno=True)
        _libc_handle.mlock.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t]
        _libc_handle.mlock.restype = ctypes.c_int
        _libc_handle.munlock.argtypes = [
            ctypes.c_void_p, ctypes.c_size_t]
        _libc_handle.munlock.restype = ctypes.c_int
        _libc_handle.mlockall.argtypes = [ctypes.c_int]
        _libc_handle.mlockall.restype = ctypes.c_int
    return _libc_handle


_libc_handle: Any = None


def _address_of(buf: Any) -> int:
    """The address of a writable buffer's first byte.

    A read-only buffer is refused rather than quietly skipped, and the
    intermediate object is dropped before returning: it holds an export
    on the buffer, and an exported buffer cannot be resized.
    """
    view = ctypes.c_char.from_buffer(buf)
    try:
        return ctypes.addressof(view)
    finally:
        del view


def _errno_text() -> str:
    """The kernel's last error, in words."""
    code = ctypes.get_errno()
    if not code:
        return "no error"
    try:
        return os.strerror(code)
    except (ValueError, OverflowError):  # pragma: no cover - exotic errno
        return f"errno {code}"


def lock(buf: Any) -> None:
    """Pin the pages that hold ``buf``.

    Raises :class:`MemlockError` with the kernel's own error.
    """
    if buf is None or len(buf) == 0:
        return
    if sys.platform != "linux":
        raise MemlockError(
            "memlock: locking memory is not available on this platform")
    libc = _libc()
    if libc.mlock(_address_of(buf), len(buf)) != 0:
        raise MemlockError(f"memlock: mlock: {_errno_text()}")


def unlock(buf: Any) -> None:
    """Release the pages that hold ``buf``.

    Unlocking a range that is not locked is not an error.
    """
    if buf is None or len(buf) == 0:
        return
    if sys.platform != "linux":
        return
    libc = _libc()
    if libc.munlock(_address_of(buf), len(buf)) != 0:
        raise MemlockError(f"memlock: munlock: {_errno_text()}")


def lock_all() -> None:
    """Pin every page of the process, and every page it maps later."""
    if sys.platform != "linux":
        raise MemlockError(
            "memlock: locking memory is not available on this platform")
    libc = _libc()
    flags = MCL_CURRENT
    if _memlock_is_unlimited():
        flags |= MCL_FUTURE
    if libc.mlockall(flags) != 0:
        raise MemlockError(f"memlock: mlockall: {_errno_text()}")


def _memlock_is_unlimited() -> bool:
    """Whether the process may lock as much as it likes."""
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except (ValueError, OSError):
        return False
    return soft == resource.RLIM_INFINITY


def disable_core_dumps() -> None:
    """Stop crashes from writing the process's memory to a file.

    The limit is lowered to zero for both the soft and the hard limit,
    so nothing can raise it again.
    """
    if sys.platform != "linux":
        return
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError) as exc:
        raise MemlockError(f"memlock: setrlimit(RLIMIT_CORE): {exc}") from exc


def core_dump_limit() -> int:
    """The core dump limit the process runs with.

    Zero means no core dump can be written. A negative number means the
    limit is unlimited or cannot be read.
    """
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_CORE)
    except (ValueError, OSError):
        return -1
    if soft == resource.RLIM_INFINITY:
        return -1
    return int(soft)


def protection_status() -> dict[str, Any]:
    """What protection the process has right now."""
    return {
        "core_dump_limit": core_dump_limit(),
        "locked_bytes": locked_bytes(),
        "lock_limit_bytes": lock_limit_bytes(),
    }


def locked_bytes() -> int:
    """How much of the address space the kernel has locked."""
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if not line.startswith("VmLck:"):
                    continue
                fields = line.split()
                if len(fields) < 2:
                    return 0
                try:
                    return int(fields[1]) * 1024
                except ValueError:
                    return 0
    except OSError:
        return 0
    return 0


def lock_limit_bytes() -> int:
    """How much the process may lock."""
    try:
        soft, _hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    except (ValueError, OSError):
        return 0
    if soft == resource.RLIM_INFINITY:
        return 0
    return int(soft)


def human_size(n: int) -> str:
    """Render a byte count for a log line."""
    if n >= 1 << 30:
        return f"{n / (1 << 30):.1f} GiB"
    if n >= 1 << 20:
        return f"{n / (1 << 20):.1f} MiB"
    if n >= 1 << 10:
        return f"{n / (1 << 10):.1f} KiB"
    return f"{n} B"


def report() -> str:
    """Say what the process locked, in one line, for the log."""
    limit = lock_limit_bytes()
    if limit == 0:
        return f"locked {human_size(locked_bytes())}, no limit reported"
    return (f"locked {human_size(locked_bytes())} of "
            f"{human_size(limit)} allowed")
