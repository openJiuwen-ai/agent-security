"""The key material must not be able to reach the disk.

The Go original is the package ``internal/memlock`` and the change
``feat(vault): the keys in this process do not reach the disk``.

A key that lives only in memory can still end up on disk two ways: the
kernel can swap the page out, and a crash can write it into a core
dump.  Either way the key is in a file, where whoever gets that file can
read it later.

These tests pin the mechanism, not the privilege: pinning a page needs
``RLIMIT_MEMLOCK``, and whether the kernel grants it is the
operating system's business.  What is the code's business is that it
**says** what it could not do.
"""

from __future__ import annotations

import subprocess
import sys

import pytest
from security_gateway.crypto.keybytes import KeyBytes
from security_gateway.platform import memlock

#: Whether this platform has the facility at all.
HAS_MLOCK = sys.platform == "linux"


pytestmark = pytest.mark.skipif(
    not HAS_MLOCK,
    reason="locking memory is a Linux facility",
)


# -- the kernel facility --------------------------------------------------


def test_locking_pins_the_pages():
    """A buffer big enough to sit on pages of its own is actually pinned.

    A small one can land on a page that is already locked, and then the
    locked total does not move — which is why the buffer here is a
    megabyte.
    """
    buf = bytearray(1 << 20)
    before = memlock.locked_bytes()

    memlock.lock(buf)
    after = memlock.locked_bytes()

    assert after >= before + (1 << 20), (
        f"the buffer was not pinned: {after} bytes locked, was {before}")

    memlock.unlock(buf)
    now = memlock.locked_bytes()
    assert now <= after, (
        f"the pages stayed locked: {now} bytes, was {after}")


def test_locking_nothing_is_not_an_error():
    """Locking an empty range is what the Go does, and it is not a failure."""
    memlock.lock(bytearray())
    memlock.unlock(bytearray())
    memlock.lock(None)
    memlock.unlock(None)


def test_unlocking_a_range_that_is_not_locked_is_not_an_error():
    """Unlocking twice must not turn into a failure at shutdown."""
    buf = bytearray(4096)
    memlock.lock(buf)
    memlock.unlock(buf)
    memlock.unlock(buf)


def test_a_read_only_buffer_cannot_be_pinned():
    """A buffer that cannot be pinned should say so, not skip quietly."""
    with pytest.raises(Exception):
        memlock.lock(b"immutable")


def test_the_report_names_the_limit():
    """The report is what the warning carries, so it must say something."""
    text = memlock.report()
    assert "locked" in text
    if memlock.lock_limit_bytes():
        assert "allowed" in text


def test_the_human_size_renders_the_units():
    """A log line with a raw byte count is unreadable."""
    assert memlock.human_size(0) == "0 B"
    assert memlock.human_size(512) == "512 B"
    assert memlock.human_size(2048) == "2.0 KiB"
    assert memlock.human_size(5 * (1 << 20)) == "5.0 MiB"
    assert memlock.human_size(3 * (1 << 30)) == "3.0 GiB"


def test_the_limit_is_reported():
    """How much may be locked is the operating system's answer."""
    limit = memlock.lock_limit_bytes()
    assert limit >= 0
    if limit:
        assert limit == memlock.lock_limit_bytes()


def test_the_future_is_pinned_only_where_the_limit_allows_it(monkeypatch):
    """A finite limit must not become a ceiling on the process.

    The Go pins the pages the process maps later as well
    (``MCL_CURRENT | MCL_FUTURE``).  A Go process's resident set is
    small and bounded, so the locked total stays under the limit and
    nothing notices.  A Python process is neither: the interpreter's
    arena, the import machinery's interned attribute names and the
    caches all grow, and with ``MCL_FUTURE`` every one of those pages
    has to come out of the memlock budget.  Past the budget the
    interpreter cannot allocate at all, and the service dies with an
    error that has nothing to do with memory protection.

    So ``MCL_FUTURE`` is used only where the limit is unlimited.
    """
    seen: list[int] = []

    class FakeLibc:
        @staticmethod
        def mlockall(flags: int) -> int:
            seen.append(flags)
            return 0

    monkeypatch.setattr(memlock, "_libc", lambda: FakeLibc())
    monkeypatch.setattr(memlock, "_memlock_is_unlimited", lambda: False)

    memlock.lock_all()
    assert seen == [memlock.MCL_CURRENT]

    seen.clear()
    monkeypatch.setattr(memlock, "_memlock_is_unlimited", lambda: True)

    memlock.lock_all()
    assert seen == [memlock.MCL_CURRENT | memlock.MCL_FUTURE]


def test_an_unlimited_limit_is_recognised(monkeypatch):
    """The rule turns on what the kernel says, not on what we assume."""
    import resource

    monkeypatch.setattr(
        resource, "getrlimit",
        lambda which: (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
    assert getattr(memlock, "_memlock_is_unlimited")() is True

    monkeypatch.setattr(resource, "getrlimit", lambda which: (0, 0))
    assert getattr(memlock, "_memlock_is_unlimited")() is False


# -- core dumps ------------------------------------------------------------


def test_core_dumps_are_forbidden():
    """The limit goes to zero, for the soft and the hard limit.

    This runs in a subprocess because the hard limit cannot be raised
    again once it has been lowered, and the test runner has no business
    losing its core dumps for the rest of the run.
    """
    script = "\n".join((
        "import resource, sys",
        "from security_gateway.platform import memlock",
        "memlock.disable_core_dumps()",
        "soft, hard = resource.getrlimit(resource.RLIMIT_CORE)",
        'sys.stderr.write(f"{soft} {hard}\\n")',
    ))

    done = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True, text=True, timeout=30, check=False)
    assert done.returncode == 0, done.stderr

    soft, hard = done.stderr.strip().split()
    assert soft == "0"
    assert hard == "0"


# -- the key material -----------------------------------------------------


def test_a_key_pins_its_own_pages(monkeypatch):
    """The material is pinned where it is made.

    Not at start-up and not on the way into the cipher: the point is
    that a key is pinned from the moment it exists to the moment it is
    cleared, with no window in between in which it could be swapped.
    """
    calls: list[int] = []
    real_lock = memlock.lock

    def spy(buf):
        calls.append(len(buf))
        return real_lock(buf)

    monkeypatch.setattr(memlock, "lock", spy)

    KeyBytes(b"\x01" * 16)  # the constructor is what locks the pages
    assert calls == [16]


def test_a_key_releases_its_pages_when_it_is_cleared(monkeypatch):
    """A cleared key must not keep its pages pinned for ever."""
    released: list[int] = []
    real_unlock = memlock.unlock

    def spy(buf):
        released.append(len(buf))
        return real_unlock(buf)

    monkeypatch.setattr(memlock, "lock", lambda buf: None)
    monkeypatch.setattr(memlock, "unlock", spy)

    key = KeyBytes(b"\x02" * 32)
    key.zero()

    assert released == [32]
    assert key.is_zero()


def test_a_key_that_could_not_be_pinned_still_works(monkeypatch):
    """Failing to pin is not fatal — the service still works.

    The point of the warning is that an operator learns the memory is
    not protected, not that the service refuses to start.
    """

    def refuse(buf):
        raise memlock.MemlockError("memlock: mlock: Operation not permitted")

    monkeypatch.setattr(memlock, "lock", refuse)

    key = KeyBytes(b"\x03" * 16)
    assert key.bytes() == b"\x03" * 16
    key.zero()
    assert key.is_zero()
