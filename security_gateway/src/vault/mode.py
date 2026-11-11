"""The data directory's cross-process mode and configuration guard.

One data directory has one vault configuration and one process model.
Two processes may share it only when both say ``multi_process=True``;
every other combination takes an exclusive lock for the lifetime of the
store. The guard is a pair of ``flock`` locks plus a small mode file:

* ``.vault_lock`` is held shared by a multi-process group and
  exclusively by a single-process store. The kernel releases it when
  the process dies, so a crash does not leave the directory locked.
* ``.vault_mode`` records the mode and a fingerprint of the
  configuration. A later process with a different configuration is
  refused even after every previous process has gone away. Changing the
  configuration is therefore a deliberate act: stop every process and
  remove the file.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
from contextlib import contextmanager
from typing import Any, Iterator

from .errors import InvalidError

try:  # pragma: no cover - the tests run on Linux
    import fcntl
except ImportError:  # pragma: no cover - Windows is not supported
    fcntl = None  # type: ignore[assignment]

MODE_FILE = ".vault_mode"
LOCK_FILE = ".vault_lock"
INIT_FILE = ".vault_init"

MODE_LOCAL = "local"
MODE_ETCD = "etcd"
MODE_MULTI_PROCESS = "multi_process"


def mode_name(cfg: Any) -> str:
    """The process model a configuration asks for."""
    if getattr(cfg, "multi_process", False):
        return MODE_MULTI_PROCESS
    etcd = getattr(cfg, "etcd", None)
    if etcd is not None and getattr(etcd, "endpoints", ()):
        return MODE_ETCD
    return MODE_LOCAL


def _fingerprint(cfg: Any, schema: Any) -> str:
    """A stable digest of everything two processes must agree on."""
    etcd = getattr(cfg, "etcd", None)
    payload: dict[str, Any] = {
        "mode": mode_name(cfg),
        "db_path": os.path.abspath(getattr(cfg, "db_path", "") or os.path.join(cfg.data_dir, "vault.db")),
        "crypto_mode": str(getattr(cfg, "crypto_mode", "")),
        "etcd": None,
    }
    if etcd is not None:
        tls = getattr(etcd, "tls", None)
        payload["etcd"] = {
            "endpoints": list(getattr(etcd, "endpoints", ())),
            "namespace": getattr(etcd, "namespace", ""),
            "node_id": getattr(etcd, "node_id", ""),
            "identity_cert_file": getattr(etcd, "identity_cert_file", ""),
            "identity_key_file": getattr(etcd, "identity_key_file", ""),
            "identity_ca_file": getattr(etcd, "identity_ca_file", ""),
            "trusted_cert_sha256": list(getattr(etcd, "trusted_cert_sha256", ())),
            "fetch_timeout": float(getattr(etcd, "fetch_timeout", 0.0)),
            "tls": None
            if tls is None
            else {
                "ca_file": getattr(tls, "ca_file", ""),
                "cert_file": getattr(tls, "cert_file", ""),
                "key_file": getattr(tls, "key_file", ""),
            },
        }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _read_mode(path: str) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = json.load(f)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as exc:
        raise InvalidError(f"vault: read the data directory's mode file {path!r}: {exc}") from exc
    if not isinstance(value, dict) or not value.get("mode"):
        raise InvalidError(f"vault: the data directory's mode file {path!r} is malformed")
    return value


def _write_mode(path: str, value: dict[str, Any]) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        f = os.fdopen(fd, "w", encoding="utf-8")
    except BaseException:
        os.close(fd)
        raise
    try:
        json.dump(value, f, sort_keys=True)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
    finally:
        f.close()
    try:
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _try_lock(fd: int, exclusive: bool) -> bool:
    if fcntl is None:  # pragma: no cover - Windows is not supported
        raise InvalidError("vault: the data directory guard needs fcntl, which this platform does not provide")
    flags = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
    try:
        fcntl.flock(fd, flags | fcntl.LOCK_NB)
        return True
    except OSError as exc:
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            return False
        raise


@contextmanager
def initialization_lock(data_dir: str) -> Iterator[None]:
    """Serialize the first open of a data directory across processes.

    Minting a store writes the S1 shard file and then the key metadata
    row.  Two processes doing that at once can leave the row of one
    pointing at the shard of the other, so the whole initialise-or-load
    step runs under this lock.
    """
    if fcntl is None:  # pragma: no cover - Windows is not supported
        raise InvalidError("vault: the data directory guard needs fcntl")
    path = os.path.join(data_dir, INIT_FILE)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


class DataDirGuard:
    """The open handle that keeps a data directory's mode reserved."""

    def __init__(self, data_dir: str, fd: int, mode: str) -> None:
        self.data_dir = data_dir
        self._fd: int | None = fd
        self.mode = mode

    @classmethod
    def acquire(cls, data_dir: str, cfg: Any, schema: Any) -> "DataDirGuard":
        """Reserve ``data_dir`` for this process, or raise.

        The mode file is read and written under a short exclusive init
        lock, so two processes starting together cannot both create it.
        """
        mode = mode_name(cfg)
        fingerprint = _fingerprint(cfg, schema)
        mode_path = os.path.join(data_dir, MODE_FILE)
        lock_path = os.path.join(data_dir, LOCK_FILE)
        init_path = os.path.join(data_dir, INIT_FILE)

        init_fd = os.open(init_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is None:  # pragma: no cover
                raise InvalidError("vault: the data directory guard needs fcntl")
            fcntl.flock(init_fd, fcntl.LOCK_EX)
            existing = _read_mode(mode_path)
            if existing is not None:
                if existing.get("mode") != mode or existing.get("fingerprint") != fingerprint:
                    raise InvalidError(
                        "vault: the data directory "
                        f"{data_dir!r} already belongs to a different vault "
                        "configuration; every process sharing a data "
                        "directory must use the same mode and settings. "
                        "Stop every process and remove "
                        f"{MODE_FILE} to change it"
                    )
            lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                if not _try_lock(lock_fd, exclusive=(mode != MODE_MULTI_PROCESS)):
                    if mode == MODE_MULTI_PROCESS:
                        detail = (
                            "a single-process vault already holds the exclusive lock; multi_process=True cannot join it"
                        )
                    else:
                        detail = (
                            "another process already uses this data directory. "
                            "Set multi_process=True in every process to share "
                            "one directory"
                        )
                    raise InvalidError(f"vault: cannot open the data directory {data_dir!r}: {detail}")
                if existing is None:
                    _write_mode(
                        mode_path,
                        {
                            "mode": mode,
                            "fingerprint": fingerprint,
                            "owner_pid": os.getpid(),
                        },
                    )
            except BaseException:
                try:
                    os.close(lock_fd)
                except OSError:
                    pass
                raise
        finally:
            try:
                fcntl.flock(init_fd, fcntl.LOCK_UN)
            finally:
                os.close(init_fd)
        return cls(data_dir, lock_fd, mode)

    def close(self) -> None:
        """Release the lock. The mode file remains as the next process's record."""
        fd = self._fd
        self._fd = None
        if fd is None:
            return
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


__all__ = [
    "DataDirGuard",
    "MODE_ETCD",
    "MODE_LOCAL",
    "MODE_MULTI_PROCESS",
    "initialization_lock",
    "mode_name",
]
