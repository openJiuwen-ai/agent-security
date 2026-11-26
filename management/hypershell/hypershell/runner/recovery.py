"""Conservative post-reboot recovery; never kill or sweep unknown resources."""

import hashlib
import os
from pathlib import Path
import re
import stat
import uuid

from .client import RunnerError


def boot_id():
    return str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text().strip()))


def process_start_ticks(pid):
    # comm may contain spaces and parentheses; field 22 follows the last ')'.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[19])


def reboot_evidence(state, state_path, *, legacy_after_reboot=False):
    current = boot_id()
    previous = state.get("boot_id")
    if previous:
        if str(uuid.UUID(previous)) == current:
            raise RunnerError("same-boot engine loss requires manual investigation; recovery refused")
        return {"kind": "boot_id_changed", "boot_id": current, "previous_boot_id": previous}
    if not legacy_after_reboot:
        raise RunnerError("legacy state has no boot ID; confirm reboot and use --legacy-after-reboot")
    started = next(
        int(line.split()[1]) for line in Path("/proc/stat").read_text().splitlines() if line.startswith("btime ")
    )
    info = state_path.stat()
    if max(info.st_mtime, info.st_ctime) >= started:
        raise RunnerError("legacy state was changed during this boot; recovery refused")
    return {
        "kind": "administrator_confirmed_legacy_reboot",
        "boot_id": current,
        "boot_time": started,
        "state_mtime": info.st_mtime,
        "state_ctime": info.st_ctime,
    }


def assert_no_residuals(
    base,
    state,
    *,
    proc=Path("/proc"),
    netns=Path("/var/run/netns"),
    cgroup=Path("/sys/fs/cgroup"),
    interfaces=Path("/sys/class/net"),
):
    """Refuse even empty leftovers; administrator must investigate them separately."""
    sid = state.get("sandbox_id")
    if sid is not None and (not isinstance(sid, str) or re.fullmatch(r"[A-Za-z0-9-]+", sid) is None):
        raise RunnerError("invalid sandbox ID in recovery state")
    if sid:
        if os.path.lexists(netns / ("jbx-" + sid)):
            raise RunnerError("sandbox namespace remains; recovery refused")
        digest = hashlib.sha256(sid.encode()).hexdigest()[:8]
        if any((interfaces / (prefix + digest)).exists() for prefix in ("jwbH", "jwbS")):
            raise RunnerError("sandbox network interface remains; recovery refused")

        def failed_scan(error):
            raise error

        for _, directories, _ in os.walk(cgroup, onerror=failed_scan):
            if sid in directories:
                raise RunnerError("sandbox cgroup remains; recovery refused")
    endpoint = str(base / "engine.sock")
    for line in (proc / "net/unix").read_text().splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 8 and fields[7] == endpoint:
            raise RunnerError("workspace socket is still bound; recovery refused")
    markers = [str(base).encode()] + ([sid.encode()] if sid else [])
    for process in proc.iterdir():
        if not process.name.isdigit():
            continue
        try:
            command = (process / "cmdline").read_bytes()
        except (FileNotFoundError, ProcessLookupError):
            continue
        if any(marker in command for marker in markers):
            raise RunnerError("workspace process remains; recovery refused", pid=int(process.name))
    socket_path = base / "engine.sock"
    if os.path.lexists(socket_path) and not stat.S_ISSOCK(socket_path.lstat().st_mode):
        raise RunnerError("engine socket path is not a socket; recovery refused")


def durable_write(path, data, *, exclusive=False):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC), 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(data)
        target.flush()
        os.fsync(target.fileno())


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY, 0o700)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
