"""A fail-closed per-netns boundary, installed before application startup.

The demo allows loopback and approved public IPv4 model endpoints on TCP 443.
DNS exceptions in the engine cannot grant access to another workspace.
These chains are owned by the runner; live engine policy updates are unsupported.
"""

import ipaddress
from contextlib import contextmanager
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from .client import RunnerError


@contextmanager
def host_network_locked():
    """Serialize create/delete across engines whose iptables omit -w."""
    import fcntl
    from .managed import trusted

    directory = Path("/run/hypershell")
    trusted(directory.parent, directory=True)
    directory.mkdir(mode=0o700, exist_ok=True)
    trusted(directory, directory=True)
    descriptor = os.open(directory / "network.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "a") as lock:
        info = os.fstat(lock.fileno())
        is_private = info.st_uid == 0 and not info.st_mode & 0o077
        if not is_private or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise RunnerError("host network lock must be a private root-owned regular file")
        deadline = time.monotonic() + 60
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError as exc:
                if time.monotonic() >= deadline:
                    raise RunnerError("host network operation is busy; try again after the active operation") from exc
                time.sleep(0.1)
        yield


def boundary_commands(sandbox_id, addresses):
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", sandbox_id):
        raise RunnerError("invalid sandbox id for network boundary")
    if not addresses:
        raise RunnerError("network boundary needs approved model addresses")
    for address in addresses:
        ip = ipaddress.ip_address(address)
        if ip.version != 4 or not ip.is_global:
            raise RunnerError("model boundary requires public IPv4 addresses")
    commands = []
    for binary in ("iptables", "ip6tables"):
        prefix = ["/usr/sbin/ip", "netns", "exec", "jbx-" + sandbox_id, binary, "-w", "5"]
        rules = [
            ["-N", "HS_OUTPUT"],
            ["-N", "HS_INPUT"],
            ["-A", "HS_OUTPUT", "-o", "lo", "-j", "ACCEPT"],
            ["-A", "HS_INPUT", "-i", "lo", "-j", "ACCEPT"],
            ["-A", "HS_INPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
        ]
        if binary == "iptables":
            rules.extend(
                ["-A", "HS_OUTPUT", "-d", address, "-p", "tcp", "--dport", "443", "-j", "ACCEPT"]
                for address in sorted(set(addresses))
            )
        rules.extend(
            [
                ["-A", "HS_OUTPUT", "-j", "DROP"],
                ["-A", "HS_INPUT", "-j", "DROP"],
                ["-I", "OUTPUT", "1", "-j", "HS_OUTPUT"],
                ["-I", "INPUT", "1", "-j", "HS_INPUT"],
            ]
        )
        commands.extend(prefix + rule for rule in rules)
    return commands


def install_boundary(sandbox_id, addresses):
    for command in boundary_commands(sandbox_id, addresses):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RunnerError("required workspace network boundary tool unavailable", tool=command[4]) from exc
        if result.returncode:
            raise RunnerError("required IPv4/IPv6 workspace network boundary failed", tool=command[4])
    return {"profile": "model-ipv4-https-only", "direct_dns": "deny", "external_ipv6": "deny"}
