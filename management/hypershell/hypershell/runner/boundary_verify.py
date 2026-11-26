"""Observe both production entry paths without starting/stopping workspaces.

Run explicitly on a Linux demo host as its administrator. Only uniquely named
synthetic fixtures and temporary TCP listeners are created. No model is called.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import errno
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import select
import stat
import subprocess
import sys
import tempfile
import uuid

from ..config import AdminConfig, load_document
from ..console import log_console
from ..policy import LaunchRequest
from .boundary_evaluation import evaluate_observation
from .boundary_probe import build_probe_command, decode_probe_result
from .client import RunnerError
from .managed import ManagedRunner, require_admin, trusted
from .provenance import collect_manifest
from .workspaces import same_workspace_instance

LIMITATIONS = [
    "Exercises the production command construction and execution paths, not interactive login or model replies.",
    "File/network checks do not independently prove Landlock enforcement or identify which mechanism denied access.",
    "Does not test CPU/memory exhaustion, external DNS/IPv6, lifecycle cleanup or full sandbox certification.",
    "Observed manifest records this run; it is not a dependency lock or immutable runtime bundle.",
]

_LISTENER = r"""
import json, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(('0.0.0.0', 0)); s.listen(8)
print(json.dumps({'port': s.getsockname()[1]}), flush=True)
while True:
    connection, _ = s.accept()
    connection.close()
"""


def _hash(data):
    return hashlib.sha256(data).hexdigest()


def write_report(path: Path, report: dict):
    """Replace a report atomically in a private administrator-owned directory."""
    path = Path(path).absolute()
    trusted(path.parent, directory=True)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1:
            raise RunnerError("report target must be a root-owned regular file")
    descriptor, temporary = tempfile.mkstemp(prefix=".boundary-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            os.fchmod(handle.fileno(), 0o600)
            json.dump(report, handle, ensure_ascii=False, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY, 0o700)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class Fixtures:
    """Keep directory descriptors so cleanup cannot follow substituted links."""

    def __init__(self):
        self.files = []
        self.directories = []
        self.errors = []

    def directory(self, parent, name):
        parent = Path(parent).absolute()
        if parent.resolve() != parent:
            raise RunnerError("fixture directory must not contain symlinks")
        descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700)
        try:
            os.mkdir(name, mode=0o755, dir_fd=descriptor)
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            self.directories.append((descriptor, name, info.st_dev, info.st_ino))
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700, dir_fd=descriptor)
            try:
                # Sticky world-write is deliberate: DAC must allow the write
                # control so a readonly mount must enforce the negative case.
                os.fchmod(child, 0o1777)
            finally:
                os.close(child)
            return parent / name
        except BaseException:
            if not any(item[0] == descriptor for item in self.directories):
                os.close(descriptor)
            raise

    def create(self, directory, name, data, *, uid=0, gid=0, mode=0o644):
        directory = Path(directory).absolute()
        if directory.resolve() != directory:
            raise RunnerError("fixture directory must not contain symlinks")
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700)
        try:
            descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=directory_fd)
            info = os.fstat(descriptor)
            self.files.append((directory_fd, name, info.st_dev, info.st_ino))
            with os.fdopen(descriptor, "wb") as handle:
                os.fchown(handle.fileno(), uid, gid)
                os.fchmod(handle.fileno(), mode)
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            # Independent positive control: the host really has the exact fixture.
            read_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            with os.fdopen(read_fd, "rb") as handle:
                if handle.read() != data:
                    raise RunnerError("host fixture positive control failed")
            return directory / name
        except BaseException:
            if not any(item[0] == directory_fd for item in self.files):
                os.close(directory_fd)
            raise

    def close(self):
        for descriptor, name, device, inode in reversed(self.files):
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (info.st_dev, info.st_ino) != (device, inode):
                    raise RunnerError("fixture identity changed; cleanup refused")
                os.unlink(name, dir_fd=descriptor)
            except OSError as exc:
                self.errors.append({"scope": "fixture_cleanup", "code": type(exc).__name__})
            except RunnerError:
                self.errors.append({"scope": "fixture_cleanup", "code": "IDENTITY_CHANGED"})
            finally:
                os.close(descriptor)
        self.files.clear()
        for descriptor, name, device, inode in reversed(self.directories):
            try:
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (info.st_dev, info.st_ino) != (device, inode):
                    raise RunnerError("fixture directory identity changed")
                os.rmdir(name, dir_fd=descriptor)
            except (OSError, RunnerError):
                self.errors.append({"scope": "fixture_cleanup", "code": "DIRECTORY_CLEANUP_FAILED"})
            finally:
                os.close(descriptor)
        self.directories.clear()


class Listener:
    def __init__(self, runner, state):
        self.process = subprocess.Popen(
            [
                "/usr/sbin/ip",
                "netns",
                "exec",
                "jbx-" + state["sandbox_id"],
                str(runner.bin / "python"),
                "-I",
                "-B",
                "-u",
                "-c",
                _LISTENER,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            if not select.select([self.process.stdout], [], [], 10)[0]:
                raise RunnerError("fixture listener readiness timed out")
            self.port = json.loads(self.process.stdout.readline())["port"]
            if type(self.port) is not int or not 1 <= self.port <= 65535:
                raise ValueError
        except BaseException:
            self.close()
            raise RunnerError("fixture listener failed to start") from None

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        if self.process.stdout:
            self.process.stdout.close()


def _check(name, operation, **target):
    return {"name": name, "operation": operation, **target}


def verify(
    config_path: Path, runtime_path: Path, users: list[str], request_paths: dict[str, Path], shared_resource: str
) -> dict:
    require_admin()

    report = {
        "schema_version": 1,
        "kind": "entry_boundary_acceptance",
        "passed": False,
        "status": "incomplete",
        "run_id": uuid.uuid4().hex,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "scope": "running-workspace chat/TUI execution paths; no lifecycle or model calls",
        "limitations": LIMITATIONS,
        "errors": [],
        "users": {},
    }
    fixtures = Fixtures()
    listeners = {}
    try:
        if len(users) != 2 or len(set(users)) != 2:
            raise RunnerError("entry verification requires two distinct users")
        import pwd
        import grp

        config = AdminConfig.load(trusted(config_path))
        trusted(runtime_path)
        runners = {uid: ManagedRunner(config, runtime_path, uid) for uid in users}
        first = runners[users[0]]
        first.require_runtime_bundle()
        report["manifest"] = collect_manifest(
            config_path=config_path,
            runtime_path=runtime_path,
            request_paths=request_paths,
            application_python=first.bin / "python",
            source_dir=first.source,
            dependency_overlay=first.dependency_overlay,
        )
        report["manifest_digest"] = report["manifest"]["manifest_digest"]
        states = {uid: runner.status() for uid, runner in runners.items()}
        if any(state.get("phase") != "RUNNING" for state in states.values()):
            raise RunnerError("both workspaces must already be RUNNING; no automatic start")
        plans = {
            uid: config.compile(uid, LaunchRequest.from_dict(load_document(trusted(request_paths[uid]))))
            for uid in users
        }
        for uid in users:
            if (
                states[uid].get("plan_digest") != plans[uid].digest
                or states[uid].get("authorization_digest") != config.explain(uid)["authorization_digest"]
                or sorted(states[uid].get("roles", [])) != sorted(config.users[uid].roles)
            ):
                raise RunnerError(
                    "running instance differs from supplied configuration/request; rebuild explicitly first"
                )
        if len({state["sandbox_id"] for state in states.values()}) != 2:
            raise RunnerError("users share a sandbox")
        host = decode_probe_result(_local_probe())
        report["host"] = host
        workspaces, shared = {}, {}
        for uid in users:
            workspaces[uid] = next((m for m in plans[uid].mounts if m.target == "/workspace" and not m.read_only), None)
            shared[uid] = next((m for m in plans[uid].mounts if m.resource_id == shared_resource and m.read_only), None)
            if workspaces[uid] is None or shared[uid] is None:
                raise RunnerError("each request must mount writable /workspace and the selected read-only resource")
        if shared[users[0]].source != shared[users[1]].source:
            raise RunnerError("read-only fixture must refer to the same registered source")
        marker = ".hs-boundary-" + report["run_id"]
        own_data = {uid: os.urandom(32) for uid in users}
        own_files, management_files = {}, {}
        for uid in users:
            profile = config.users[uid]
            account = pwd.getpwnam(profile.run_as_user)
            group = grp.getgrnam(profile.run_as_group)
            own_files[uid] = fixtures.create(
                workspaces[uid].source, marker, own_data[uid], uid=account.pw_uid, gid=group.gr_gid
            )
            management_files[uid] = fixtures.create(runners[uid].base, marker, os.urandom(32), mode=0o600)
            listeners[uid] = Listener(runners[uid], states[uid])
        shared_data = os.urandom(32)
        fixtures.create(shared[users[0]].source, marker, shared_data)
        shared_writable = fixtures.directory(shared[users[0]].source, marker + "-write")
        for uid in users:
            profile = config.users[uid]
            control = subprocess.run(
                build_probe_command(
                    sys.executable, {"checks": [_check("shared_dac_control", "create", path=str(shared_writable))]}
                ),
                user=pwd.getpwnam(profile.run_as_user).pw_uid,
                group=grp.getgrnam(profile.run_as_group).gr_gid,
                extra_groups=[],
                capture_output=True,
                text=True,
                timeout=10,
            )
            evidence = decode_probe_result({"exit_code": control.returncode, "stdout": control.stdout})
            checks = evidence.get("checks", [])
            if (
                len(checks) != 1
                or checks[0].get("outcome") != "succeeded"
                or checks[0].get("cleanup_succeeded") is not True
            ):
                raise RunnerError("same-UID host write positive control failed")
        report["positive_controls"] = {"host_fixture_reads": True, "listeners": {}}
        report["positive_controls"]["shared_same_uid_writes"] = True
        specs, expected = {}, {}
        for uid in users:
            peer = next(item for item in users if item != uid)
            ip = str(ipaddress.IPv4Address(states[uid]["observed_sandbox"]["ip_address"]))
            peer_ip = str(ipaddress.IPv4Address(states[peer]["observed_sandbox"]["ip_address"]))
            peer_listener = listeners.get(peer)
            if peer_listener is None:
                raise RunnerError("peer fixture listener is missing")
            checks = [
                _check("own_read", "read", path=posixpath.join("/workspace", marker)),
                _check("own_write", "create", path="/workspace"),
                _check("peer_read", "read", path=str(own_files[peer])),
                _check("management_read", "read", path=str(management_files[uid])),
                _check("shared_read", "read", path=posixpath.join(shared[uid].target, marker)),
                _check("shared_write", "create", path=posixpath.join(shared[uid].target, f"{marker}-write")),
                _check("loopback", "tcp_connect", host="127.0.0.1", port=listeners[uid].port),
                _check("own_endpoint", "tcp_connect", host=ip, port=listeners[uid].port),
                _check("peer_endpoint", "tcp_connect", host=peer_ip, port=peer_listener.port),
            ]
            specs[uid] = {"checks": checks}
            expected[uid] = {item["name"]: {**item, "outcome": "succeeded"} for item in checks}
            for name in ("peer_read", "management_read"):
                expected[uid][name].update(outcome="blocked", allow_errno=[errno.ENOENT, errno.EACCES, errno.EPERM])
            expected[uid]["shared_write"].update(
                outcome="blocked", allow_errno=[errno.EACCES, errno.EPERM, errno.EROFS]
            )
            expected[uid]["peer_endpoint"].update(
                outcome="blocked",
                allow_errno=[errno.EACCES, errno.EPERM, errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH],
            )
            expected[uid]["own_read"]["sha256"] = _hash(own_data[uid])
            expected[uid]["shared_read"]["sha256"] = _hash(shared_data)
        # First prove each real peer listener accepts its own namespace IP.
        # No failed connection can stand in for isolation without this control.
        for uid in users:
            positive = {"checks": [specs[uid]["checks"][7]]}
            evidence = decode_probe_result(
                runners[uid].run_probe("chat", build_probe_command(runners[uid].bin / "python", positive), timeout=15)
            )
            checks = evidence.get("checks", [])
            if len(checks) != 1 or checks[0].get("executed") is not True or checks[0].get("outcome") != "succeeded":
                raise RunnerError("peer listener positive control failed")
            if listeners[uid].process.poll() is not None:
                raise RunnerError("peer listener positive control failed")
            report["positive_controls"]["listeners"][uid] = True
        for uid in users:
            report["users"][uid] = {
                "sandbox_id": states[uid]["sandbox_id"],
                "expected_checks": expected[uid],
                "entries": {},
            }
            reference = None
            for entry in ("chat", "tui"):
                try:
                    evidence = decode_probe_result(
                        runners[uid].run_probe(
                            entry, build_probe_command(runners[uid].bin / "python", specs[uid]), timeout=30
                        )
                    )
                    profile = config.users[uid]
                    verdict = evaluate_observation(
                        evidence,
                        expected_uid=pwd.getpwnam(profile.run_as_user).pw_uid,
                        expected_gid=grp.getgrnam(profile.run_as_group).gr_gid,
                        host_observation=host,
                        expected_checks=expected[uid],
                        reference_observation=reference,
                    )
                    report["users"][uid]["entries"][entry] = {"evidence": evidence, "verdict": verdict}
                    if entry == "chat":
                        reference = evidence
                except Exception as exc:
                    report["users"][uid]["entries"][entry] = {
                        "verdict": {"passed": False},
                        "error_code": type(exc).__name__,
                    }
        for uid in users:
            if not same_workspace_instance(states[uid], runners[uid].status()):
                raise RunnerError("instance changed during verification; evidence is inconclusive")
        if any(listener.process.poll() is not None for listener in listeners.values()):
            raise RunnerError("fixture listener exited during verification")
        report["status"] = (
            "passed"
            if all(
                report["users"][uid]["entries"][entry]["verdict"]["passed"]
                for uid in users
                for entry in ("chat", "tui")
            )
            else "failed"
        )
        report["passed"] = report["status"] == "passed"
    except Exception as exc:
        report["errors"].append(
            {
                "scope": "verification",
                "code": type(exc).__name__,
                "message": str(exc) if isinstance(exc, RunnerError) else "verification prerequisite failed",
            }
        )
    finally:
        for listener in listeners.values():
            try:
                listener.close()
            except Exception:
                report["errors"].append({"scope": "listener_cleanup", "code": "CLEANUP_FAILED"})
        fixtures.close()
        report["errors"].extend(fixtures.errors)
        if report["errors"]:
            report.update(passed=False, status="incomplete")
    return report


def _local_probe():
    result = subprocess.run(
        build_probe_command(sys.executable, {"checks": []}), capture_output=True, text=True, timeout=10
    )
    return {"exit_code": result.returncode, "stdout": result.stdout}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/hypershell-demo/admin.yaml"))
    parser.add_argument("--runtime", type=Path, default=Path("/etc/hypershell-demo/runtime.yaml"))
    parser.add_argument("--users", nargs=2, required=True)
    parser.add_argument("--request", action="append", default=[], metavar="USER=PATH")
    parser.add_argument("--shared-resource", required=True, help="read-only directory mounted by both users")
    parser.add_argument("--output", type=Path, required=True, help="report in an existing root-controlled directory")
    args = parser.parse_args(argv)
    try:
        require_admin()
        requests = {uid: args.config.parent / f"request-{uid}.yaml" for uid in args.users}
        for assignment in args.request:
            uid, path = assignment.split("=", 1)
            if uid not in requests or not path:
                raise ValueError
            requests[uid] = Path(path)
        # Check output safety before creating fixtures or entering a workspace.
        trusted(args.output.absolute().parent, directory=True)
        report = verify(args.config, args.runtime, args.users, requests, args.shared_resource)
        write_report(args.output, report)
    except Exception as exc:
        log_console(json.dumps({"passed": False, "error_code": type(exc).__name__}), error=True)
        return 2
    log_console(
        json.dumps(
            {
                "passed": report["passed"],
                "status": report["status"],
                "manifest_digest": report.get("manifest_digest"),
                "report": str(args.output),
            }
        )
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
