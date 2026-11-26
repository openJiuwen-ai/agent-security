"""Build an in-process boundary observation command using only the stdlib.

The same source can run inside a chat tool, a TUI tool, or a host control. It
does not import HyperShell, read credentials, contact a model, or decide whether
an entry passed acceptance. Callers must compare observations and behavioral
results against their independently verified fixtures and positive controls.
"""

from __future__ import annotations

import json
from os import PathLike
from typing import Any, Mapping

from .client import RunnerError


def decode_probe_result(result):
    """Return versioned evidence from a successful probe process."""
    if not isinstance(result, dict) or result.get("exit_code") != 0:
        raise RunnerError("entry probe process failed")
    try:
        value = json.loads(result.get("stdout"))
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError
        return value
    except (TypeError, ValueError) as exc:
        # Never copy process stderr or malformed stdout into the report.
        raise RunnerError("entry probe returned invalid evidence") from exc


# Keep this self-contained: the application interpreter may not have HyperShell
# installed. The only input is JSON in argv[1]; stdout is exactly one JSON object.
PROBE_SOURCE = r"""
import errno
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import stat
import sys


def error_fields(exc):
    fields = {"exception_type": type(exc).__name__}
    if isinstance(getattr(exc, "errno", None), int):
        fields["errno"] = exc.errno
    return fields


def observe():
    errors = []
    identity = {"pid": os.getpid(), "cwd": None}
    for field, function in (("uid", "getuid"), ("euid", "geteuid"),
                            ("gid", "getgid"), ("egid", "getegid"),
                            ("groups", "getgroups")):
        identity[field] = None
        try:
            value = getattr(os, function)()
            identity[field] = sorted(value) if field == "groups" else value
        except (AttributeError, OSError) as exc:
            errors.append({"scope": "identity." + field, "code": "OBSERVATION_UNAVAILABLE",
                           **error_fields(exc)})
    try:
        identity["cwd"] = os.getcwd()
    except OSError as exc:
        errors.append({"scope": "identity.cwd", "code": "OBSERVATION_UNAVAILABLE",
                       **error_fields(exc)})
    status_fields = {"CapEff": None, "CapBnd": None, "NoNewPrivs": None, "Seccomp": None}
    namespaces = {name: None for name in ("mnt", "net", "pid", "ipc", "uts", "cgroup")}
    observation = {"linux_available": sys.platform.startswith("linux"),
                   "identity": identity, "proc_status": status_fields,
                   "cgroup": None, "namespaces": namespaces}
    if not observation["linux_available"]:
        for scope in ("proc_status", "cgroup", "namespaces"):
            errors.append({"scope": scope, "code": "LINUX_OBSERVATION_UNAVAILABLE"})
        return observation, errors
    try:
        with open("/proc/self/status", encoding="ascii") as handle:
            fields = dict(line.split(":", 1) for line in handle if ":" in line)
        for name in status_fields:
            try:
                status_fields[name] = int(fields[name].strip(), 16 if name.startswith("Cap") else 10)
            except KeyError:
                errors.append({"scope": "proc_status." + name, "code": "PROC_STATUS_FIELD_MISSING"})
            except ValueError:
                errors.append({"scope": "proc_status." + name, "code": "PROC_STATUS_FIELD_INVALID"})
    except (OSError, UnicodeError) as exc:
        errors.append({"scope": "proc_status", "code": "PROC_STATUS_READ_FAILED", **error_fields(exc)})
    try:
        with open("/proc/self/cgroup", encoding="utf-8") as handle:
            value = handle.read(65537)
        if not value.strip() or len(value) > 65536:
            errors.append({"scope": "cgroup", "code": "CGROUP_CONTENT_INVALID"})
        else:
            observation["cgroup"] = value.strip()
    except (OSError, UnicodeError) as exc:
        errors.append({"scope": "cgroup", "code": "CGROUP_READ_FAILED", **error_fields(exc)})
    for name in namespaces:
        try:
            namespaces[name] = os.readlink("/proc/self/ns/" + name)
        except OSError as exc:
            errors.append({"scope": "namespaces." + name, "code": "NAMESPACE_READ_FAILED",
                           **error_fields(exc)})
    return observation, errors


def operation_error(result, exc):
    number = getattr(exc, "errno", None)
    result.update(outcome="error", error_code="OPERATION_FAILED", **error_fields(exc))
    if number in (errno.EACCES, errno.EPERM, errno.EROFS):
        result.update(outcome="denied", error_code="ACCESS_DENIED")
    elif number == errno.ENOENT:
        result["error_code"] = "TARGET_NOT_FOUND"
    elif number == errno.ENOTDIR:
        result["error_code"] = "NOT_A_DIRECTORY"
    elif number == errno.ELOOP:
        result["error_code"] = "SYMLINK_NOT_ALLOWED"
    elif number == errno.EEXIST:
        result["error_code"] = "TARGET_ALREADY_EXISTS"
    elif isinstance(exc, (TimeoutError, socket.timeout)) or number == errno.ETIMEDOUT:
        result["error_code"] = "CONNECT_TIMEOUT"
    elif number == errno.ECONNREFUSED:
        result["error_code"] = "CONNECTION_REFUSED"
    elif number in (errno.ENETUNREACH, errno.EHOSTUNREACH):
        result["error_code"] = "NETWORK_UNREACHABLE"


def path_valid(value):
    return isinstance(value, str) and bool(value) and "\x00" not in value and os.path.isabs(value)


def read_check(result, check):
    path = check.get("path")
    maximum = check.get("max_bytes", 1048576)
    if not path_valid(path) or type(maximum) is not int or not 1 <= maximum <= 16777216:
        result["error_code"] = "INVALID_READ_ARGUMENTS"
        return
    result["path"] = path
    descriptor = None
    try:
        result["executed"] = True
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0), 0o700)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            result["error_code"] = "TARGET_NOT_REGULAR_FILE"
            return
        digest = hashlib.sha256()
        count = 0
        while True:
            chunk = os.read(descriptor, min(65536, maximum + 1 - count))
            if not chunk:
                break
            count += len(chunk)
            if count > maximum:
                result.update(error_code="READ_LIMIT_EXCEEDED", bytes=count)
                return
            digest.update(chunk)
        result.update(outcome="succeeded", sha256=digest.hexdigest(), bytes=count)
        result.pop("error_code", None)
    except OSError as exc:
        operation_error(result, exc)
    finally:
        if descriptor is not None:
            os.close(descriptor)


def create_check(result, check):
    directory = check.get("path")
    if not path_valid(directory):
        result["error_code"] = "INVALID_CREATE_ARGUMENTS"
        return
    result.update(path=directory, created=False, cleanup_succeeded=None)
    if (not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY")
            or os.open not in os.supports_dir_fd or os.unlink not in os.supports_dir_fd
            or os.stat not in os.supports_dir_fd or os.stat not in os.supports_follow_symlinks):
        result["error_code"] = "SAFE_CREATE_UNAVAILABLE"
        return
    directory_fd = descriptor = None
    created_identity = None
    filename = ".hypershell-boundary-" + secrets.token_hex(16)
    try:
        result["executed"] = True
        directory_fd = os.open(directory, getattr(os, "O_PATH", os.O_RDONLY) | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700)
        descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory_fd)
        result["created"] = True
        info = os.fstat(descriptor)
        created_identity = (info.st_dev, info.st_ino)
        payload = b"hypershell-boundary-probe\n"
        written = os.write(descriptor, payload)
        if written != len(payload):
            result["error_code"] = "INCOMPLETE_WRITE"
        else:
            result.update(outcome="succeeded", bytes_written=written)
            result.pop("error_code", None)
    except OSError as exc:
        operation_error(result, exc)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if result["created"]:
            result["cleanup_succeeded"] = False
            try:
                current = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
                if created_identity is None or (current.st_dev, current.st_ino) != created_identity:
                    result.update(outcome="error", error_code="CLEANUP_IDENTITY_UNVERIFIED")
                else:
                    os.unlink(filename, dir_fd=directory_fd)
                    result["cleanup_succeeded"] = True
            except OSError as exc:
                result.update(outcome="error", error_code="CLEANUP_FAILED",
                              cleanup_error=error_fields(exc))
        if directory_fd is not None:
            os.close(directory_fd)


def tcp_check(result, check):
    host, port, timeout = check.get("host"), check.get("port"), check.get("timeout", 0.5)
    try:
        if not isinstance(host, str):
            raise ValueError()
        address = ipaddress.ip_address(host)
        if (type(port) is not int or not 1 <= port <= 65535
                or type(timeout) not in (int, float) or not 0.05 <= timeout <= 2):
            raise ValueError()
    except ValueError:
        result["error_code"] = "INVALID_TCP_ARGUMENTS"
        return
    result.update(host=str(address), port=port, timeout=timeout)
    try:
        result["executed"] = True
        family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
        with socket.socket(family, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout)
            connection.connect((str(address), port))
        result["outcome"] = "succeeded"
        result.pop("error_code", None)
    except OSError as exc:
        operation_error(result, exc)


def run_check(check, index):
    result = {"name": None, "operation": None, "executed": False,
              "outcome": "error", "error_code": "INVALID_CHECK", "index": index}
    if not isinstance(check, dict):
        return result
    name, operation = check.get("name"), check.get("operation")
    if not isinstance(name, str) or not name or len(name) > 200:
        return result
    result.update(name=name, operation=operation if isinstance(operation, str) else None)
    operations = {"read": read_check, "create": create_check, "tcp_connect": tcp_check}
    if not isinstance(operation, str) or operation not in operations:
        result["error_code"] = "UNSUPPORTED_OPERATION"
        return result
    try:
        operations[operation](result, check)
    except Exception as exc:
        result.update(outcome="error", error_code="PROBE_CHECK_ERROR", **error_fields(exc))
    return result


def reject_constant(value):
    raise ValueError()


def main():
    observations, errors = observe()
    report = {"schema_version": 1, "observations": observations, "errors": errors, "checks": []}
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > 65536:
            raise ValueError()
        spec = json.loads(sys.argv[1], parse_constant=reject_constant)
        if not isinstance(spec, dict):
            raise ValueError()
        checks = spec.get("checks", [])
        if not isinstance(checks, list) or len(checks) > 64:
            raise ValueError()
    except (ValueError, TypeError):
        errors.append({"scope": "spec", "code": "INVALID_SPEC"})
        return report, 2
    report["checks"] = [run_check(check, index) for index, check in enumerate(checks)]
    return report, 0


try:
    report, exit_code = main()
except Exception as exc:
    report = {"schema_version": 1, "observations": {}, "checks": [],
              "errors": [{"scope": "probe", "code": "PROBE_INTERNAL_ERROR", **error_fields(exc)}]}
    exit_code = 2
print(json.dumps(report, ensure_ascii=True, sort_keys=True, allow_nan=False))
sys.exit(exit_code)
"""


def build_probe_command(python_path: str | PathLike[str], spec: Mapping[str, Any]) -> list[str]:
    """Return argv for a direct subprocess/tool execution, never a shell command.

    ``read`` checks accept an absolute ``path`` and optional ``max_bytes``.
    ``create`` checks accept an existing directory ``path``; only a randomly
    named exclusive file inside it is created and then removed. ``tcp_connect``
    checks accept a numeric ``host``, ``port`` and a 0.05--2 second ``timeout``.
    Expected hashes and allowed/denied decisions belong to the caller.
    """
    # The workspace may contain json.py/socket.py or a hostile PYTHONPATH.
    # This stdlib-only measurement must not import code from either location.
    return [
        str(python_path),
        "-I",
        "-c",
        PROBE_SOURCE,
        json.dumps(dict(spec), ensure_ascii=True, separators=(",", ":"), allow_nan=False),
    ]
