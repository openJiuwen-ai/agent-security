"""Execute the real stdlib probe; model text and mocked syscalls are not evidence."""

from __future__ import annotations

import hashlib
from ipaddress import IPv4Address
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from uuid import uuid4

import pytest

from hypershell.runner.boundary_probe import PROBE_SOURCE, build_probe_command

LOOPBACK = str(IPv4Address(socket.INADDR_LOOPBACK))


@pytest.fixture
def probe_dir():
    # Default mkdir preserves inherited Windows desktop sandbox ACLs.
    path = Path(__file__).resolve().parents[1] / ".test-tmp" / ("boundary-probe-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


def _run(spec, *, cwd=None):
    process = subprocess.run(
        build_probe_command(sys.executable, spec), capture_output=True, text=True, timeout=10, cwd=cwd
    )
    assert process.stderr == ""
    assert len(process.stdout.splitlines()) == 1
    return process, json.loads(process.stdout)


def test_probe_observes_actual_process_and_cwd(probe_dir):
    process, report = _run({"checks": []}, cwd=probe_dir)
    assert process.returncode == 0
    identity = report["observations"]["identity"]
    assert identity["pid"] != os.getpid()
    assert Path(identity["cwd"]).resolve() == probe_dir.resolve()
    assert report["checks"] == []
    assert "passed" not in report and "ok" not in report
    if sys.platform.startswith("linux"):
        assert identity["uid"] == os.getuid()
        assert identity["euid"] == os.geteuid()
        assert identity["gid"] == os.getgid()
        assert identity["egid"] == os.getegid()
        assert identity["groups"] == sorted(os.getgroups())
        assert report["observations"]["linux_available"] is True
        for name in ("CapEff", "CapBnd", "NoNewPrivs", "Seccomp"):
            assert type(report["observations"]["proc_status"][name]) is int
        assert report["observations"]["cgroup"] == Path("/proc/self/cgroup").read_text().strip()
        for name in ("mnt", "net", "pid", "ipc", "uts", "cgroup"):
            assert report["observations"]["namespaces"][name] == os.readlink(Path("/proc/self/ns") / name)
        assert report["errors"] == []
    else:
        assert report["observations"]["linux_available"] is False
        assert all(value is None for value in report["observations"]["proc_status"].values())
        assert all(value is None for value in report["observations"]["namespaces"].values())
        assert {error["scope"] for error in report["errors"] if error["code"] == "LINUX_OBSERVATION_UNAVAILABLE"} == {
            "proc_status",
            "cgroup",
            "namespaces",
        }


def test_read_hashes_real_bytes_without_echoing_contents_or_trusting_expected_hash(probe_dir):
    content = b"PRIVATE_FIXTURE_CONTENT_MUST_NOT_APPEAR_IN_REPORT\x00\xff"
    target = probe_dir / "fixture.bin"
    target.write_bytes(content)
    process, report = _run(
        {"checks": [{"name": "own-file", "operation": "read", "path": str(target), "expected_sha256": "0" * 64}]}
    )
    assert process.returncode == 0
    check = report["checks"][0]
    assert check["executed"] is True and check["outcome"] == "succeeded"
    assert check["sha256"] == hashlib.sha256(content).hexdigest()
    assert check["bytes"] == len(content)
    assert "PRIVATE_FIXTURE_CONTENT" not in process.stdout
    assert "expected_sha256" not in process.stdout


def test_missing_file_is_not_reported_as_access_denied(probe_dir):
    _, report = _run({"checks": [{"name": "absent", "operation": "read", "path": str(probe_dir / "missing")}]})
    check = report["checks"][0]
    assert check["executed"] is True and check["outcome"] == "error"
    assert check["error_code"] == "TARGET_NOT_FOUND"
    assert "sha256" not in check


def test_read_limit_cannot_return_a_partial_success_hash(probe_dir):
    target = probe_dir / "too-large"
    target.write_bytes(b"a" * 20)
    _, report = _run({"checks": [{"name": "bounded", "operation": "read", "path": str(target), "max_bytes": 10}]})
    check = report["checks"][0]
    assert check["outcome"] == "error" and check["error_code"] == "READ_LIMIT_EXCEEDED"
    assert "sha256" not in check


def test_directory_cannot_be_returned_as_a_successful_fixture_read(probe_dir):
    _, report = _run({"checks": [{"name": "directory", "operation": "read", "path": str(probe_dir)}]})
    check = report["checks"][0]
    assert check["executed"] is True and check["outcome"] != "succeeded"
    assert "sha256" not in check


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="POSIX permissions and credential switching require Linux"
)
def test_actual_filesystem_permission_denials_are_distinct_from_missing_targets(probe_dir):
    target = probe_dir / "unreadable"
    target.write_bytes(b"private fixture")
    directory = probe_dir / "unwritable"
    directory.mkdir()
    target.chmod(0o000)
    directory.chmod(0o555)
    command = build_probe_command(
        sys.executable,
        {
            "checks": [
                {"name": "unreadable", "operation": "read", "path": str(target)},
                {"name": "unwritable", "operation": "create", "path": str(directory)},
            ]
        },
    )
    # Root can override file modes. Exercise the actual kernel as nobody in
    # that case; no mocked os.open, canned probe JSON, or model text is used.
    credentials = {"user": 65534, "group": 65534, "extra_groups": []} if os.geteuid() == 0 else {}
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=10, **credentials)
        assert process.returncode == 0 and process.stderr == ""
        checks = json.loads(process.stdout)["checks"]
        assert all(check["executed"] is True and check["outcome"] == "denied" for check in checks)
        assert all(check["error_code"] == "ACCESS_DENIED" for check in checks)
        assert "private fixture" not in process.stdout
    finally:
        target.chmod(0o600)
        directory.chmod(0o700)
    assert target.read_bytes() == b"private fixture"
    assert list(directory.iterdir()) == []


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="safe dir_fd/O_NOFOLLOW creation requires Linux")
def test_create_is_exclusive_and_removes_only_its_own_file(probe_dir):
    existing = probe_dir / "keep.txt"
    existing.write_bytes(b"do not overwrite")
    _, report = _run({"checks": [{"name": "writable", "operation": "create", "path": str(probe_dir)}]})
    check = report["checks"][0]
    assert check["executed"] is True and check["outcome"] == "succeeded"
    assert check["created"] is True and check["cleanup_succeeded"] is True
    assert existing.read_bytes() == b"do not overwrite"
    assert list(probe_dir.iterdir()) == [existing]


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="safe dir_fd/O_NOFOLLOW creation requires Linux")
def test_create_refuses_file_and_symlink_targets_without_modifying_them(probe_dir):
    existing = probe_dir / "keep.txt"
    existing.write_bytes(b"do not overwrite")
    link = probe_dir / "directory-link"
    link.symlink_to(probe_dir, target_is_directory=True)
    _, report = _run(
        {
            "checks": [
                {"name": "file", "operation": "create", "path": str(existing)},
                {"name": "link", "operation": "create", "path": str(link)},
            ]
        }
    )
    assert all(check["outcome"] == "error" and not check["created"] for check in report["checks"])
    assert existing.read_bytes() == b"do not overwrite"
    assert set(probe_dir.iterdir()) == {existing, link}


@pytest.mark.skipif(hasattr(os, "O_NOFOLLOW"), reason="platform has safe create primitives")
def test_create_reports_unavailable_when_nofollow_is_missing(probe_dir):
    _, report = _run({"checks": [{"name": "create", "operation": "create", "path": str(probe_dir)}]})
    check = report["checks"][0]
    assert check["executed"] is False and check["outcome"] == "error"
    assert check["error_code"] == "SAFE_CREATE_UNAVAILABLE"
    assert list(probe_dir.iterdir()) == []


def test_tcp_positive_control_connects_to_real_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((LOOPBACK, 0))
        listener.listen(1)
        _, report = _run(
            {
                "checks": [
                    {
                        "name": "loopback",
                        "operation": "tcp_connect",
                        "host": LOOPBACK,
                        "port": listener.getsockname()[1],
                        "timeout": 0.2,
                    }
                ]
            }
        )
        check = report["checks"][0]
        assert check["executed"] is True and check["outcome"] == "succeeded"
        listener.settimeout(1)
        accepted, _ = listener.accept()
        accepted.close()


def test_tcp_missing_listener_is_not_reported_as_policy_denial():
    # Reserve the port without listening so no unrelated listener can claim it.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved:
        reserved.bind((LOOPBACK, 0))
        _, report = _run(
            {
                "checks": [
                    {
                        "name": "no-listener",
                        "operation": "tcp_connect",
                        "host": LOOPBACK,
                        "port": reserved.getsockname()[1],
                        "timeout": 0.1,
                    }
                ]
            }
        )
    check = report["checks"][0]
    assert check["executed"] is True and check["outcome"] == "error"
    assert check["error_code"] in {"CONNECTION_REFUSED", "CONNECT_TIMEOUT"}


@pytest.mark.parametrize(
    "check",
    [
        {"name": "bad-op", "operation": "shell", "path": "/tmp"},
        {"name": "relative", "operation": "read", "path": "relative"},
        {"name": "dns", "operation": "tcp_connect", "host": "example.invalid", "port": 443},
        {"name": "long-timeout", "operation": "tcp_connect", "host": LOOPBACK, "port": 443, "timeout": 60},
        {"name": "wrong-port", "operation": "tcp_connect", "host": LOOPBACK, "port": True},
    ],
)
def test_invalid_check_never_looks_executed(check):
    _, report = _run({"checks": [check]})
    result = report["checks"][0]
    assert result["outcome"] == "error" and result["executed"] is False
    assert result["error_code"]


@pytest.mark.parametrize("argument", ["not json", "[]", '{"checks":{}}', '{"checks":[],"timeout":NaN}'])
def test_invalid_spec_returns_one_structured_error(argument):
    process = subprocess.run(
        [sys.executable, "-I", "-c", PROBE_SOURCE, argument], capture_output=True, text=True, timeout=10
    )
    assert process.returncode == 2 and process.stderr == ""
    report = json.loads(process.stdout)
    assert report["checks"] == []
    assert {"scope": "spec", "code": "INVALID_SPEC"} in report["errors"]


def test_command_preserves_argument_without_shell_interpretation(probe_dir):
    target = probe_dir / "$(do-not-execute); space ' quotes.txt"
    target.write_bytes(b"literal path")
    command = build_probe_command(
        sys.executable, {"checks": [{"name": "literal", "operation": "read", "path": str(target)}]}
    )
    assert command[0] == sys.executable and "-I" in command
    assert command[command.index("-c") + 1] == PROBE_SOURCE
    process = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert process.returncode == 0
    assert json.loads(process.stdout)["checks"][0]["sha256"] == hashlib.sha256(b"literal path").hexdigest()


def test_isolated_probe_ignores_workspace_and_pythonpath_import_poisoning(probe_dir):
    (probe_dir / "json.py").write_text(
        "from pathlib import Path\n"
        "Path('IMPORT_POISON_EXECUTED').write_text('untrusted module imported')\n"
        "raise RuntimeError('attacker controlled json module')\n",
        encoding="utf-8",
    )
    command = build_probe_command(sys.executable, {"checks": []})
    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=10,
        cwd=probe_dir,
        env={**os.environ, "PYTHONPATH": str(probe_dir)},
    )
    assert process.returncode == 0 and process.stderr == ""
    report = json.loads(process.stdout)
    assert report["schema_version"] == 1 and report["checks"] == []
    assert not (probe_dir / "IMPORT_POISON_EXECUTED").exists()
