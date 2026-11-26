"""Trust audit must reject before executing any target code."""

import os
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from hypershell.runner import runtime_trust as trust
from hypershell.runner.client import RunnerError


def test_unsupported_platform_and_non_root_are_incomplete(monkeypatch):
    monkeypatch.setattr(trust.sys, "platform", "win32")
    assert trust.audit_runtime(["/x"])["issues"][0]["code"] == "LINUX_REQUIRED"
    monkeypatch.setattr(trust.sys, "platform", "linux")
    monkeypatch.setattr(trust.os, "geteuid", lambda: 1000, raising=False)
    assert trust.audit_runtime(["/x"])["issues"][0]["code"] == "ADMIN_REQUIRED"


@pytest.fixture
def audit_metadata(tmp_path, monkeypatch):
    if sys.platform != "linux":
        pytest.skip("requires Linux symlinks and filesystem metadata")
    root = tmp_path / "runtime"
    root.mkdir(mode=0o755)
    (root / "module.py").write_text("raise RuntimeError('NEVER_EXECUTE')")
    owners = {}

    # Isolate /tmp's world-writable ancestor and CI's uid from subject metadata.
    def metadata(path):
        info = os.lstat(path)
        mode = info.st_mode if Path(path) == root or root in Path(path).parents else info.st_mode & ~0o022
        return SimpleNamespace(
            st_uid=owners.get(Path(path), 0),
            st_mode=mode,
            st_dev=info.st_dev,
            st_ino=info.st_ino,
            st_nlink=info.st_nlink,
        )

    filesystem = SimpleNamespace(
        lstat=metadata, geteuid=lambda: 0, PathLike=os.PathLike, readlink=os.readlink, scandir=os.scandir
    )
    monkeypatch.setattr(trust, "os", filesystem)
    return root, owners


@pytest.fixture
def audit_tree(audit_metadata):
    root, _ = audit_metadata
    return root


def test_controlled_tree_and_internal_links_are_accepted(audit_tree):
    (audit_tree / "alias").symlink_to("module.py")
    assert trust.require_trusted_runtime([audit_tree])["trusted"]


@pytest.mark.parametrize(
    "kind,code",
    [
        ("writable", "GROUP_WORLD_WRITABLE"),
        ("hardlink", "HARDLINK_FILE"),
        ("outside", "SYMLINK_OUTSIDE_ROOTS"),
        ("cycle", "SYMLINK_CYCLE"),
        ("fifo", "SPECIAL_FILE"),
        ("missing", "PATH_MISSING"),
    ],
)
def test_mutable_or_escaping_tree_is_rejected(audit_tree, kind, code):
    if kind == "writable":
        (audit_tree / "module.py").chmod(0o666)
    elif kind == "hardlink":
        os.link(audit_tree / "module.py", audit_tree / "duplicate")
    elif kind == "outside":
        other = audit_tree.parent / "other"
        other.write_text("external")
        (audit_tree / "alias").symlink_to(other)
    elif kind == "cycle":
        (audit_tree / "a").symlink_to("b")
        (audit_tree / "b").symlink_to("a")
    elif kind == "fifo":
        os.mkfifo(audit_tree / "fifo")
    else:
        (audit_tree / "alias").symlink_to("missing")
    report = trust.audit_runtime([audit_tree])
    assert not report["trusted"]
    assert code in {issue["code"] for issue in report["issues"]}
    with pytest.raises(RunnerError):
        trust.require_trusted_runtime([audit_tree])


def test_limits_never_report_partial_audit_as_trusted(audit_tree):
    assert trust.audit_runtime([audit_tree], max_entries=1)["status"] == "incomplete"
    for index in range(4):
        (audit_tree / f"file-{index}").write_text("a")
        (audit_tree / f"file-{index}").chmod(0o666)
    report = trust.audit_runtime([audit_tree], max_issues=1)
    assert not report["trusted"] and report["issues_truncated"]


def test_wrong_owner_is_rejected(audit_metadata):
    root, owners = audit_metadata
    owners[root / "module.py"] = 1000
    assert "NOT_ROOT_OWNED" in {issue["code"] for issue in trust.audit_runtime([root])["issues"]}
