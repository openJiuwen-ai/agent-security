"""Acceptance orchestration must preserve failures and clean only its fixtures."""

import json
import os
from pathlib import Path
import sys
from types import SimpleNamespace
from uuid import uuid4

import pytest

from hypershell.runner import boundary_verify as verifier
from hypershell.runner.boundary_probe import decode_probe_result
from hypershell.runner.client import RunnerError
from hypershell.runner.workspaces import same_workspace_instance


@pytest.fixture
def folder():
    path = Path(__file__).resolve().parents[1] / ".test-tmp" / ("verify-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


@pytest.mark.parametrize(
    "result",
    [
        None,
        {"exit_code": 1, "stdout": "SECRET"},
        {"exit_code": 0, "stdout": "SECRET"},
        {"exit_code": 0, "stdout": "[]"},
        {"exit_code": 0, "stdout": "{}"},
        {"exit_code": 0, "stdout": '{"schema_version":2}'},
    ],
)
def test_invalid_process_evidence_is_rejected_without_echo(result):
    with pytest.raises(RunnerError) as error:
        decode_probe_result(result)
    assert "SECRET" not in str(error.value)


def test_decode_requires_successful_versioned_process_response():
    observation = {"schema_version": 1, "observations": {}, "checks": [], "errors": []}
    assert decode_probe_result({"exit_code": 0, "stdout": json.dumps(observation)}) == observation


@pytest.mark.parametrize("users", [[], ["u1"], ["u1", "u1"], ["u1", "u2", "u3"]])
def test_distinct_user_precondition_does_not_create_fixtures(monkeypatch, users):
    monkeypatch.setattr(verifier, "require_admin", lambda: None)
    monkeypatch.setattr(verifier.Fixtures, "create", lambda *a, **k: pytest.fail("created fixture"))
    report = verifier.verify(Path("absent-admin"), Path("absent-runtime"), users, {}, "knowledge")
    assert not report["passed"]
    assert report["status"] == "incomplete"
    assert report["errors"][0]["code"] == "RunnerError"


def test_missing_configuration_is_incomplete_without_echoing_arbitrary_errors(monkeypatch):
    monkeypatch.setattr(verifier, "require_admin", lambda: None)
    monkeypatch.setitem(sys.modules, "pwd", SimpleNamespace())
    monkeypatch.setitem(sys.modules, "grp", SimpleNamespace())

    def fail(*args, **kwargs):
        raise OSError("SECRET runtime output")

    monkeypatch.setattr(verifier, "trusted", fail)
    report = verifier.verify(Path("missing"), Path("runtime"), ["u1", "u2"], {}, "knowledge")
    assert not report["passed"] and report["status"] == "incomplete"
    assert "SECRET" not in json.dumps(report)


def test_cleanup_errors_cannot_leave_an_acceptance_pass(monkeypatch):
    monkeypatch.setattr(verifier, "require_admin", lambda: None)

    def cleanup(self):
        self.errors.append({"scope": "fixture_cleanup", "code": "CLEANUP_FAILED"})

    monkeypatch.setattr(verifier.Fixtures, "close", cleanup)
    report = verifier.verify(Path("a"), Path("r"), [], {}, "knowledge")
    assert not report["passed"] and report["status"] == "incomplete"
    assert any(item["scope"] == "fixture_cleanup" for item in report["errors"])


@pytest.mark.parametrize("changed", ["sandbox_id", "generation", "engine_pid", "engine_start_ticks", "boot_id"])
def test_replaced_instance_invalidates_evidence(changed):
    before = {
        "phase": "RUNNING",
        "sandbox_id": "s",
        "generation": "g",
        "engine_pid": 1,
        "engine_start_ticks": 2,
        "boot_id": "b",
    }
    assert same_workspace_instance(before, dict(before))
    assert not same_workspace_instance(before, {**before, changed: "changed"})
    assert not same_workspace_instance(before, {**before, "phase": "STOPPED"})


@pytest.mark.skipif(sys.platform != "linux", reason="descriptor-relative fixture lifecycle requires Linux")
def test_fixture_control_and_cleanup_preserve_unrelated_files(folder):
    original = folder / "user-data"
    original.write_text("retain", encoding="utf-8")
    fixtures = verifier.Fixtures()
    synthetic = fixtures.create(folder, ".probe", b"fixture", uid=os.getuid(), gid=os.getgid())
    child = fixtures.directory(folder, ".write-test")
    assert synthetic.read_bytes() == b"fixture"
    assert child.stat().st_mode & 0o7777 == 0o1777
    fixtures.close()
    assert not fixtures.errors
    assert not synthetic.exists() and not child.exists()
    assert original.read_text() == "retain"


@pytest.mark.skipif(sys.platform != "linux", reason="descriptor-relative cleanup requires Linux")
def test_fixture_replacement_is_retained_and_reported(folder):
    fixtures = verifier.Fixtures()
    target = fixtures.create(folder, ".probe", b"fixture", uid=os.getuid(), gid=os.getgid())
    old = folder / "old"
    target.rename(old)
    target.write_text("replacement", encoding="utf-8")
    fixtures.close()
    assert fixtures.errors == [{"scope": "fixture_cleanup", "code": "IDENTITY_CHANGED"}]
    assert target.read_text() == "replacement"


@pytest.mark.skipif(sys.platform != "linux", reason="POSIX report permissions require Linux")
def test_report_is_private_and_rejects_symlink_target(folder, monkeypatch):
    monkeypatch.setattr(verifier, "trusted", lambda path, **kw: Path(path))
    target = folder / "report.json"
    verifier.write_report(target, {"passed": False, "status": "failed"})
    assert json.loads(target.read_text())["passed"] is False
    assert target.stat().st_mode & 0o777 == 0o600
    link = folder / "link"
    link.symlink_to(target)
    with pytest.raises(RunnerError):
        verifier.write_report(link, {"passed": True})
    assert json.loads(target.read_text())["passed"] is False
