"""Diagnose the actual interpreter and fail closed on invalid probe output."""

import os
from pathlib import Path
import subprocess
import sqlite3
import sys

import pytest

from hypershell.runner.client import RunnerError
from hypershell.runner.diagnostics import inspect_python
from hypershell.runner.managed import ManagedRunner


def test_current_interpreter_sqlite_probe():
    report = inspect_python(sys.executable, environment=dict(os.environ))
    connection = sqlite3.connect(":memory:")
    try:
        connection.execute("SELECT name FROM sqlite_schema LIMIT 1")
        expected = True
    except sqlite3.DatabaseError:
        expected = False
    finally:
        connection.close()
    assert report["sqlite_schema_supported"] is expected
    assert report["python"]
    assert "packages" in report


@pytest.mark.parametrize("stdout", ["not json", "[]", '{"sqlite_schema_supported": "yes"}'])
def test_invalid_diagnostic_output_is_rejected(monkeypatch, stdout):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 0, stdout, ""))
    with pytest.raises(RunnerError, match="invalid runtime diagnostic"):
        inspect_python("python", environment={})


@pytest.mark.parametrize("lock_ok", [True, False])
def test_doctor_checks_actual_lock_behavior_with_old_sqlite(monkeypatch, lock_ok):
    runner = object.__new__(ManagedRunner)
    runner.bin, runner.prefix = Path("/runtime/bin"), Path("/runtime")
    runner.dependency_overlay = None
    monkeypatch.setattr(runner, "require_runtime_bundle", lambda: {})
    monkeypatch.setattr(
        "hypershell.runner.diagnostics.inspect_python",
        lambda *a, **k: {"sqlite_schema_supported": False, "sqlite": "3.31.1", "file_lock_compatible": lock_ok},
    )
    report = runner.doctor()
    assert report["ready"] is lock_ok
    assert report["warnings"] == ["SQLITE_SCHEMA_UNSUPPORTED"]
    assert report["blockers"] == ([] if lock_ok else ["APPLICATION_FILE_LOCK_INCOMPATIBLE"])


def test_failed_probe_does_not_echo_dependency_stderr(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: subprocess.CompletedProcess([], 1, "", "SECRET_VALUE"))
    with pytest.raises(RunnerError) as error:
        inspect_python("python", environment={})
    assert "SECRET_VALUE" not in str(error.value)


def test_probe_timeout_is_structured(monkeypatch):
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("python", 60)

    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(RunnerError, match="timed out"):
        inspect_python("python", environment={})


def test_doctor_passes_only_configured_overlay_to_probe(monkeypatch):
    runner = object.__new__(ManagedRunner)
    runner.bin, runner.prefix = Path("/runtime/bin"), Path("/runtime")
    runner.dependency_overlay = Path("/approved/compat")
    monkeypatch.setattr(runner, "require_runtime_bundle", lambda: {})
    monkeypatch.setenv("PYTHONPATH", "/caller-controlled")

    def inspect(executable, *, environment):
        assert environment["PYTHONPATH"] == str(runner.dependency_overlay)
        assert "/caller-controlled" not in environment.values()
        return {"sqlite_schema_supported": True, "file_lock_compatible": True}

    monkeypatch.setattr("hypershell.runner.diagnostics.inspect_python", inspect)
    assert runner.doctor()["ready"] is True
