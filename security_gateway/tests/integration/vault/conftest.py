"""Shared helpers for the cross-process vault tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

WORKER = Path(__file__).with_name("_worker.py")


def _env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    return env


def _command(*args: object) -> list[str]:
    return [sys.executable, "-u", str(WORKER), *(str(arg) for arg in args)]


def run_worker(*args: object, timeout: float = 60.0) -> dict:
    """Run a worker to completion and return its JSON result."""
    proc = subprocess.run(
        _command(*args),
        check=False,
        capture_output=True,
        text=True,
        env=_env(),
        timeout=timeout,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"worker {args!r} failed with {proc.returncode}\n"
            f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
        )
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if not lines:
        raise AssertionError(f"worker {args!r} wrote no JSON\nstderr: {proc.stderr}")
    return json.loads(lines[-1])


def start_worker(*args: object) -> subprocess.Popen[str]:
    """Start a worker that stays alive until the test releases it."""
    return subprocess.Popen(
        _command(*args),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_env(),
    )


def finish_worker(proc: subprocess.Popen[str], timeout: float = 60.0) -> dict:
    """Wait for a worker and return its JSON result."""
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        proc.kill()
        stdout, stderr = proc.communicate()
        raise AssertionError(
            f"worker timed out\nstdout: {stdout}\nstderr: {stderr}"
        ) from exc
    if proc.returncode != 0:
        raise AssertionError(
            f"worker failed with {proc.returncode}\n--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
        )
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        raise AssertionError(f"worker wrote no JSON\nstderr: {stderr}")
    return json.loads(lines[-1])


def wait_for(path: Path, timeout: float = 30.0) -> None:
    """Wait until a worker-created marker file exists."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path}")


@pytest.fixture()
def data_dir(tmp_path: Path) -> Path:
    """A fresh data directory whose parents are not group/world writable."""
    path = tmp_path / "vault-data"
    path.mkdir(mode=0o700)
    return path


@pytest.fixture()
def control_dir(tmp_path: Path) -> Path:
    """Where tests and workers drop the markers they synchronise on."""
    path = tmp_path / "control"
    path.mkdir(mode=0o700)
    return path
