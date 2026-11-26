"""Read-only runtime compatibility probes; never read application secrets."""

import json
import subprocess

from .client import RunnerError

PYTHON_PROBE = r"""
import importlib.metadata as metadata
import asyncio, contextlib, io, json, pathlib, platform, sqlite3, sys, tempfile
packages = {}
for name in ("openjiuwen", "jiuwenbox", "jiuwenswarm", "filelock", "pysqlite3-binary"):
    try:
        packages[name] = metadata.version(name)
    except metadata.PackageNotFoundError:
        packages[name] = None
connection = sqlite3.connect(":memory:")
try:
    connection.execute("SELECT name FROM sqlite_schema LIMIT 1").fetchall()
    schema_supported = True
except sqlite3.DatabaseError:
    schema_supported = False
finally:
    connection.close()
async def check_lock():
    with tempfile.TemporaryDirectory(prefix="hypershell-doctor-") as folder:
        from openjiuwen.core.sys_operation.local._async_read_write_lock import HybridAsyncReadWriteLock
        lock = HybridAsyncReadWriteLock(pathlib.Path(folder) / "probe.lock")
        try:
            async with lock.write(timeout=3):
                pass
            async with lock.read(timeout=3):
                pass
        finally:
            await lock.close()
try:
    with contextlib.redirect_stdout(io.StringIO()):
        asyncio.run(check_lock())
    lock_supported, lock_error = True, None
except Exception as exc:
    lock_supported, lock_error = False, type(exc).__name__
print(json.dumps({"python": platform.python_version(), "executable": sys.executable,
    "sqlite": sqlite3.sqlite_version, "sqlite_schema_supported": schema_supported,
    "file_lock_compatible": lock_supported, "file_lock_error": lock_error,
    "packages": packages}))
"""


def inspect_python(executable, *, environment):
    try:
        # -P excludes the current directory; PYTHONPATH is supplied only by
        # the administrator-validated runtime overlay, never the caller env.
        result = subprocess.run(
            [str(executable), "-P", "-B", "-c", PYTHON_PROBE],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except subprocess.TimeoutExpired as exc:
        raise RunnerError("runtime diagnostic timed out") from exc
    if result.returncode:
        # Do not echo arbitrary dependency stderr into reports.
        raise RunnerError("runtime diagnostic process failed", exit_code=result.returncode)
    try:
        report = json.loads(result.stdout)
        if (
            not isinstance(report, dict)
            or not isinstance(report.get("sqlite_schema_supported"), bool)
            or not isinstance(report.get("file_lock_compatible"), bool)
        ):
            raise ValueError("invalid diagnostic result")
        return report
    except (ValueError, TypeError) as exc:
        raise RunnerError("invalid runtime diagnostic response") from exc
