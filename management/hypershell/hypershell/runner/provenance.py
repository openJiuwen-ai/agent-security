"""Collect observed runtime identities without reading secrets or importing apps.

This is evidence of the files and interpreter observed at collection time, not a
dependency lock or an immutable deployment attestation. Collection is read-only;
callers own output-file permissions and publication of the resulting manifest.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
from typing import Mapping

from .. import __version__

PACKAGES = ("jiuwenbox", "jiuwenswarm", "openjiuwen", "PyYAML", "filelock", "pysqlite3-binary")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}\Z")
_CODE_SUFFIXES = frozenset({".py", ".toml", ".html"})
_CODE_EXCLUDED_DIRECTORIES = frozenset(
    {
        "__pycache__",
        "node_modules",
        "venv",
        "env",
        "site-packages",
        "tests",
        "test",
        "data",
        "home",
        "logs",
        "backups",
        "dist",
        "build",
        "htmlcov",
    }
)
_INTERPRETER_PROBE_HELPERS = r"""
import importlib.metadata as metadata
import importlib.util
import hashlib, json, os, pathlib, platform, re, stat, sys

MAX_CODE_FILES = 20000
MAX_CODE_BYTES = 256 * 1024 * 1024
MAX_CODE_ENTRIES = 100000
MAX_DISTRIBUTIONS = 10000
CODE_SUFFIXES = (".py", ".so", ".pyd", ".dll", ".dylib")
EXCLUDED_DIRS = {"__pycache__", "node_modules", "venv", "env", "site-packages",
                 "tests", "test", "data", "home", "logs", "backups", "dist", "build"}
VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}\Z")
NAME_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?\Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class ProbeLimit(Exception):
    pass


def backend_code_identity():
    result = {"status": "unknown", "sha256": None, "files": 0, "bytes": 0,
              "roots": [], "unavailable_files": 0,
              "scope": "jiuwenbox import roots; source/native code only; no symlinks, data or caches",
              "limits": {"files": MAX_CODE_FILES, "bytes": MAX_CODE_BYTES, "entries": MAX_CODE_ENTRIES}}
    try:
        # A top-level find_spec consults the actual interpreter's import path
        # (including editable installs) without importing jiuwenbox itself.
        spec = importlib.util.find_spec("jiuwenbox")
        if spec is None:
            result["error"] = "backend_not_found"
            return result
        locations = spec.submodule_search_locations
        is_package = locations is not None
        raw_roots = list(locations) if is_package else ([spec.origin] if spec.origin else [])
        if not raw_roots or len(raw_roots) > 64 or any(not isinstance(item, str) for item in raw_roots):
            result["error"] = "backend_roots_unavailable"
            return result
        roots = sorted({pathlib.Path(os.path.abspath(item)) for item in raw_roots}, key=str)
        result["roots"] = [str(root) for root in roots]
        records = []
        entries = 0
        candidates = 0

        def unavailable(path, code):
            result["unavailable_files"] += 1
            result.setdefault("error", code)
            records.append({"path": path, "error": code})

        def code_name(name):
            return (not name.startswith(".") and
                    (name.lower().endswith(CODE_SUFFIXES) or re.search(r"\.so(?:\.\d+)+$", name.lower()) is not None))

        def hash_file(path, label):
            nonlocal candidates
            candidates += 1
            if candidates > MAX_CODE_FILES:
                raise ProbeLimit("file_limit")
            descriptor = None
            try:
                before = path.lstat()
                if not stat.S_ISREG(before.st_mode):
                    unavailable(label, "non_regular_code_file")
                    return
                if before.st_size > MAX_CODE_BYTES - result["bytes"]:
                    raise ProbeLimit("byte_limit")
                flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
                descriptor = os.open(path, flags, 0o700)
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or
                        (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)):
                    unavailable(label, "code_file_changed")
                    return
                digest = hashlib.sha256()
                while True:
                    remaining = MAX_CODE_BYTES - result["bytes"]
                    chunk = os.read(descriptor, min(1024 * 1024, remaining + 1))
                    if not chunk:
                        break
                    if len(chunk) > remaining:
                        raise ProbeLimit("byte_limit")
                    result["bytes"] += len(chunk)
                    digest.update(chunk)
                after = os.fstat(descriptor)
                if ((opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) !=
                        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
                    unavailable(label, "code_file_changed")
                    return
                records.append({"path": label, "sha256": digest.hexdigest(), "bytes": after.st_size})
                result["files"] += 1
            except OSError:
                unavailable(label, "unreadable_code_file")
            finally:
                if descriptor is not None:
                    os.close(descriptor)

        for index, root in enumerate(roots):
            try:
                root_info = root.lstat()
                if root.resolve() != root or stat.S_ISLNK(root_info.st_mode):
                    unavailable(str(index), "symlinked_backend_root")
                    continue
                if not is_package:
                    if code_name(root.name):
                        hash_file(root, str(index) + "/" + root.name)
                    else:
                        unavailable(str(index), "unsupported_backend_origin")
                    continue
                if not stat.S_ISDIR(root_info.st_mode):
                    unavailable(str(index), "backend_root_not_directory")
                    continue
                pending = [root]
                while pending:
                    directory = pending.pop()
                    children = []
                    try:
                        with os.scandir(directory) as listing:
                            for child in listing:
                                entries += 1
                                if entries > MAX_CODE_ENTRIES:
                                    raise ProbeLimit("entry_limit")
                                children.append(child)
                    except OSError:
                        label = str(index) + "/" + directory.relative_to(root).as_posix()
                        unavailable(label, "unreadable_code_directory")
                        continue
                    for child in sorted(children, key=lambda item: item.name, reverse=True):
                        if child.name.startswith(".") or child.name.lower() in EXCLUDED_DIRS:
                            continue
                        path = pathlib.Path(child.path)
                        label = str(index) + "/" + path.relative_to(root).as_posix()
                        try:
                            if child.is_symlink():
                                # Do not inspect the target to determine its type.
                                unavailable(label, "code_symlink")
                            elif child.is_dir(follow_symlinks=False):
                                pending.append(path)
                            elif code_name(child.name):
                                hash_file(path, label)
                        except OSError:
                            unavailable(label, "unreadable_code_entry")
            except OSError:
                unavailable(str(index), "backend_root_unavailable")
        if not result["files"]:
            result.setdefault("error", "no_backend_code_files")
            return result
        result["status"] = "incomplete" if result["unavailable_files"] else "ok"
        result["sha256"] = hashlib.sha256(canonical(sorted(records, key=lambda item: item["path"]))).hexdigest()
    except ProbeLimit as exc:
        result["status"] = "incomplete"
        result["error"] = str(exc)
        result["sha256"] = None
    except Exception:
        result["status"] = "unknown"
        result["sha256"] = None
        result["error"] = "backend_inspection_failed"
    return result


def distributions_identity():
    result = {"status": "unknown", "count": 0, "sha256": None, "entries": [],
              "unavailable_entries": 0, "limit": MAX_DISTRIBUTIONS,
              "scope": "PEP 503 normalized name and validated metadata version only"}
    try:
        entries = []
        for index, distribution in enumerate(metadata.distributions()):
            if index >= MAX_DISTRIBUTIONS:
                result.update(status="incomplete", error="distribution_limit")
                return result
            try:
                name, version = distribution.metadata.get("Name"), distribution.version
                if (not isinstance(name, str) or NAME_PATTERN.fullmatch(name) is None or
                        not isinstance(version, str) or VERSION_PATTERN.fullmatch(version) is None):
                    raise ValueError()
                entries.append({"name": re.sub(r"[-_.]+", "-", name).lower(), "version": version})
            except Exception:
                result["unavailable_entries"] += 1
        entries.sort(key=lambda entry: (entry["name"], entry["version"]))
        result.update(status="incomplete" if result["unavailable_entries"] else "ok", entries=entries,
                      count=len(entries), sha256=hashlib.sha256(canonical(entries)).hexdigest())
    except Exception:
        result["error"] = "distribution_inspection_failed"
    return result
"""
_METADATA_PROBE = _INTERPRETER_PROBE_HELPERS + r"""
packages = {}
for name in ("jiuwenbox", "jiuwenswarm", "openjiuwen", "PyYAML", "filelock", "pysqlite3-binary"):
    try:
        packages[name] = {"status": "installed", "version": metadata.version(name)}
    except metadata.PackageNotFoundError:
        packages[name] = {"status": "not_installed", "version": None}
    except Exception:
        packages[name] = {"status": "unknown", "version": None}
print(json.dumps({"python": {"version": platform.python_version(),
    "implementation": platform.python_implementation(), "executable": sys.executable},
    "packages": packages, "backend_code": backend_code_identity(),
    "distributions": distributions_identity()}))
"""


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _file_identity(path: Path) -> dict:
    result = {"path": str(path), "status": "unknown", "sha256": None}
    try:
        mode = path.lstat().st_mode
        if not stat.S_ISREG(mode):
            result["error"] = "not_a_regular_file"
        else:
            result.update(status="ok", sha256=_sha256(path))
    except FileNotFoundError:
        result["error"] = "missing"
    except OSError:
        result["error"] = "unreadable"
    return result


def _subprocess_environment() -> dict[str, str]:
    # No model credentials, PYTHONPATH, user Git configuration overrides or
    # arbitrary caller environment are needed by these read-only probes.
    allowed = {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "LC_CTYPE"}
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


GIT = shutil.which("git")


def _git(root: Path, *arguments: str) -> subprocess.CompletedProcess:
    if GIT is None:
        raise FileNotFoundError("git executable was not found")
    environment = _subprocess_environment()
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["GIT_NO_LAZY_FETCH"] = "1"
    return subprocess.run(
        [str(Path(GIT).absolute()), "-c", "core.fsmonitor=false", "-C", str(root), *arguments],
        capture_output=True,
        env=environment,
        timeout=15,
        check=False,
    )


def _source_identity(directory: Path) -> dict:
    result = {
        "path": str(directory),
        "status": "unknown",
        "commit": None,
        "dirty": None,
        "dirty_scope": "tracked_files",
        "tracked_sha256": None,
        "untracked_files_included": False,
        "tracked_hash_scope": "source .py/.toml/.html files",
    }
    try:
        location = _git(directory, "rev-parse", "--show-toplevel")
        if location.returncode:
            result["error"] = "not_a_git_checkout"
            return result
        root = Path(os.fsdecode(location.stdout.rstrip(b"\r\n")))
        result["repository_root"] = str(root)
        commit = _git(root, "rev-parse", "--verify", "HEAD")
        identity = commit.stdout.strip().decode("ascii", errors="replace")
        if commit.returncode or not re.fullmatch(r"[0-9a-fA-F]{40,64}", identity):
            result["error"] = "git_head_unavailable"
            return result
        result["commit"] = identity.lower()
        changes = _git(root, "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--")
        if changes.returncode not in (0, 1):
            result["error"] = "git_dirty_check_failed"
            return result
        result["dirty"] = changes.returncode == 1
        listing = _git(root, "ls-files", "--cached", "-z")
        if listing.returncode:
            result["error"] = "git_tracked_files_unavailable"
            return result
        records = []
        incomplete = 0
        # Paths are used only for hashing within the repository; no Git output
        # or file contents are copied into error messages.
        for raw_name in sorted(set(listing.stdout.split(b"\0")) - {b""}):
            name = os.fsdecode(raw_name)
            relative = Path(name)
            # Source identity must never open a tracked .env, credential file or
            # session database merely because it was accidentally committed.
            if relative.suffix.lower() not in _CODE_SUFFIXES:
                continue
            if relative.is_absolute() or ".." in relative.parts:
                records.append({"path": name, "status": "invalid_path"})
                incomplete += 1
                continue
            item = _file_identity(root / relative)
            records.append({"path": name, "status": item["status"], "sha256": item["sha256"]})
            if item["status"] != "ok":
                incomplete += 1
        result.update(
            status="incomplete" if incomplete else "ok",
            tracked_files=len(records),
            unavailable_files=incomplete,
            tracked_sha256=hashlib.sha256(_canonical(records)).hexdigest(),
        )
    except FileNotFoundError:
        result["error"] = "git_unavailable"
    except subprocess.TimeoutExpired:
        result["error"] = "git_timeout"
    except (OSError, ValueError):
        result["error"] = "source_inspection_failed"
    return result


def _code_identity(directory: Path, package_directories: tuple[str, ...]) -> dict:
    """Hash deployed source bytes independently of Git, including new modules.

    Only known package roots and the root pyproject are considered. Directory
    links and file links are reported as unavailable, never followed; runtime
    data, credential files and caches are outside this source-only scope.
    """
    result = {
        "path": str(directory),
        "status": "unknown",
        "sha256": None,
        "files": 0,
        "unavailable_files": 0,
        "scope": {
            "package_roots": list(package_directories),
            "root_files": ["pyproject.toml"],
            "suffixes": sorted(_CODE_SUFFIXES),
            "excluded_directories": sorted(_CODE_EXCLUDED_DIRECTORIES),
            "exclude_dot_directories": True,
            "follow_symlinks": False,
        },
    }
    try:
        root_mode = directory.lstat().st_mode
        if not stat.S_ISDIR(root_mode):
            result["error"] = "source_root_is_not_a_regular_directory"
            return result
        records = []
        unavailable = 0
        found_packages = 0
        missing_roots = []

        def add_file(path: Path) -> None:
            nonlocal unavailable
            identity = _file_identity(path)
            record = {
                "path": path.relative_to(directory).as_posix(),
                "status": identity["status"],
                "sha256": identity["sha256"],
            }
            if identity["status"] != "ok":
                record["error"] = identity.get("error", "unavailable")
                unavailable += 1
            records.append(record)

        def walking_error(_error) -> None:
            nonlocal unavailable
            unavailable += 1

        add_file(directory / "pyproject.toml")
        for name in package_directories:
            package = directory / name
            try:
                mode = package.lstat().st_mode
            except FileNotFoundError:
                missing_roots.append(name)
                continue
            if not stat.S_ISDIR(mode):
                records.append({"path": name, "status": "unknown", "error": "package_root_is_not_a_regular_directory"})
                unavailable += 1
                continue
            found_packages += 1
            for folder, directories, files in os.walk(package, followlinks=False, onerror=walking_error):
                directories[:] = sorted(
                    child
                    for child in directories
                    if not child.startswith(".") and child.lower() not in _CODE_EXCLUDED_DIRECTORIES
                )
                for child in list(directories):
                    candidate = Path(folder) / child
                    if candidate.is_symlink():
                        directories.remove(child)
                        records.append(
                            {
                                "path": candidate.relative_to(directory).as_posix(),
                                "status": "unknown",
                                "error": "directory_symlink",
                            }
                        )
                        unavailable += 1
                for child in sorted(files):
                    candidate = Path(folder) / child
                    if not child.startswith(".") and candidate.suffix.lower() in _CODE_SUFFIXES:
                        add_file(candidate)
        result.update(
            files=sum(record.get("status") == "ok" for record in records),
            unavailable_files=unavailable,
            missing_package_roots=missing_roots,
        )
        if not found_packages or not any(
            record.get("status") == "ok" and record["path"].endswith(".py") for record in records
        ):
            result["error"] = "package_source_unavailable"
            return result
        result.update(
            status="incomplete" if unavailable else "ok",
            sha256=hashlib.sha256(_canonical(sorted(records, key=lambda item: item["path"]))).hexdigest(),
        )
    except FileNotFoundError:
        result["error"] = "missing_source_root"
    except (OSError, ValueError):
        result["error"] = "code_inspection_failed"
    return result


def _overlay_identity(path: Path | None) -> dict | None:
    if path is None:
        return None
    try:
        mode = path.lstat().st_mode
        if stat.S_ISREG(mode):
            return {"kind": "file", **_file_identity(path)}
        if not stat.S_ISDIR(mode):
            return {"path": str(path), "status": "unknown", "error": "not_a_regular_file_or_directory"}
        records = []
        incomplete = False

        def walking_error(_error):
            nonlocal incomplete
            incomplete = True

        for folder, directories, files in os.walk(path, followlinks=False, onerror=walking_error):
            # Bytecode is generated by interpreter activity, not an overlay's
            # source identity. Never follow links into external trees.
            directories[:] = sorted(name for name in directories if name != "__pycache__")
            for name in list(directories):
                candidate = Path(folder) / name
                if candidate.is_symlink():
                    directories.remove(name)
                    records.append({"path": candidate.relative_to(path).as_posix(), "status": "symlink"})
                    incomplete = True
            for name in sorted(files):
                if name.endswith((".pyc", ".pyo")):
                    continue
                candidate = Path(folder) / name
                item = _file_identity(candidate)
                records.append(
                    {"path": candidate.relative_to(path).as_posix(), "status": item["status"], "sha256": item["sha256"]}
                )
                incomplete |= item["status"] != "ok"
        return {
            "path": str(path),
            "kind": "directory",
            "status": "incomplete" if incomplete else "ok",
            "files": len(records),
            "sha256": hashlib.sha256(_canonical(sorted(records, key=lambda r: r["path"]))).hexdigest(),
            "excluded": ["__pycache__", "*.pyc", "*.pyo"],
        }
    except FileNotFoundError:
        return {"path": str(path), "status": "unknown", "error": "missing"}
    except (OSError, ValueError):
        return {"path": str(path), "status": "unknown", "error": "overlay_inspection_failed"}


def _validate_backend_code(value: object) -> dict:
    expected = {"status", "sha256", "files", "bytes", "roots", "unavailable_files", "scope", "limits"}
    if not isinstance(value, dict) or not expected <= value.keys() or value.keys() - expected - {"error"}:
        raise ValueError("invalid backend identity fields")
    if value["status"] not in {"ok", "incomplete", "unknown"}:
        raise ValueError("invalid backend identity status")
    for field, maximum in (("files", 20000), ("bytes", 256 * 1024 * 1024), ("unavailable_files", 100000)):
        if type(value[field]) is not int or not 0 <= value[field] <= maximum:
            raise ValueError("invalid backend identity counts")
    if value["limits"] != {"files": 20000, "bytes": 256 * 1024 * 1024, "entries": 100000}:
        raise ValueError("invalid backend identity limits")
    if (
        not isinstance(value["roots"], list)
        or len(value["roots"]) > 64
        or any(not isinstance(root, str) or not root or len(root) > 4096 or "\x00" in root for root in value["roots"])
    ):
        raise ValueError("invalid backend identity roots")
    if value["scope"] != "jiuwenbox import roots; source/native code only; no symlinks, data or caches":
        raise ValueError("invalid backend identity scope")
    digest = value["sha256"]
    if digest is not None and (not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None):
        raise ValueError("invalid backend identity digest")
    has_complete_inventory = bool(digest) and value["files"] > 0
    has_errors = value["unavailable_files"] > 0 or "error" in value
    if value["status"] == "ok" and (not has_complete_inventory or has_errors):
        raise ValueError("backend identity is not complete")
    if value["status"] == "unknown" and digest is not None:
        raise ValueError("unknown backend identity cannot have a complete digest")
    if "error" in value and value["error"] not in {
        "backend_not_found",
        "backend_roots_unavailable",
        "non_regular_code_file",
        "code_file_changed",
        "unreadable_code_file",
        "symlinked_backend_root",
        "unsupported_backend_origin",
        "backend_root_not_directory",
        "unreadable_code_directory",
        "code_symlink",
        "unreadable_code_entry",
        "backend_root_unavailable",
        "no_backend_code_files",
        "file_limit",
        "byte_limit",
        "entry_limit",
        "backend_inspection_failed",
    }:
        raise ValueError("invalid backend identity error")
    return value


def _validate_distributions(value: object) -> dict:
    expected = {"status", "count", "sha256", "entries", "unavailable_entries", "limit", "scope"}
    if not isinstance(value, dict) or not expected <= value.keys() or value.keys() - expected - {"error"}:
        raise ValueError("invalid distribution identity fields")
    if value["status"] not in {"ok", "incomplete", "unknown"} or value["limit"] != 10000:
        raise ValueError("invalid distribution identity status")
    if value["scope"] != "PEP 503 normalized name and validated metadata version only":
        raise ValueError("invalid distribution identity scope")
    entries = value["entries"]
    count = value["count"]
    unavailable = value["unavailable_entries"]
    if not isinstance(entries, list) or type(count) is not int or type(unavailable) is not int:
        raise ValueError("invalid distribution identity counts")
    if not 0 <= count == len(entries) <= 10000 or not 0 <= unavailable <= 10000:
        raise ValueError("invalid distribution identity counts")
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"name", "version"}:
            raise ValueError("invalid distribution identity entry")
        name, version = entry["name"], entry["version"]
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("invalid distribution name/version")
        normalized_name = re.sub(r"[-_.]+", "-", name).lower()
        if (
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?", name) is None
            or name != normalized_name
            or _VERSION.fullmatch(version) is None
        ):
            raise ValueError("invalid distribution name/version")
    if entries != sorted(entries, key=lambda entry: (entry["name"], entry["version"])):
        raise ValueError("distribution identity is not canonical")
    digest = value["sha256"]
    if digest is not None and digest != hashlib.sha256(_canonical(entries)).hexdigest():
        raise ValueError("invalid distribution identity digest")
    has_errors = unavailable > 0 or "error" in value
    if value["status"] == "ok" and (digest is None or has_errors):
        raise ValueError("distribution identity is not complete")
    if value["status"] == "unknown" and (digest is not None or entries):
        raise ValueError("unknown distribution identity cannot be complete")
    if "error" in value and value["error"] not in {"distribution_limit", "distribution_inspection_failed"}:
        raise ValueError("invalid distribution identity error")
    return value


def _application_identity(executable: Path) -> dict:
    result = {"requested_executable": str(executable), "status": "unknown"}
    try:
        probe = subprocess.run(
            [str(executable), "-I", "-B", "-c", _METADATA_PROBE],
            env=_subprocess_environment(),
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
        if probe.returncode:
            return {**result, "error": "interpreter_probe_failed", "exit_code": probe.returncode}
        payload = json.loads(probe.stdout)
        if not isinstance(payload, dict) or set(payload) != {"python", "packages", "backend_code", "distributions"}:
            raise ValueError("invalid interpreter response fields")
        python = payload["python"]
        if (
            not isinstance(python, dict)
            or set(python) != {"version", "implementation", "executable"}
            or not all(isinstance(value, str) and value for value in python.values())
        ):
            raise ValueError("invalid interpreter fields")
        packages = payload["packages"]
        if not isinstance(packages, dict) or set(packages) != set(PACKAGES):
            raise ValueError("invalid package fields")
        for entry in packages.values():
            if not isinstance(entry, dict) or set(entry) != {"status", "version"}:
                raise ValueError("invalid package entry")
            if entry["status"] == "installed":
                if not isinstance(entry["version"], str) or not _VERSION.fullmatch(entry["version"]):
                    raise ValueError("invalid package version")
            elif entry["status"] not in {"not_installed", "unknown"} or entry["version"] is not None:
                raise ValueError("invalid package status")
        return {
            **result,
            "status": "ok",
            "python": python,
            "packages": packages,
            "backend_code": _validate_backend_code(payload["backend_code"]),
            "distributions": _validate_distributions(payload["distributions"]),
        }
    except FileNotFoundError:
        return {**result, "error": "interpreter_unavailable"}
    except subprocess.TimeoutExpired:
        return {**result, "error": "interpreter_probe_timeout"}
    except (OSError, UnicodeError):
        return {**result, "error": "interpreter_probe_failed"}
    except (ValueError, TypeError, KeyError):
        return {**result, "error": "invalid_interpreter_response"}


def collect_manifest(
    *,
    config_path: Path,
    runtime_path: Path,
    request_paths: Mapping[str, Path],
    application_python: Path,
    source_dir: Path,
    dependency_overlay: Path | None = None,
    hypershell_root: Path | None = None,
) -> dict:
    """Return canonicalizable observed identities; never write files or start apps.

    ``source_dir`` is the JiuwenSwarm application source directory, while
    ``hypershell_root`` defaults to this package's checkout root. Git identity
    covers tracked files only; ignored/untracked test output cannot mark it dirty.
    Independent ``code`` inventories cover deployed package source, including
    untracked modules and copies without Git. Unknown identities remain explicit,
    not assumed clean or replaced by the collector's own repository identity.
    """
    root = Path(hypershell_root) if hypershell_root is not None else Path(__file__).resolve().parents[2]
    manifest = {
        "schema_version": 1,
        "kind": "observed",
        "scope": "Observed versions and file hashes; not a lockfile or immutable deployment attestation.",
        "hypershell": {
            "version": __version__,
            "source": _source_identity(root),
            "code": _code_identity(root, ("hypershell",)),
        },
        "collector_python": {
            "version": platform.python_version(),
            "executable": sys.executable,
            "implementation": platform.python_implementation(),
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        },
        "application": {
            "source": _source_identity(Path(source_dir)),
            "code": _code_identity(Path(source_dir), ("jiuwenswarm", "src")),
            "interpreter": _application_identity(Path(application_python)),
        },
        "configuration": {
            "admin": _file_identity(Path(config_path)),
            "runtime": _file_identity(Path(runtime_path)),
            "requests": {user: _file_identity(Path(path)) for user, path in sorted(request_paths.items())},
        },
        "dependency_overlay": _overlay_identity(Path(dependency_overlay) if dependency_overlay is not None else None),
    }
    manifest["manifest_digest"] = hashlib.sha256(_canonical(manifest)).hexdigest()
    return manifest
