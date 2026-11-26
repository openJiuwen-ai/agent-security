"""Capture and check an explicit baseline of the observed runtime coverage.

This detects changes to measured components. It is neither a dependency lock
nor an immutable deployment or signature, and never starts/stops a workspace.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

from ..config import AdminConfig, _path, load_document
from ..console import log_console
from ..policy import LaunchRequest
from .boundary_verify import write_report
from .client import RunnerError
from .managed import require_admin, trusted
from .provenance import PACKAGES, collect_manifest, _validate_backend_code, _validate_distributions

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_USER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+!_-]{0,127}\Z")
MAX_BASELINE_BYTES = 4 * 1024 * 1024
LIMITATIONS = [
    "Only the explicitly observed code and version coverage is pinned.",
    "Node/TUI JavaScript, interpreter binaries and non-backend dependency payloads are not fully hashed.",
    "A matching baseline does not enforce ownership, immutability or eliminate hash-to-execution races.",
    "This is not a lockfile, signature, sandbox acceptance or production certification.",
]


class BaselineError(RunnerError):
    code = "BASELINE_ERROR"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value):
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise BaselineError("required SHA-256 identity is unavailable")
    return value


def _mapping(value):
    if not isinstance(value, dict):
        raise BaselineError("runtime identity must be a structured object")
    return value


def _record(value, *, code=False):
    value = _mapping(value)
    if value.get("status") != "ok":
        raise BaselineError("required runtime identity is unknown or incomplete")
    if code:
        files, unavailable = value.get("files"), value.get("unavailable_files")
        if type(files) is not int or type(unavailable) is not int:
            raise BaselineError("required source inventory is incomplete")
        if files <= 0 or unavailable != 0:
            raise BaselineError("required source inventory is incomplete")
    return _sha(value.get("sha256"))


def _python(value):
    value = _mapping(value)
    result = {key: value.get(key) for key in ("version", "implementation")}
    if any(not isinstance(item, str) or not _VERSION.fullmatch(item) for item in result.values()):
        raise BaselineError("interpreter version identity is incomplete")
    return result


def _packages(value):
    value = _mapping(value)
    if set(value) != set(PACKAGES):
        raise BaselineError("package version coverage differs from the supported schema")
    result = {}
    for name, entry in sorted(value.items()):
        entry = _mapping(entry)
        if set(entry) != {"status", "version"}:
            raise BaselineError("invalid package version record")
        status, version = entry["status"], entry["version"]
        if status == "installed":
            if not isinstance(version, str) or not _VERSION.fullmatch(version):
                raise BaselineError("invalid installed package version")
        elif status != "not_installed" or version is not None:
            raise BaselineError("unknown package versions cannot be frozen")
        result[name] = {"status": status, "version": version}
    return result


def fingerprint_from_manifest(manifest):
    manifest = _mapping(manifest)
    if (
        type(manifest.get("schema_version")) is not int
        or manifest["schema_version"] != 1
        or manifest.get("kind") != "observed"
    ):
        raise BaselineError("unsupported observed manifest")
    if _sha(manifest.get("manifest_digest")) != _digest({k: v for k, v in manifest.items() if k != "manifest_digest"}):
        raise BaselineError("observed manifest digest mismatch")
    application = _mapping(manifest.get("application"))
    interpreter = _mapping(application.get("interpreter"))
    if interpreter.get("status") != "ok":
        raise BaselineError("application interpreter observation is incomplete")
    try:
        distributions = _validate_distributions(interpreter.get("distributions"))
        backend = _validate_backend_code(interpreter.get("backend_code"))
    except (TypeError, ValueError) as exc:
        raise BaselineError("interpreter code or distribution evidence is internally inconsistent") from exc
    if distributions["status"] != "ok" or distributions["count"] <= 0 or distributions["unavailable_entries"] != 0:
        raise BaselineError("installed distribution observation is incomplete")
    configuration = _mapping(manifest.get("configuration"))
    requests = _mapping(configuration.get("requests"))
    if not requests or any(not isinstance(uid, str) or not _USER.fullmatch(uid) for uid in requests):
        raise BaselineError("a nonempty explicit user/request set is required")
    hypershell = _mapping(manifest.get("hypershell"))
    version = hypershell.get("version")
    if not isinstance(version, str) or not _VERSION.fullmatch(version):
        raise BaselineError("HyperShell version identity is incomplete")
    platform = _mapping(manifest.get("platform"))
    platform = {key: platform.get(key) for key in ("system", "release", "version", "machine")}
    if any(not isinstance(value, str) or not value or len(value) > 4096 for value in platform.values()):
        raise BaselineError("platform identity is incomplete")
    if "dependency_overlay" not in manifest:
        raise BaselineError("dependency overlay state is unknown")
    overlay = manifest["dependency_overlay"]
    if overlay is not None:
        overlay = _mapping(overlay)
        if overlay.get("kind") not in {"file", "directory"}:
            raise BaselineError("unsupported dependency overlay identity")
        overlay = {"kind": overlay["kind"], "sha256": _record(overlay)}
    code_scopes = {}
    for name, record in (("hypershell", hypershell.get("code")), ("application", application.get("code"))):
        scope = _mapping(_mapping(record).get("scope"))
        code_scopes[name] = _digest(scope)
    if not isinstance(backend.get("scope"), str) or not backend["scope"] or not isinstance(backend.get("limits"), dict):
        raise BaselineError("backend code coverage is incomplete")
    code_scopes["backend"] = _digest({"scope": backend["scope"], "limits": backend["limits"]})
    return {
        "coverage_version": 1,
        "hypershell_version": version,
        "hypershell_code_sha256": _record(hypershell.get("code"), code=True),
        "application_code_sha256": _record(application.get("code"), code=True),
        "backend_code_sha256": _record(interpreter.get("backend_code"), code=True),
        "distributions_sha256": _sha(distributions.get("sha256")),
        "distribution_count": distributions["count"],
        "code_scopes": code_scopes,
        "application_python": _python(interpreter.get("python")),
        "controller_python": _python(manifest.get("collector_python")),
        "packages": _packages(interpreter.get("packages")),
        "platform": platform,
        "configuration": {
            "admin": _record(configuration.get("admin")),
            "runtime": _record(configuration.get("runtime")),
            "requests": {uid: _record(record) for uid, record in sorted(requests.items())},
        },
        "overlay": overlay,
    }


def make_baseline(manifest):
    fingerprint = fingerprint_from_manifest(manifest)
    baseline = {
        "schema_version": 1,
        "kind": "observed_runtime_baseline",
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "fingerprint": fingerprint,
        "fingerprint_digest": _digest(fingerprint),
        "observed_manifest": json.loads(_canonical(manifest)),
        "observed_manifest_digest": manifest["manifest_digest"],
        "limitations": list(LIMITATIONS),
    }
    baseline["baseline_digest"] = _digest(baseline)
    if len(_canonical(baseline)) > MAX_BASELINE_BYTES:
        raise BaselineError("baseline exceeds the supported document size")
    return baseline


def _validate_fingerprint(value):
    value = _mapping(value)
    expected = {
        "coverage_version",
        "hypershell_version",
        "hypershell_code_sha256",
        "application_code_sha256",
        "backend_code_sha256",
        "distributions_sha256",
        "distribution_count",
        "code_scopes",
        "application_python",
        "controller_python",
        "packages",
        "platform",
        "configuration",
        "overlay",
    }
    if set(value) != expected or type(value["coverage_version"]) is not int or value["coverage_version"] != 1:
        raise BaselineError("unsupported baseline fingerprint schema")
    if not isinstance(value["hypershell_version"], str) or not _VERSION.fullmatch(value["hypershell_version"]):
        raise BaselineError("invalid baseline project version")
    for key in ("hypershell_code_sha256", "application_code_sha256", "backend_code_sha256", "distributions_sha256"):
        _sha(value[key])
    if type(value["distribution_count"]) is not int or value["distribution_count"] <= 0:
        raise BaselineError("invalid baseline distribution count")
    scopes = _mapping(value["code_scopes"])
    if set(scopes) != {"hypershell", "application", "backend"}:
        raise BaselineError("invalid code coverage schema")
    for digest in scopes.values():
        _sha(digest)
    for name in ("application_python", "controller_python"):
        if set(_mapping(value[name])) != {"version", "implementation"}:
            raise BaselineError("invalid baseline interpreter schema")
        _python(value[name])
    _packages(value["packages"])
    platform = _mapping(value["platform"])
    if set(platform) != {"system", "release", "version", "machine"} or any(
        not isinstance(v, str) or not v or len(v) > 4096 for v in platform.values()
    ):
        raise BaselineError("invalid baseline platform")
    config = _mapping(value["configuration"])
    if set(config) != {"admin", "runtime", "requests"}:
        raise BaselineError("invalid baseline configuration coverage")
    _sha(config["admin"])
    _sha(config["runtime"])
    requests = _mapping(config["requests"])
    if not requests or any(not isinstance(uid, str) or not _USER.fullmatch(uid) for uid in requests):
        raise BaselineError("invalid baseline request set")
    for digest in requests.values():
        _sha(digest)
    if value["overlay"] is not None:
        overlay = _mapping(value["overlay"])
        if set(overlay) != {"kind", "sha256"} or overlay["kind"] not in {"file", "directory"}:
            raise BaselineError("invalid baseline overlay")
        _sha(overlay["sha256"])
    return value


def validate_baseline(baseline):
    baseline = _mapping(baseline)
    fields = {
        "schema_version",
        "kind",
        "captured_at",
        "fingerprint",
        "fingerprint_digest",
        "observed_manifest",
        "observed_manifest_digest",
        "limitations",
        "baseline_digest",
    }
    if set(baseline) != fields:
        raise BaselineError("unsupported baseline document")
    version = baseline["schema_version"]
    if type(version) is not int or version != 1 or baseline["kind"] != "observed_runtime_baseline":
        raise BaselineError("unsupported baseline document")
    if baseline["limitations"] != LIMITATIONS:
        raise BaselineError("unsupported baseline document")
    try:
        if (
            not isinstance(baseline["captured_at"], str)
            or datetime.fromisoformat(baseline["captured_at"]).tzinfo is None
        ):
            raise ValueError
    except ValueError as exc:
        raise BaselineError("invalid baseline capture time") from exc
    _sha(baseline["observed_manifest_digest"])
    if _sha(baseline["baseline_digest"]) != _digest({k: v for k, v in baseline.items() if k != "baseline_digest"}):
        raise BaselineError("baseline document digest mismatch")
    fingerprint = _validate_fingerprint(baseline["fingerprint"])
    if _sha(baseline["fingerprint_digest"]) != _digest(fingerprint):
        raise BaselineError("baseline fingerprint digest mismatch")
    observation = _mapping(baseline["observed_manifest"])
    if (
        observation.get("manifest_digest") != baseline["observed_manifest_digest"]
        or fingerprint_from_manifest(observation) != fingerprint
    ):
        raise BaselineError("baseline reference differs from its recorded observation")
    return baseline


def compare_baseline(baseline, manifest):
    baseline = validate_baseline(baseline)
    actual = fingerprint_from_manifest(manifest)
    differences = []

    def visit(expected, observed, path):
        if isinstance(expected, dict) and isinstance(observed, dict):
            for key in sorted(expected.keys() | observed.keys()):
                visit(expected.get(key), observed.get(key), path + "." + key if path else key)
        elif type(expected) is not type(observed) or expected != observed:
            differences.append({"field": path, "expected": expected, "actual": observed})

    visit(baseline["fingerprint"], actual, "")
    return {
        "schema_version": 1,
        "kind": "runtime_baseline_check",
        "matched": not differences,
        "status": "matched" if not differences else "drift",
        "baseline_digest": baseline["baseline_digest"],
        "actual_fingerprint_digest": _digest(actual),
        "observed_manifest_digest": manifest["manifest_digest"],
        "differences": differences[:128],
        "difference_count": len(differences),
        "limitations": LIMITATIONS,
    }


def load_baseline(path):
    path = trusted(path)
    info = path.lstat()
    is_private_regular_file = stat.S_ISREG(info.st_mode) and not info.st_mode & 0o077
    if not is_private_regular_file or info.st_nlink != 1 or info.st_size > MAX_BASELINE_BYTES:
        raise BaselineError("baseline must be a private bounded root-owned regular file")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise BaselineError("duplicate baseline JSON keys")
            result[key] = value
        return result

    def invalid_constant(_):
        raise BaselineError("non-finite baseline values are forbidden")

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=pairs, parse_constant=invalid_constant)
    except ValueError as exc:
        raise BaselineError("invalid baseline JSON") from exc
    return validate_baseline(value)


def _observe(args):
    config = AdminConfig.load(trusted(args.config))
    runtime = load_document(trusted(args.runtime))
    if type(runtime.get("version")) is not int or runtime["version"] != 1:
        raise BaselineError("unsupported runtime version")
    from .runtime_bundle import require_bundle_config

    require_bundle_config(runtime)
    users = args.users
    if (
        not users
        or len(users) != len(set(users))
        or any(uid not in config.users or not _USER.fullmatch(uid) for uid in users)
    ):
        raise BaselineError("select distinct configured users")
    requests = {uid: args.config.parent / f"request-{uid}.yaml" for uid in users}
    for argument in args.request:
        uid, path = argument.split("=", 1)
        if uid not in requests or not path:
            raise BaselineError("request override must name a selected user")
        requests[uid] = Path(path)
    for uid, path in requests.items():
        config.compile(uid, LaunchRequest.from_dict(load_document(trusted(path))))
    source = Path(_path(runtime["source_dir"], "source_dir"))
    overlay = runtime.get("dependency_overlay")
    return collect_manifest(
        config_path=args.config,
        runtime_path=args.runtime,
        request_paths=requests,
        source_dir=source,
        application_python=source / ".venv/bin/python",
        dependency_overlay=Path(_path(overlay, "dependency_overlay")) if overlay is not None else None,
    )


def _protect_runtime_output(args, manifest):
    """Reports belong outside measured source/runtime trees, even with --replace."""
    if args.output is None:
        return
    target = args.output.resolve()
    roots = [Path(__file__).resolve().parents[1], Path(sys.prefix).resolve(), Path(sys.base_prefix).resolve()]
    files = [Path(__file__).resolve().parents[2] / "pyproject.toml", Path(sys.executable).resolve()]
    application = _mapping(manifest.get("application"))
    for entry in (
        manifest.get("hypershell", {}).get("code"),
        application.get("code"),
        manifest.get("dependency_overlay"),
    ):
        if isinstance(entry, dict) and isinstance(entry.get("path"), str):
            roots.append(Path(entry["path"]).resolve())
    interpreter = _mapping(application.get("interpreter"))
    roots.extend(Path(path).resolve() for path in _mapping(interpreter.get("backend_code")).get("roots", []))
    for key in ("requested_executable",):
        if isinstance(interpreter.get(key), str):
            files.append(Path(interpreter[key]).resolve())
    runtime = load_document(trusted(args.runtime))
    for key in ("source_dir", "python_prefix", "node_prefix", "dependency_overlay"):
        value = runtime.get(key, "/opt/node20" if key == "node_prefix" else None)
        if value is not None:
            roots.append(Path(_path(value, key)).resolve())
    if target in files or any(target == root or root in target.parents for root in roots):
        raise BaselineError("output must be outside measured source, interpreter and runtime trees")


def _publish_baseline(path, document):
    """Atomically create a new baseline; a competing capture cannot overwrite it."""
    path = Path(path).absolute()
    trusted(path.parent, directory=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".baseline-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            os.fchmod(handle.fileno(), 0o600)
            handle.write(_canonical(document) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            raise BaselineError("baseline already exists; replacement requires --replace") from exc
        os.unlink(temporary)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY, 0o700)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for action in ("capture", "check"):
        command = commands.add_parser(action)
        command.add_argument("--config", type=Path, default=Path("/etc/hypershell-demo/admin.yaml"))
        command.add_argument("--runtime", type=Path, default=Path("/etc/hypershell-demo/runtime.yaml"))
        command.add_argument("--users", nargs="+", required=True)
        command.add_argument("--request", action="append", default=[], metavar="USER=PATH")
        command.add_argument("--output", type=Path, required=action == "capture")
        if action == "capture":
            command.add_argument("--replace", action="store_true")
        else:
            command.add_argument("--baseline", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require_admin()
        if args.output:
            trusted(args.output.absolute().parent, directory=True)
            protected = {args.config.resolve(), args.runtime.resolve()}
            protected.update((args.config.parent / f"request-{uid}.yaml").resolve() for uid in args.users)
            for argument in args.request:
                _, path = argument.split("=", 1)
                protected.add(Path(path).resolve())
            if args.command == "check":
                protected.add(args.baseline.resolve())
            if args.output.resolve() in protected:
                raise BaselineError("output must not overwrite an input configuration, request or reference baseline")
        if args.command == "capture" and args.output.exists() and not args.replace:
            raise BaselineError("baseline already exists; replacement requires --replace")
        expected = load_baseline(args.baseline) if args.command == "check" else None
        manifest = _observe(args)
        _protect_runtime_output(args, manifest)
        if args.command == "capture":
            baseline = make_baseline(manifest)
            if args.replace:
                write_report(args.output, baseline)
            else:
                _publish_baseline(args.output, baseline)
            log_console(
                json.dumps(
                    {
                        "status": "captured",
                        "baseline_digest": baseline["baseline_digest"],
                        "fingerprint_digest": baseline["fingerprint_digest"],
                        "output": str(args.output),
                    }
                )
            )
            return 0
        result = compare_baseline(expected, manifest)
        if args.output:
            write_report(args.output, result)
        log_console(json.dumps(result, ensure_ascii=False))
        return 0 if result["matched"] else 1
    except Exception as exc:
        log_console(
            json.dumps(
                {
                    "status": "incomplete",
                    "error_code": getattr(exc, "code", type(exc).__name__),
                    "message": str(exc) if isinstance(exc, RunnerError) else "baseline operation failed",
                }
            ),
            error=True,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
