"""Static, administrator-operated runtime snapshots; never execute input code.

This preserves a source checkout's layout and materializes an explicitly selected
set of editable packages. It is a same-host snapshot, not a wheel builder or an
independent reproducible build. Python and Node remain external trust anchors.
"""

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat

from ..console import log_console
from .client import RunnerError
from .managed import require_admin, trusted

MAX_FILES = 150_000
MAX_BYTES = 8 * 1024**3
MAX_MANIFEST = 64 * 1024**2
MAX_DEPTH = 64
MAX_EDITABLE_FILES = 128
MAX_EDITABLE_BYTES = 4 * 1024**2
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".pytest_cache", ".mypy_cache"}
SKIP_FILES = {"direct_url.json", ".DS_Store"}
METADATA = ("pyproject.toml", "setup.py", "MANIFEST.in", "LICENSE", "OPEN_SOURCE_SOFTWARE_NOTICE.md")
DISTUTILS_HOOK = (
    "import os; var = 'SETUPTOOLS_USE_DISTUTILS'; enabled = os.environ.get(var, 'local') == 'local'; "
    "enabled and __import__('_distutils_hack').add_shim();"
)
MANIFEST = "runtime-bundle.json"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _relative(value):
    if not isinstance(value, str) or not value:
        raise RunnerError("invalid bundle relative path")
    if "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise RunnerError("invalid bundle relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise RunnerError("invalid bundle relative path")
    return path


def _skip(name):
    return (
        name in SKIP_DIRS
        or name in SKIP_FILES
        or name.endswith((".pyc", ".pyo"))
        or name == ".env"
        or name.startswith(".env.")
    )


class _Copier:
    def __init__(self, *, copy_linked_inputs=False):
        self.files = 0
        self.bytes = 0
        self.entries = 0
        self.copy_linked_inputs = copy_linked_inputs

    @staticmethod
    def names(descriptor):
        names = []
        with os.scandir(descriptor) as entries:
            for entry in entries:
                names.append(entry.name)
                if len(names) > MAX_FILES:
                    raise RunnerError("bundle directory entry limit exceeded")
        return sorted(names)

    @staticmethod
    def open_directory(source):
        source = Path(source).absolute()
        descriptor = os.open(source.anchor, os.O_RDONLY | os.O_DIRECTORY, 0o700)
        try:
            for part in source.parts[1:]:
                parent = descriptor
                descriptor = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700, dir_fd=parent)
                os.close(parent)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def copy(self, source, target, *, site=False, internal_links=False):
        """Use directory FDs and O_NOFOLLOW, including for untrusted inputs."""
        descriptor = self.open_directory(source)
        try:
            self._directory(
                descriptor,
                target,
                site=site,
                input_root=Path(source).absolute() if internal_links else None,
                relative=Path(),
            )
        finally:
            os.close(descriptor)

    def _directory(self, descriptor, target, *, site=False, depth=0, input_root=None, relative=Path()):
        self.entries += 1
        if depth > MAX_DEPTH or self.entries > MAX_FILES:
            raise RunnerError("bundle directory limit exceeded")
        before = os.fstat(descriptor)
        target.mkdir(mode=0o755, parents=True, exist_ok=True)
        names = self.names(descriptor)
        self.entries += len(names)
        if self.entries > MAX_FILES:
            raise RunnerError("bundle entry limit exceeded")
        for name in names:
            if _skip(name):
                continue
            info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, 0o700, dir_fd=descriptor)
                try:
                    actual = os.fstat(child)
                    if (actual.st_dev, actual.st_ino) != (info.st_dev, info.st_ino):
                        raise RunnerError("input directory was substituted")
                    self._directory(
                        child, target / name, depth=depth + 1, input_root=input_root, relative=relative / name
                    )
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode):
                if name.endswith(".egg-link"):
                    raise RunnerError("legacy editable egg links are unsupported")
                if site and name.startswith("__editable__"):
                    continue
                if site and name.endswith(".pth"):
                    content = self.read(descriptor, name, info, limit=65536)
                    if name != "distutils-precedence.pth" or content.decode("utf-8").strip() != DISTUTILS_HOOK:
                        raise RunnerError(
                            "unrecognized site path hook; explicitly materialize packages instead", path=name
                        )
                    _write_bundle_file(target / name, content, 0o444)
                else:
                    self.file(descriptor, name, info, target / name)
            elif stat.S_ISLNK(info.st_mode) and input_root is not None:
                link = os.readlink(name, dir_fd=descriptor)
                resolved = Path(os.path.normpath(input_root / relative / link))
                if os.path.isabs(link) or not resolved.is_relative_to(input_root):
                    raise RunnerError("package symlink must stay inside its copied package tree", path=name)
                # Preserve the relative link without reading its target. The
                # final trust audit rejects missing targets or escaping chains.
                (target / name).symlink_to(link)
            else:
                raise RunnerError("bundle inputs must be regular files and directories without links", path=name)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RunnerError("input directory changed during snapshot")

    def _open(self, directory, name, expected):
        if expected.st_nlink != 1 and not self.copy_linked_inputs:
            raise RunnerError("hard linked input files are unsupported", path=name)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, 0o700, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            unexpected_link = before.st_nlink != 1 and not self.copy_linked_inputs
            if (
                not stat.S_ISREG(before.st_mode)
                or unexpected_link
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns)
            ):
                raise RunnerError("input was substituted during snapshot", path=name)
            if self.files >= MAX_FILES or self.bytes + before.st_size > MAX_BYTES:
                raise RunnerError("bundle input limit exceeded")
            return descriptor, before
        except BaseException:
            os.close(descriptor)
            raise

    def _finish(self, descriptor, before, size, name):
        after = os.fstat(descriptor)
        if size != before.st_size or (before.st_size, before.st_nlink, before.st_mtime_ns, before.st_ctime_ns) != (
            after.st_size,
            after.st_nlink,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise RunnerError("input changed during snapshot", path=name)
        self.files += 1
        self.bytes += size

    def read(self, directory, name, expected, *, limit=1024 * 1024):
        descriptor, before = self._open(directory, name, expected)
        try:
            if before.st_size > limit:
                raise RunnerError("input file exceeds size limit", path=name)
            chunks = []
            size = 0
            for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                size += len(chunk)
                if size > before.st_size:
                    raise RunnerError("input grew during snapshot", path=name)
                chunks.append(chunk)
            self._finish(descriptor, before, size, name)
            return b"".join(chunks)
        finally:
            os.close(descriptor)

    def file(self, directory, name, info, target):
        descriptor, before = self._open(directory, name, info)
        try:
            size = 0
            with open(target, "xb") as handle:
                for chunk in iter(lambda: os.read(descriptor, 1024 * 1024), b""):
                    size += len(chunk)
                    if size > before.st_size:
                        raise RunnerError("input grew during snapshot", path=name)
                    handle.write(chunk)
                self._finish(descriptor, before, size, name)
                os.fchmod(handle.fileno(), 0o555 if before.st_mode & 0o111 else 0o444)
        finally:
            os.close(descriptor)


def _write_bundle_file(target, content, mode):
    with open(target, "xb") as handle:
        handle.write(content)
        os.fchmod(handle.fileno(), mode)


def _inventory(root):
    entries = []
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in sorted(dirs + files):
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST:
                continue
            info = path.lstat()
            entry = {"path": relative, "mode": stat.S_IMODE(info.st_mode)}
            if stat.S_ISLNK(info.st_mode):
                entry.update(kind="symlink", target=os.readlink(path))
                if name in dirs:
                    dirs.remove(name)
            elif stat.S_ISDIR(info.st_mode):
                entry.update(kind="directory")
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                total += info.st_size
                if total > MAX_BYTES:
                    raise RunnerError("bundle payload exceeds limit")
                with open(path, "rb") as handle:
                    digest = hashlib.file_digest(handle, "sha256").hexdigest()
                entry.update(kind="file", size=info.st_size, sha256=digest)
            else:
                raise RunnerError("unsupported bundle payload entry", path=relative)
            entries.append(entry)
            if len(entries) > MAX_FILES:
                raise RunnerError("bundle payload entry limit exceeded")
    return sorted(entries, key=lambda entry: entry["path"])


def _editable_declarations(source, *, copy_linked_inputs=False):
    """Parse generated literal mappings, never import the editable finders."""
    site = source / ".venv/lib/python3.11/site-packages"
    descriptor = _Copier.open_directory(site)
    try:
        names = _Copier.names(descriptor)
        values = {}
        metadata_bytes = 0
        for name in names:
            if name.startswith("__editable__"):
                info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or (info.st_nlink != 1 and not copy_linked_inputs):
                    raise RunnerError("editable declarations must be regular files")
                metadata_bytes += info.st_size
                if len(values) >= MAX_EDITABLE_FILES or metadata_bytes > MAX_EDITABLE_BYTES:
                    raise RunnerError("editable declaration budget exceeded")
                values[name] = (
                    _Copier(copy_linked_inputs=copy_linked_inputs)
                    .read(descriptor, name, info, limit=65536)
                    .decode("utf-8")
                )
    except UnicodeError as exc:
        raise RunnerError("invalid editable declaration encoding") from exc
    finally:
        os.close(descriptor)
    mappings = {}
    finders = set()
    for finder_name, content in values.items():
        if not finder_name.endswith("finder.py"):
            continue
        declared = {}
        try:
            for statement in ast.parse(content).body:
                if (
                    isinstance(statement, ast.AnnAssign)
                    and isinstance(statement.target, ast.Name)
                    and statement.target.id in {"MAPPING", "NAMESPACES"}
                ):
                    if statement.target.id in declared:
                        raise RunnerError("duplicate editable declaration")
                    declared[statement.target.id] = ast.literal_eval(statement.value)
        except (SyntaxError, ValueError, TypeError, RecursionError) as exc:
            raise RunnerError("invalid editable mapping syntax") from exc
        mapping = declared.get("MAPPING")
        if declared.get("NAMESPACES") != {} or not isinstance(mapping, dict):
            raise RunnerError("only explicit non-namespace editable packages are supported")
        for name, target in mapping.items():
            if name in mappings or not isinstance(target, str):
                raise RunnerError("duplicate or invalid editable mapping")
            try:
                mappings[name] = Path(target).relative_to(source).as_posix()
            except ValueError as exc:
                raise RunnerError("editable source lies outside the declared source tree") from exc
        finders.add(Path(finder_name).stem)
    hooks = set()
    for name, content in values.items():
        if not name.endswith(".pth"):
            if not name.endswith("finder.py"):
                raise RunnerError("unrecognized editable artifact")
            continue
        match = re.fullmatch(r"import ([A-Za-z_]\w*); \1\.install\(\)", content.strip())
        if match is None or match[1] not in finders:
            raise RunnerError("unrecognized editable path hook")
        hooks.add(match[1])
    if hooks != finders:
        raise RunnerError("editable hooks and finders do not match")
    return mappings


def build_bundle(source, destination, python_prefix, node_prefix, packages, *, copy_linked_inputs=False):
    require_admin()
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    trusted(destination.parent, directory=True)
    if source.resolve() != source or not source.is_dir():
        raise RunnerError("source must be an existing non-symlink directory")
    if source == destination or source in destination.parents or destination in source.parents:
        raise RunnerError("bundle output and input must not overlap")
    from .runtime_trust import require_trusted_runtime

    python_prefix = Path(python_prefix).absolute()
    node_prefix = Path(node_prefix).absolute()
    if any(any(c.isspace() or c == ":" for c in str(path)) for path in (destination, python_prefix, node_prefix)):
        raise RunnerError("runtime bundle and anchor paths cannot contain whitespace or PATH separators")
    if any(
        destination == root or destination in root.parents or root in destination.parents
        for root in (python_prefix, node_prefix)
    ):
        raise RunnerError("bundle output must not overlap external runtime anchors")
    require_trusted_runtime([python_prefix, node_prefix])
    executable = python_prefix / "bin/python3.11"
    if not executable.is_file():
        raise RunnerError("this snapshot profile requires Python 3.11")
    normalized = {}
    for name, relative in packages.items():
        if not re.fullmatch(r"[A-Za-z_]\w*", name) or not isinstance(relative, str):
            raise RunnerError("invalid editable package declaration")
        relative = _relative(relative)
        if relative.parts[0].startswith(".") or relative.name != name:
            raise RunnerError("editable packages must map to matching package directories")
        normalized[name] = relative
    if not normalized:
        raise RunnerError("declare the complete editable package set")
    if not isinstance(copy_linked_inputs, bool):
        raise RunnerError("invalid linked-input option")
    if {name: str(path) for name, path in normalized.items()} != _editable_declarations(
        source, copy_linked_inputs=copy_linked_inputs
    ):
        raise RunnerError("explicit package declarations must exactly match all editable mappings")
    original_site = source / ".venv/lib/python3.11/site-packages"
    if any((original_site / name).exists() or (original_site / (name + ".py")).exists() for name in normalized):
        raise RunnerError("materialized packages conflict with installed site-packages")
    paths = list(normalized.values())
    if any(a != b and (a in b.parents or b in a.parents) for a in paths for b in paths):
        raise RunnerError("editable package trees must not overlap")
    # Exclusive reservation: incomplete snapshots remain private and have no manifest.
    destination.mkdir(mode=0o700)
    try:
        copier = _Copier(copy_linked_inputs=copy_linked_inputs)
        output = destination / "source"
        site = output / ".venv/lib/python3.11/site-packages"
        copier.copy(source / ".venv/lib/python3.11/site-packages", site, site=True)
        for relative in paths:
            copier.copy(source / str(relative), output / str(relative), internal_links=True)
        # The application initializer requires this filename. Never copy the
        # original environment template: generate an empty one without secrets.
        if "jiuwenswarm" in normalized:
            resources = output / str(normalized["jiuwenswarm"]) / "resources"
            if not resources.is_dir():
                raise RunnerError("JiuwenSwarm resources directory is required")
            _write_bundle_file(
                resources / ".env.template",
                b"# Configure model settings in each workspace; no credentials are bundled.\n",
                0o444,
            )
        root_fd = copier.open_directory(source)
        try:
            for name in METADATA:
                try:
                    info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    raise RunnerError("source metadata must be a regular file", path=name)
                copier.file(root_fd, name, info, output / name)
        finally:
            os.close(root_fd)
        parents = sorted({os.path.relpath(output / str(path.parent), site) for path in paths})
        _write_bundle_file(site / "hypershell-materialized.pth", ("\n".join(parents) + "\n").encode(), 0o444)
        bins = output / ".venv/bin"
        bins.mkdir(mode=0o755)
        # Fixed launchers avoid copying shell trampolines or arbitrary old tools.
        launchers = {
            "jiuwenswarm": "jiuwenswarm.channels.cli.main",
            "jiuwenswarm-start": "jiuwenswarm.start_services",
            "jiuwenswarm-tui": "jiuwenswarm_tui.app",
            "jiuwenswarm-web": "jiuwenswarm.channels.web.app_web",
            "jiuwenbox-server": "jiuwenbox.server.launcher",
        }
        shebang = b"#!" + os.fsencode(bins / "python")
        if len(shebang) > 127:
            raise RunnerError("bundle path is too long for portable console shebangs")
        for name, module in launchers.items():
            if module.split(".")[0] in normalized:
                _write_bundle_file(
                    bins / name,
                    shebang
                    + (
                        "\nimport sys\nsys.dont_write_bytecode = True\nfrom "
                        + module
                        + " import main\nif __name__ == '__main__':\n    sys.exit(main())\n"
                    ).encode(),
                    0o555,
                )
        (bins / "python").symlink_to(executable)
        (bins / "python3").symlink_to("python")
        (bins / "python3.11").symlink_to("python")
        (output / ".venv/lib64").symlink_to("lib")
        _write_bundle_file(
            output / ".venv/pyvenv.cfg",
            (f"home = {python_prefix}/bin\ninclude-system-site-packages = false\nversion = 3.11\n").encode(),
            0o444,
        )
        entries = _inventory(destination)
        document = {
            "schema_version": 1,
            "kind": "runtime_bundle",
            "source_dir": str(output),
            "python_prefix": str(python_prefix),
            "node_prefix": str(node_prefix),
            "packages": {name: str(path) for name, path in sorted(normalized.items())},
            "copied_linked_inputs": copy_linked_inputs,
            "entries": entries,
            "payload_digest": _digest(entries),
            "limitations": (
                "Same-host static snapshot; external Python/Node/OS anchors and approved input content remain "
                "administrator responsibilities. Not a reproducible build or signature."
            ),
        }
        document["bundle_digest"] = _digest(document)
        serialized = _canonical(document) + b"\n"
        if len(serialized) > MAX_MANIFEST:
            raise RunnerError("bundle manifest exceeds size limit")
        require_trusted_runtime([destination, python_prefix, node_prefix])
        _write_bundle_file(destination / MANIFEST, serialized, 0o444)
        os.chmod(destination, 0o755)
        return {
            "status": "built",
            "destination": str(destination),
            "bundle_digest": document["bundle_digest"],
            "payload_entries": len(entries),
            "copied_bytes": copier.bytes,
        }
    except BaseException:
        # This private directory was exclusively created under a trusted parent.
        shutil.rmtree(destination)
        raise


def verify_bundle(destination):
    require_admin()
    destination = trusted(destination, directory=True)
    from .runtime_trust import require_trusted_runtime

    path = trusted(destination / MANIFEST)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_MANIFEST:
        raise RunnerError("invalid bundle manifest file")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise RunnerError("duplicate bundle JSON keys")
            result[key] = value
        return result

    try:
        document = json.loads(
            path.read_text(),
            object_pairs_hook=pairs,
            parse_constant=lambda _: (_ for _ in ()).throw(RunnerError("invalid bundle JSON constant")),
        )
    except ValueError as exc:
        raise RunnerError("invalid bundle JSON encoding or syntax") from exc
    expected_fields = {
        "schema_version",
        "kind",
        "source_dir",
        "python_prefix",
        "node_prefix",
        "packages",
        "copied_linked_inputs",
        "entries",
        "payload_digest",
        "limitations",
        "bundle_digest",
    }
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise RunnerError("invalid bundle manifest")
    version = document["schema_version"]
    if type(version) is not int or version != 1 or document["kind"] != "runtime_bundle":
        raise RunnerError("invalid bundle manifest")
    recorded_digest = document.pop("bundle_digest", None)
    if recorded_digest != _digest(document) or document.get("source_dir") != str(destination / "source"):
        raise RunnerError("bundle manifest digest or location mismatch")
    entries = document.get("entries")
    if not isinstance(entries, list) or document.get("payload_digest") != _digest(entries):
        raise RunnerError("bundle payload digest mismatch")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise RunnerError("invalid bundle payload entry")
        _relative(entry["path"])
        if entry["path"] in seen or type(entry.get("mode")) is not int or not 0 <= entry["mode"] <= 0o777:
            raise RunnerError("invalid or duplicate bundle payload entry")
        seen.add(entry["path"])
        common = {"path", "mode", "kind"}
        if entry.get("kind") == "file":
            valid = (
                set(entry) == common | {"size", "sha256"}
                and type(entry["size"]) is int
                and 0 <= entry["size"] <= MAX_BYTES
                and isinstance(entry["sha256"], str)
                and re.fullmatch("[0-9a-f]{64}", entry["sha256"])
            )
        elif entry.get("kind") == "directory":
            valid = set(entry) == common
        elif entry.get("kind") == "symlink":
            valid = (
                set(entry) == common | {"target"}
                and isinstance(entry["target"], str)
                and 0 < len(entry["target"]) <= 4096
                and "\x00" not in entry["target"]
            )
        else:
            valid = False
        if not valid:
            raise RunnerError("invalid bundle payload entry schema")
    require_trusted_runtime([destination, Path(document["python_prefix"]), Path(document["node_prefix"])])
    actual = _inventory(destination)
    if actual != entries:
        expected = {entry["path"]: entry for entry in entries}
        observed = {entry["path"]: entry for entry in actual}
        changed = [
            name for name in sorted(expected.keys() | observed.keys()) if expected.get(name) != observed.get(name)
        ]
        return {"status": "drift", "matched": False, "changed_count": len(changed), "changed_paths": changed[:32]}
    return {
        "status": "matched",
        "matched": True,
        "bundle_digest": recorded_digest,
        "payload_entries": len(actual),
        "runtime": {key: document[key] for key in ("source_dir", "python_prefix", "node_prefix")},
    }


def require_bundle_config(runtime):
    """Require a matching static bundle before privileged application execution."""
    from ..config import _path

    selected = runtime.get("runtime_bundle")
    if selected is None:
        raise RunnerError(
            "runtime_bundle is required before root application execution; "
            "build and verify a controlled runtime snapshot"
        )
    result = verify_bundle(Path(_path(selected, "runtime_bundle")))
    if not result["matched"]:
        raise RunnerError("runtime bundle payload drift; root application execution refused")
    for key in ("source_dir", "python_prefix", "node_prefix"):
        configured = _path(runtime.get(key, "/opt/node20" if key == "node_prefix" else None), key)
        if configured != result["runtime"][key]:
            raise RunnerError("runtime configuration does not match the verified bundle", field=key)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    build = commands.add_parser("build")
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--destination", type=Path, required=True)
    build.add_argument("--python-prefix", type=Path, required=True)
    build.add_argument("--node-prefix", type=Path, required=True)
    build.add_argument("--package", action="append", default=[], metavar="NAME=RELATIVE/PACKAGE")
    build.add_argument(
        "--copy-linked-inputs",
        action="store_true",
        help="copy explicitly approved hardlinked input files by value; output never shares their inodes",
    )
    verify = commands.add_parser("verify")
    verify.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            packages = {}
            for argument in args.package:
                name, relative = argument.split("=", 1)
                if name in packages:
                    raise RunnerError("duplicate editable package")
                packages[name] = relative
            result = build_bundle(
                args.source,
                args.destination,
                args.python_prefix,
                args.node_prefix,
                packages,
                copy_linked_inputs=args.copy_linked_inputs,
            )
        else:
            result = verify_bundle(args.destination)
        log_console(json.dumps(result, sort_keys=True))
        return 1 if result.get("matched") is False else 0
    except (RunnerError, OSError, ValueError, KeyError) as exc:
        log_console(json.dumps({"status": "error", "message": str(exc)}), error=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
