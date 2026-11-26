"""Observed provenance must be reproducible, offline and free of secret values."""

import ast
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4
import venv

import pytest

from hypershell.runner import provenance

GIT = shutil.which("git")


@pytest.fixture
def tmp_path():
    # Match the repository's desktop-sandbox workaround for private temp ACLs.
    path = Path(__file__).resolve().parents[1] / ".test-tmp" / ("provenance-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


def _arguments(tmp_path):
    admin = tmp_path / "admin.yaml"
    runtime = tmp_path / "runtime.yaml"
    request = tmp_path / "request-u1.yaml"
    for path, text in (
        (admin, "password: ADMIN_SECRET\n"),
        (runtime, "model_key: MODEL_SECRET\n"),
        (request, "resources: []\n"),
    ):
        path.write_text(text, encoding="utf-8")
    source = tmp_path / "source"
    source.mkdir()
    return dict(
        config_path=admin,
        runtime_path=runtime,
        request_paths={"u1": request},
        application_python=Path(sys.executable),
        source_dir=source,
        hypershell_root=source,
    )


def _fake_interpreter():
    return {
        "status": "ok",
        "python": {"version": "3.11.9"},
        "packages": {"jiuwenbox": {"status": "installed", "version": "0.1.0"}},
    }


@pytest.fixture
def observe_interpreter(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(provenance, "_git", Mock(return_value=subprocess.CompletedProcess([], 1)))

    def observe(executable=sys.executable):
        settings = {**arguments, "application_python": Path(executable)}
        return provenance.collect_manifest(**settings)["application"]["interpreter"]

    return observe


@pytest.fixture
def probe_namespace(observe_interpreter, monkeypatch):
    process = Mock(return_value=subprocess.CompletedProcess([], 1))
    with monkeypatch.context() as capture:
        capture.setattr(provenance.subprocess, "run", process)
        assert observe_interpreter()["error"] == "interpreter_probe_failed"
    process.assert_called_once()
    (command,) = process.call_args.args
    script = ast.parse(command[-1])
    # Load the emitted probe's definitions so individual limits and inventory
    # sources can be exercised while leaving its reporting loop to integration tests.
    declarations = (ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.ClassDef)
    script.body = [statement for statement in script.body if isinstance(statement, declarations)]
    namespace = {}
    exec(compile(script, "<interpreter probe>", "exec"), namespace)
    namespace.update(
        importlib=SimpleNamespace(util=SimpleNamespace(find_spec=Mock(return_value=None))),
        metadata=SimpleNamespace(distributions=list),
    )
    return namespace


def _probe_function(namespace, name):
    function = namespace.get(name)
    assert callable(function)
    return function


def _probe_payload(namespace):
    return {
        "python": {"version": "3.11.9", "implementation": "CPython", "executable": "/approved/python"},
        "packages": {name: {"status": "not_installed", "version": None} for name in provenance.PACKAGES},
        "backend_code": _probe_function(namespace, "backend_code_identity")(),
        "distributions": _probe_function(namespace, "distributions_identity")(),
    }


@pytest.fixture
def read_probe_response(observe_interpreter, monkeypatch):
    def read(payload):
        response = subprocess.CompletedProcess([], 0, json.dumps(payload), "")
        with monkeypatch.context() as process:
            process.setattr(provenance.subprocess, "run", Mock(return_value=response))
            return observe_interpreter()

    return read


def _init_repository(path):
    if GIT is None:
        pytest.skip("git is required for real tracked-source provenance")

    def git(*arguments):
        result = subprocess.run([GIT, "-C", str(path), *arguments], capture_output=True, text=True, check=True)
        return result.stdout.strip()

    git("init")
    git("config", "user.name", "Provenance Test")
    git("config", "user.email", "provenance@example.invalid")
    git("config", "core.autocrlf", "false")
    git("config", "core.hooksPath", str(path / "no-hooks"))
    (path / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    (path / "hypershell").mkdir()
    (path / "hypershell" / "__init__.py").write_text("# deployed code\n", encoding="utf-8")
    (path / "pyproject.toml").write_text('[project]\nname = "test-source"\n', encoding="utf-8")
    (path / ".gitignore").write_text(".test-tmp/\n__pycache__/\n", encoding="utf-8")
    git("add", "module.py", ".gitignore", "hypershell", "pyproject.toml")
    git("-c", "commit.gpgsign=false", "commit", "-m", "baseline")
    return git("rev-parse", "HEAD")


def test_manifest_is_deterministic_and_hashes_config_without_exposing_secrets(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(provenance, "_application_identity", lambda _path: _fake_interpreter())
    first = provenance.collect_manifest(**arguments)
    second = provenance.collect_manifest(**arguments)
    assert first == second
    assert first["kind"] == "observed"
    assert "not a lockfile" in first["scope"]
    assert (
        first["configuration"]["admin"]["sha256"] == hashlib.sha256(arguments["config_path"].read_bytes()).hexdigest()
    )
    serialized = json.dumps(first)
    assert "ADMIN_SECRET" not in serialized
    assert "MODEL_SECRET" not in serialized
    digest = first.pop("manifest_digest")
    encoded = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    assert digest == hashlib.sha256(encoded).hexdigest()
    assert "timestamp" not in first
    arguments["request_paths"]["u1"].write_text("resources: [{id: project, mode: read}]\n", encoding="utf-8")
    changed = provenance.collect_manifest(**arguments)
    assert changed["manifest_digest"] != digest
    assert changed["configuration"]["requests"]["u1"]["sha256"] != second["configuration"]["requests"]["u1"]["sha256"]


def test_source_tracks_staged_and_worktree_changes_but_ignores_test_output(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    source = arguments["source_dir"]
    commit = _init_repository(source)
    monkeypatch.setattr(provenance, "_application_identity", lambda _path: _fake_interpreter())
    baseline = provenance.collect_manifest(**arguments)
    observed = baseline["hypershell"]["source"]
    assert observed["status"] == "ok"
    assert observed["commit"] == commit
    assert observed["dirty"] is False
    assert observed["dirty_scope"] == "tracked_files"
    (source / ".test-tmp").mkdir()
    (source / ".test-tmp" / "arbitrary-output.json").write_text("generated", encoding="utf-8")
    (source / "untracked.log").write_text("generated", encoding="utf-8")
    generated = provenance.collect_manifest(**arguments)
    assert generated["hypershell"]["source"] == observed
    assert generated["manifest_digest"] == baseline["manifest_digest"]
    (source / "hypershell" / "new_module.py").write_text("NEW = True\n", encoding="utf-8")
    untracked = provenance.collect_manifest(**arguments)
    assert untracked["hypershell"]["source"] == observed
    assert untracked["hypershell"]["code"]["sha256"] != baseline["hypershell"]["code"]["sha256"]
    (source / "module.py").write_text("VALUE = 2\n", encoding="utf-8")
    modified = provenance.collect_manifest(**arguments)["application"]["source"]
    assert modified["commit"] == commit
    assert modified["dirty"] is True
    assert modified["tracked_sha256"] != observed["tracked_sha256"]
    subprocess.run([GIT, "-C", str(source), "add", "module.py"], check=True, capture_output=True)
    staged = provenance.collect_manifest(**arguments)["application"]["source"]
    assert staged["dirty"] is True
    assert staged["tracked_sha256"] == modified["tracked_sha256"]


def test_missing_git_is_explicit_unknown_without_echoing_errors(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)

    def missing(*_args, **_kwargs):
        raise FileNotFoundError("PRIVATE_CREDENTIAL")

    monkeypatch.setattr(provenance, "_git", missing)
    monkeypatch.setattr(provenance, "_application_identity", lambda _path: _fake_interpreter())
    manifest = provenance.collect_manifest(**arguments)
    for source in (manifest["hypershell"]["source"], manifest["application"]["source"]):
        assert source["status"] == "unknown"
        assert source["commit"] is None
        assert source["dirty"] is None
        assert source["error"] == "git_unavailable"
    assert "PRIVATE_CREDENTIAL" not in json.dumps(manifest)


def _deployed_sources(source):
    for package in ("hypershell", "jiuwenswarm"):
        (source / package).mkdir()
        (source / package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (source / "hypershell" / "templates").mkdir()
    (source / "hypershell" / "templates" / "base.html").write_text("<main>Demo</main>\n", encoding="utf-8")
    (source / "pyproject.toml").write_text('[project]\nname = "deployment"\n', encoding="utf-8")


def test_copied_deployment_without_git_has_independent_code_digest(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    source = arguments["source_dir"]
    _deployed_sources(source)
    assert not (source / ".git").exists()
    monkeypatch.setattr(provenance, "_git", lambda *args: subprocess.CompletedProcess([], 1, b"", b""))
    monkeypatch.setattr(provenance, "_application_identity", lambda _path: _fake_interpreter())
    baseline = provenance.collect_manifest(**arguments)
    for kind in ("hypershell", "application"):
        assert baseline[kind]["source"]["status"] == "unknown"
        assert baseline[kind]["code"]["status"] == "ok"
        assert len(baseline[kind]["code"]["sha256"]) == 64
    (source / "jiuwenswarm" / "new_module.py").write_text("NEW = 2\n", encoding="utf-8")
    modified = provenance.collect_manifest(**arguments)
    assert modified["application"]["code"]["sha256"] != baseline["application"]["code"]["sha256"]
    assert modified["hypershell"]["code"]["sha256"] == baseline["hypershell"]["code"]["sha256"]
    assert modified["manifest_digest"] != baseline["manifest_digest"]


def test_code_inventory_never_opens_secrets_sessions_or_generated_files(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    source = arguments["source_dir"]
    _deployed_sources(source)
    package = source / "hypershell"
    for name in (".env", "accounts.yaml", "credentials.json", "session.sqlite", "private.key"):
        (package / name).write_text("PRIVATE_CONTENT", encoding="utf-8")
    for name in ("data", "home", "tests", "node_modules", ".venv", "__pycache__"):
        (package / name).mkdir()
        (package / name / "private.py").write_text("PRIVATE_CONTENT", encoding="utf-8")
    original_open = Path.open
    read_paths = []

    def record_read(path, mode="r", *args, **kwargs):
        if mode == "rb" and (path == source / "pyproject.toml" or package in path.parents):
            read_paths.append(path.relative_to(source).as_posix())
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", record_read)
    monkeypatch.setattr(provenance, "_application_identity", lambda _: _fake_interpreter())
    observed = provenance.collect_manifest(**arguments)["hypershell"]["code"]
    assert observed["status"] == "ok"
    assert set(read_paths) == {"pyproject.toml", "hypershell/__init__.py", "hypershell/templates/base.html"}
    assert "PRIVATE_CONTENT" not in json.dumps(observed)


def test_code_inventory_reports_symlink_as_unavailable_without_hashing_target(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    source = arguments["source_dir"]
    _deployed_sources(source)
    linked = source / "hypershell" / "linked.py"
    linked.write_text("PRIVATE_TARGET_CONTENT", encoding="utf-8")
    # Exercise lstat handling on Windows too, where symlink creation often needs
    # privileges. The simulated link's bytes must never reach the hash function.
    original_lstat = Path.lstat

    def linked_lstat(path, *args, **kwargs):
        if path == linked:
            return SimpleNamespace(st_mode=stat.S_IFLNK)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", linked_lstat)
    original_open = Path.open

    def refuse_link(path, *args, **kwargs):
        assert path != linked
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", refuse_link)
    monkeypatch.setattr(provenance, "_application_identity", lambda _: _fake_interpreter())
    observed = provenance.collect_manifest(**arguments)["hypershell"]["code"]
    assert observed["status"] == "incomplete"
    assert observed["unavailable_files"] == 1
    assert len(observed["sha256"]) == 64
    assert "PRIVATE_TARGET_CONTENT" not in json.dumps(observed)


def test_missing_code_root_remains_unknown(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(provenance, "_application_identity", lambda _: _fake_interpreter())
    settings = {**arguments, "hypershell_root": tmp_path / "missing"}
    observed = provenance.collect_manifest(**settings)["hypershell"]["code"]
    assert observed["status"] == "unknown"
    assert observed["sha256"] is None
    assert observed["error"] == "missing_source_root"
    empty = provenance.collect_manifest(**arguments)["hypershell"]["code"]
    assert empty["status"] == "unknown"
    assert empty["sha256"] is None
    assert empty["error"] == "package_source_unavailable"


def test_missing_config_does_not_hash_an_empty_file(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    arguments["runtime_path"].unlink()
    monkeypatch.setattr(provenance, "_application_identity", lambda _path: _fake_interpreter())
    observed = provenance.collect_manifest(**arguments)["configuration"]["runtime"]
    assert observed["status"] == "unknown"
    assert observed["error"] == "missing"
    assert observed["sha256"] is None


def test_overlay_digest_changes_with_source_but_not_bytecode(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(provenance, "_application_identity", lambda _: _fake_interpreter())
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    module = overlay / "sitecustomize.py"
    module.write_text("# compatibility overlay\n", encoding="utf-8")
    baseline = provenance.collect_manifest(**arguments, dependency_overlay=overlay)["dependency_overlay"]
    (overlay / "__pycache__").mkdir()
    (overlay / "__pycache__" / "sitecustomize.pyc").write_bytes(b"generated")
    (overlay / "other.pyc").write_bytes(b"generated")
    assert provenance.collect_manifest(**arguments, dependency_overlay=overlay)["dependency_overlay"] == baseline
    module.write_text("# changed compatibility overlay\n", encoding="utf-8")
    modified = provenance.collect_manifest(**arguments, dependency_overlay=overlay)["dependency_overlay"]
    assert modified["sha256"] != baseline["sha256"]
    single_file = provenance.collect_manifest(**arguments, dependency_overlay=module)["dependency_overlay"]
    assert single_file["kind"] == "file"
    assert single_file["sha256"] == hashlib.sha256(module.read_bytes()).hexdigest()


def test_overlay_does_not_follow_symlink(tmp_path, monkeypatch):
    arguments = _arguments(tmp_path)
    monkeypatch.setattr(provenance, "_application_identity", lambda _: _fake_interpreter())
    secret = tmp_path / "private-file"
    secret.write_text("DO_NOT_HASH_EXTERNAL_SECRET", encoding="utf-8")
    overlay = tmp_path / "overlay"
    overlay.mkdir()
    try:
        (overlay / "external.py").symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    observed = provenance.collect_manifest(**arguments, dependency_overlay=overlay)["dependency_overlay"]
    assert observed["status"] == "incomplete"
    assert "DO_NOT_HASH_EXTERNAL_SECRET" not in json.dumps(observed)
    assert observed["sha256"] != hashlib.sha256(secret.read_bytes()).hexdigest()


def test_actual_interpreter_metadata_probe_uses_isolation(tmp_path, monkeypatch, observe_interpreter):
    # A caller-controlled Python search path must neither import an application
    # nor execute an unapproved sitecustomize while observing package metadata.
    marker = tmp_path / "imported"
    injection = tmp_path / "injected"
    injection.mkdir()
    payload = "from pathlib import Path\nPath(" + repr(str(marker)) + ").write_text('ran')\n"
    (injection / "sitecustomize.py").write_text(payload, encoding="utf-8")
    (injection / "jiuwenbox.py").write_text(payload, encoding="utf-8")
    monkeypatch.setenv("PYTHONPATH", str(injection))
    monkeypatch.setenv("MODEL_KEY", "DO_NOT_REPORT_THIS_KEY")
    result = observe_interpreter()
    assert result["status"] == "ok"
    assert result["python"]["version"]
    assert set(result["packages"]) == set(provenance.PACKAGES)
    assert result["backend_code"]["status"] in {"ok", "incomplete", "unknown"}
    distributions = result["distributions"]
    assert distributions["status"] == "ok"
    assert distributions["count"] == len(distributions["entries"])
    canonical = json.dumps(distributions["entries"], sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert distributions["sha256"] == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert not marker.exists()
    assert "DO_NOT_REPORT_THIS_KEY" not in json.dumps(result)


def test_probe_passes_only_minimum_environment_and_does_not_import_applications(monkeypatch, observe_interpreter):
    monkeypatch.setenv("MODEL_KEY", "PRIVATE_MODEL_KEY")
    monkeypatch.setenv("PYTHONPATH", "/unapproved/overlay")

    def inspect(command, **kwargs):
        assert command[:4] == [str(Path("/approved/python")), "-I", "-B", "-c"]
        assert "PYTHONPATH" not in kwargs["env"]
        assert "MODEL_KEY" not in kwargs["env"]
        assert "import jiuwenbox" not in command[4]
        assert "import jiuwenswarm" not in command[4]
        assert "import openjiuwen" not in command[4]
        assert "importlib.metadata" in command[4]
        return subprocess.CompletedProcess(command, 1, "PRIVATE_STDOUT", "PRIVATE_STDERR")

    monkeypatch.setattr(provenance.subprocess, "run", inspect)
    result = observe_interpreter("/approved/python")
    assert result["error"] == "interpreter_probe_failed"
    assert result["exit_code"] == 1
    assert "PRIVATE" not in json.dumps(result)


@pytest.mark.parametrize("output", ["not json PRIVATE_KEY", "[]", "{}", '{"python": [], "packages": {}}'])
def test_invalid_probe_output_is_explicit_unknown(monkeypatch, observe_interpreter, output):
    monkeypatch.setattr(
        provenance.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess([], 0, output, "PRIVATE_STDERR"),
    )
    result = observe_interpreter()
    assert result["status"] == "unknown"
    assert result["error"] == "invalid_interpreter_response"
    assert "PRIVATE" not in json.dumps(result)


def test_probe_timeout_does_not_disclose_command_or_output(monkeypatch, observe_interpreter):
    def timeout(*_args, **_kwargs):
        raise subprocess.TimeoutExpired("PRIVATE_COMMAND", 20, output="PRIVATE_OUTPUT")

    monkeypatch.setattr(provenance.subprocess, "run", timeout)
    result = observe_interpreter()
    assert result["error"] == "interpreter_probe_timeout"
    assert "PRIVATE" not in json.dumps(result)


def _set_backend_root(namespace, root):
    package = SimpleNamespace(submodule_search_locations=[str(root)], origin=str(root / "__init__.py"))
    namespace["importlib"] = SimpleNamespace(util=SimpleNamespace(find_spec=Mock(return_value=package)))


def test_backend_fingerprint_covers_native_and_new_source_without_reading_secrets(
    tmp_path, probe_namespace, read_probe_response
):
    root = tmp_path / "jiuwenbox"
    root.mkdir()
    (root / "__init__.py").write_text("raise RuntimeError('must never import backend')\n", encoding="utf-8")
    (root / "native.so").write_bytes(b"native-code")
    for directory in ("data", "home", "tests", "__pycache__", ".venv"):
        (root / directory).mkdir()
        (root / directory / "hidden.py").write_text("PRIVATE_CONTENT", encoding="utf-8")
    for name in (".env", "credentials.json", "accounts.yaml", "sessions.sqlite", "cache.pyc"):
        (root / name).write_text("PRIVATE_CONTENT", encoding="utf-8")
    _set_backend_root(probe_namespace, root)
    inventory = _probe_function(probe_namespace, "backend_code_identity")
    first = inventory()
    assert first["status"] == "ok" and first["files"] == 2
    assert first["roots"] == [str(root)]
    assert first["bytes"] == sum((root / name).stat().st_size for name in ("__init__.py", "native.so"))
    assert "PRIVATE_CONTENT" not in json.dumps(first)
    response = read_probe_response(_probe_payload(probe_namespace))
    assert response["backend_code"] == first
    (root / "new_module.py").write_text("VALUE = 1\n", encoding="utf-8")
    second = inventory()
    assert second["files"] == 3 and second["sha256"] != first["sha256"]
    (root / "native.so").write_bytes(b"changed-native-code")
    assert inventory()["sha256"] != second["sha256"]


def test_backend_fingerprint_missing_import_is_unknown(probe_namespace, read_probe_response):
    observed = _probe_function(probe_namespace, "backend_code_identity")()
    assert observed["status"] == "unknown"
    assert observed["sha256"] is None and observed["error"] == "backend_not_found"
    response = read_probe_response(_probe_payload(probe_namespace))
    assert response["backend_code"] == observed


@pytest.mark.parametrize(
    "limit,value,error",
    [
        ("MAX_CODE_FILES", 1, "file_limit"),
        ("MAX_CODE_BYTES", 4, "byte_limit"),
        ("MAX_CODE_ENTRIES", 1, "entry_limit"),
    ],
)
def test_backend_fingerprint_limits_remain_incomplete(tmp_path, probe_namespace, limit, value, error):
    (tmp_path / "one.py").write_text("ONE = 1\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("TWO = 2\n", encoding="utf-8")
    _set_backend_root(probe_namespace, tmp_path)
    probe_namespace[limit] = value
    observed = _probe_function(probe_namespace, "backend_code_identity")()
    assert observed["status"] == "incomplete" and observed["error"] == error
    assert observed["sha256"] is None
    assert observed["files"] <= observed["limits"]["files"]
    assert observed["bytes"] <= observed["limits"]["bytes"]


def test_backend_fingerprint_refuses_symlink_file_without_opening_it(tmp_path, monkeypatch, probe_namespace):
    (tmp_path / "normal.py").write_text("VALUE = 1\n", encoding="utf-8")
    linked = tmp_path / "link.py"
    linked.write_text("PRIVATE_TARGET", encoding="utf-8")
    original_lstat = Path.lstat

    def lstat(path, *args, **kwargs):
        if path == linked:
            return SimpleNamespace(st_mode=stat.S_IFLNK)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", lstat)
    _set_backend_root(probe_namespace, tmp_path)
    observed = _probe_function(probe_namespace, "backend_code_identity")()
    assert observed["status"] == "incomplete" and observed["files"] == 1
    assert observed["unavailable_files"] == 1
    assert "PRIVATE_TARGET" not in json.dumps(observed)


def test_distribution_inventory_is_canonical_and_contains_only_names_versions(probe_namespace, read_probe_response):
    private_value = uuid4().hex
    packages = [
        SimpleNamespace(metadata={"Name": "Z_Package", "direct_url": "PRIVATE_URL"}, version="2.0"),
        SimpleNamespace(metadata={"Name": "a.package", "Password": private_value}, version="1.0+local"),
    ]
    probe_namespace["metadata"] = SimpleNamespace(distributions=lambda: packages)
    inventory = _probe_function(probe_namespace, "distributions_identity")
    observed = inventory()
    assert observed["status"] == "ok" and observed["count"] == 2
    assert observed["entries"] == [
        {"name": "a-package", "version": "1.0+local"},
        {"name": "z-package", "version": "2.0"},
    ]
    rendered = json.dumps(observed)
    assert "PRIVATE_URL" not in rendered
    assert private_value not in rendered
    response = read_probe_response(_probe_payload(probe_namespace))
    assert response["distributions"] == observed
    packages.reverse()
    assert inventory() == observed
    packages[0].version = "9.0"
    assert inventory()["sha256"] != observed["sha256"]


def test_distribution_inventory_invalid_metadata_or_limits_cannot_be_complete(probe_namespace):
    probe_namespace["metadata"] = SimpleNamespace(
        distributions=lambda: [
            SimpleNamespace(metadata={"Name": "valid-name"}, version="1.0"),
            SimpleNamespace(metadata={"Name": "PRIVATE_URL/invalid"}, version="PRIVATE_VERSION VALUE"),
        ]
    )
    inventory = _probe_function(probe_namespace, "distributions_identity")
    observed = inventory()
    assert observed["status"] == "incomplete" and observed["unavailable_entries"] == 1
    assert observed["entries"] == [{"name": "valid-name", "version": "1.0"}]
    assert "PRIVATE" not in json.dumps(observed)
    probe_namespace["MAX_DISTRIBUTIONS"] = 1
    truncated = inventory()
    assert truncated["status"] == "incomplete" and truncated["sha256"] is None
    assert truncated["error"] == "distribution_limit"


def test_real_application_interpreter_finds_editable_backend_without_importing_it(tmp_path, observe_interpreter):
    environment = tmp_path / "application-venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    if sys.platform == "win32":
        executable, site = environment / "Scripts/python.exe", environment / "Lib/site-packages"
    else:
        executable = environment / "bin/python"
        site = (
            environment
            / ("lib/python" + str(sys.version_info.major) + "." + str(sys.version_info.minor))
            / "site-packages"
        )
    site.mkdir(parents=True, exist_ok=True)
    source = tmp_path / "external-editable-source"
    package = source / "jiuwenbox"
    package.mkdir(parents=True)
    marker = tmp_path / "backend-imported"
    (package / "__init__.py").write_text(
        "from pathlib import Path\nPath("
        + repr(str(marker))
        + ").write_text('IMPORTED')\nraise RuntimeError('must not import')\n",
        encoding="utf-8",
    )
    module = package / "process.py"
    module.write_text("BACKEND = 1\n", encoding="utf-8")
    (site / "backend-editable.pth").write_text(str(source) + "\n", encoding="utf-8")
    metadata = site / "jiuwenbox-9.8.7.dist-info"
    metadata.mkdir()
    (metadata / "METADATA").write_text("Metadata-Version: 2.1\nName: jiuwenbox\nVersion: 9.8.7\n", encoding="utf-8")
    (metadata / "direct_url.json").write_text('{"url":"PRIVATE_URL_CREDENTIAL"}', encoding="utf-8")
    first = observe_interpreter(executable)
    assert first["status"] == "ok"
    assert first["packages"]["jiuwenbox"] == {"status": "installed", "version": "9.8.7"}
    assert first["backend_code"]["status"] == "ok" and first["backend_code"]["files"] == 2
    assert first["backend_code"]["roots"] == [str(package)]
    assert first["distributions"]["entries"] == [{"name": "jiuwenbox", "version": "9.8.7"}]
    assert not marker.exists() and "PRIVATE" not in json.dumps(first)
    module.write_text("BACKEND = 2\n", encoding="utf-8")
    second = observe_interpreter(executable)
    assert second["backend_code"]["sha256"] != first["backend_code"]["sha256"]
    assert second["distributions"] == first["distributions"]
    assert not marker.exists()


@pytest.mark.parametrize(
    "damage", ["missing_digest", "backend_extra", "distribution_extra", "distribution_digest", "false_complete"]
)
def test_invalid_new_fingerprints_cannot_claim_complete_or_export_extra_metadata(
    tmp_path, probe_namespace, read_probe_response, damage
):
    (tmp_path / "backend.py").write_text("VALUE = 1\n", encoding="utf-8")
    _set_backend_root(probe_namespace, tmp_path)
    probe_namespace["metadata"] = SimpleNamespace(
        distributions=lambda: [
            SimpleNamespace(metadata={"Name": "example-dependency"}, version="1.0"),
        ]
    )
    payload = _probe_payload(probe_namespace)
    if damage == "missing_digest":
        payload["backend_code"]["sha256"] = None
    elif damage == "backend_extra":
        payload["backend_code"]["environment"] = {"MODEL_KEY": "PRIVATE_SECRET"}
    elif damage == "distribution_extra":
        payload["distributions"]["entries"][0]["direct_url"] = "PRIVATE_SECRET"
    elif damage == "distribution_digest":
        payload["distributions"]["sha256"] = "0" * 64
    else:
        payload["distributions"]["unavailable_entries"] = 1
    observed = read_probe_response(payload)
    assert observed["status"] == "unknown" and observed["error"] == "invalid_interpreter_response"
    assert "PRIVATE" not in json.dumps(observed)
