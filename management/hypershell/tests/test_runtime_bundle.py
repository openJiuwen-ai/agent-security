"""Static snapshot contracts and real Linux filesystem regressions."""

import hashlib
import json
from pathlib import Path
import sys

import pytest

from hypershell.runner import runtime_bundle as bundle
from hypershell.runner.client import RunnerError


@pytest.mark.parametrize("path", ["/tmp/a", "../a", "a/../b", "a//b", "a\\b", "./a", "a/", "", "a\nb", "a\x00b"])
def test_relative_paths_are_strict(tmp_path, monkeypatch, path):
    monkeypatch.setattr(bundle, "require_admin", lambda: None)
    monkeypatch.setattr(bundle, "trusted", lambda item, **kw: item)
    entries = [{"path": path, "kind": "directory", "mode": 0o755}]
    document = {
        "schema_version": 1,
        "kind": "runtime_bundle",
        "source_dir": str(tmp_path / "source"),
        "python_prefix": str(tmp_path / "python"),
        "node_prefix": str(tmp_path / "node"),
        "packages": {},
        "copied_linked_inputs": False,
        "entries": entries,
        "payload_digest": _manifest_digest(entries),
        "limitations": "test fixture",
    }
    document["bundle_digest"] = _manifest_digest(document)
    (tmp_path / bundle.MANIFEST).write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RunnerError, match="invalid bundle relative path"):
        bundle.verify_bundle(tmp_path)


def _manifest_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def fixture_source(tmp_path):
    source = tmp_path / "original"
    site = source / ".venv/lib/python3.11/site-packages"
    site.mkdir(parents=True)
    package = source / "nested/demo"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("raise RuntimeError('MUST NOT IMPORT')\n")
    (package / "asset.js").write_text("asset")
    (package / ".env").write_text("DO_NOT_COPY_SECRET")
    (site / "dependency.py").write_text("value = 1\n")
    (site / "__editable___demo_finder.py").write_text(
        f"MAPPING: dict = {{'demo': {str(package)!r}}}\n"
        "NAMESPACES: dict = {}\n"
        "raise RuntimeError('MUST NOT EXECUTE')\n"
    )
    (site / "__editable__.demo.pth").write_text("import __editable___demo_finder; __editable___demo_finder.install()\n")
    return source, site


def test_editable_mapping_is_parsed_without_import(linux_build):
    source, _, prefix, node, destination = linux_build
    bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    manifest = json.loads((destination / bundle.MANIFEST).read_text(encoding="utf-8"))
    assert manifest["packages"] == {"demo": "nested/demo"}


def test_unknown_editable_hook_is_refused(linux_build):
    source, site, prefix, node, destination = linux_build
    (site / "__editable__.demo.pth").write_text("import unexpected_editable_hook")
    with pytest.raises(RunnerError, match="unrecognized editable"):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert not destination.exists()


@pytest.fixture
def linux_build(tmp_path, monkeypatch):
    if sys.platform != "linux":
        pytest.skip("requires Linux directory FDs and symlinks")
    from hypershell.runner import runtime_trust

    monkeypatch.setattr(bundle, "require_admin", lambda: None)
    monkeypatch.setattr(bundle, "trusted", lambda p, **kw: Path(p).absolute())
    monkeypatch.setattr(runtime_trust, "require_trusted_runtime", lambda roots: {})
    source, site = fixture_source(tmp_path)
    prefix = tmp_path / "python"
    (prefix / "bin").mkdir(parents=True)
    (prefix / "bin/python3.11").write_text("external interpreter not executed")
    node = tmp_path / "node"
    node.mkdir()
    destination = tmp_path / "release"
    return source, site, prefix, node, destination


def test_build_is_static_and_separate_then_detects_payload_drift(linux_build):
    source, site, prefix, node, destination = linux_build
    result = bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert result["status"] == "built"
    assert bundle.verify_bundle(destination)["matched"]
    copied = destination / "source/nested/demo"
    assert (copied / "asset.js").read_text() == "asset"
    assert not (copied / ".env").exists()
    assert not list(destination.rglob("__editable__*"))
    new_site = destination / "source/.venv/lib/python3.11/site-packages"
    assert (new_site / "hypershell-materialized.pth").read_text() == "../../../../nested\n"
    (source / "nested/demo/asset.js").write_text("old source mutation")
    assert (copied / "asset.js").read_text() == "asset"
    (copied / "asset.js").chmod(0o644)
    (copied / "asset.js").write_text("tampered")
    check = bundle.verify_bundle(destination)
    assert check["status"] == "drift" and check["changed_paths"] == ["source/nested/demo/asset.js"]


def test_build_refuses_existing_destination_and_incomplete_mapping(linux_build):
    source, site, prefix, node, destination = linux_build
    with pytest.raises(RunnerError, match="exactly match"):
        bundle.build_bundle(source, destination, prefix, node, {"other": "other"})
    destination.mkdir()
    (destination / "preserve").write_text("original")
    with pytest.raises(FileExistsError):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert (destination / "preserve").read_text() == "original"


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "pth", "collision"])
def test_unsafe_inputs_are_refused_and_new_output_cleaned(linux_build, kind):
    import os

    source, site, prefix, node, destination = linux_build
    if kind == "symlink":
        (source / "nested/demo/link").symlink_to(site / "dependency.py")
    elif kind == "hardlink":
        os.link(site / "dependency.py", site / "duplicate.py")
    elif kind == "fifo":
        os.mkfifo(site / "fifo")
    elif kind == "pth":
        (site / "malicious.pth").write_text("import os; os.system('never execute')")
    else:
        (site / "demo").mkdir()
    with pytest.raises(RunnerError):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert not destination.exists()


def test_manifest_tampering_is_rejected(linux_build):
    source, site, prefix, node, destination = linux_build
    bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    path = destination / bundle.MANIFEST
    document = json.loads(path.read_text())
    document["node_prefix"] = "/unapproved"
    path.chmod(0o644)
    path.write_text(json.dumps(document))
    with pytest.raises(RunnerError, match="digest"):
        bundle.verify_bundle(destination)


def test_explicit_linked_input_copy_produces_independent_output(linux_build):
    import os

    source, site, prefix, node, destination = linux_build
    os.link(site / "dependency.py", site / "duplicate.py")
    bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"}, copy_linked_inputs=True)
    copied = destination / "source/.venv/lib/python3.11/site-packages/dependency.py"
    assert copied.stat().st_nlink == 1
    assert not os.path.samefile(copied, site / "dependency.py")
    assert bundle.verify_bundle(destination)["matched"]


def test_relative_package_links_preserve_copied_internal_targets(linux_build):
    source, site, prefix, node, destination = linux_build
    package = source / "nested/demo"
    (package / ".bin").mkdir()
    (package / ".bin/asset").symlink_to("../asset.js")
    bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    copied = destination / "source/nested/demo/.bin/asset"
    assert copied.is_symlink() and copied.read_text() == "asset"
    assert copied.resolve().is_relative_to(destination)
    assert bundle.verify_bundle(destination)["matched"]


def test_app_environment_template_is_generated_without_source_values(linux_build):
    source, site, prefix, node, destination = linux_build
    package = source / "jiuwenswarm"
    package.mkdir()
    (package / "resources").mkdir()
    (package / "resources/.env.template").write_text("API_KEY=SOURCE_SECRET")
    (site / "__editable___demo_finder.py").write_text(
        f"MAPPING: dict = {{'jiuwenswarm': {str(package)!r}}}\nNAMESPACES: dict = {{}}\n"
    )
    bundle.build_bundle(source, destination, prefix, node, {"jiuwenswarm": "jiuwenswarm"})
    template = (destination / "source/jiuwenswarm/resources/.env.template").read_text()
    assert "SOURCE_SECRET" not in template and "API_KEY=" not in template


@pytest.mark.parametrize("kind", ["fifo", "symlink", "syntax"])
def test_editable_preflight_never_opens_special_files(linux_build, kind):
    import os

    source, site, prefix, node, destination = linux_build
    finder = site / "__editable___demo_finder.py"
    finder.unlink()
    if kind == "fifo":
        os.mkfifo(finder)
    elif kind == "symlink":
        finder.symlink_to(site / "dependency.py")
    else:
        finder.write_text("THIS PRIVATE SOURCE SHOULD NEVER APPEAR IN ERROR !!!")
    with pytest.raises(RunnerError) as error:
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert "PRIVATE SOURCE" not in str(error.value)
    assert not destination.exists()


def test_editable_metadata_has_a_combined_memory_budget(linux_build, monkeypatch):
    source, site, prefix, node, destination = linux_build
    monkeypatch.setattr(bundle, "MAX_EDITABLE_FILES", 1)
    with pytest.raises(RunnerError, match="declaration budget"):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert not destination.exists()


def test_directory_budget_and_manifest_budget_abort_publication(linux_build, monkeypatch):
    source, site, prefix, node, destination = linux_build
    monkeypatch.setattr(bundle, "MAX_DEPTH", 1)
    (site / "a/b/c").mkdir(parents=True)
    with pytest.raises(RunnerError, match="directory limit"):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert not destination.exists()
    monkeypatch.setattr(bundle, "MAX_DEPTH", 64)
    monkeypatch.setattr(bundle, "MAX_MANIFEST", 64)
    with pytest.raises(RunnerError, match="manifest exceeds"):
        bundle.build_bundle(source, destination, prefix, node, {"demo": "nested/demo"})
    assert not destination.exists()


def test_missing_bundle_refuses_privileged_execution_before_verification(monkeypatch):
    monkeypatch.setattr(bundle, "verify_bundle", lambda _: pytest.fail("must reject before inspecting a runtime"))
    with pytest.raises(RunnerError, match="runtime_bundle is required"):
        bundle.require_bundle_config({"source_dir": "/user/writable"})


@pytest.mark.parametrize("condition", ["drift", "source", "python", "node"])
def test_runtime_config_must_match_verified_bundle(monkeypatch, condition):
    runtime = {
        "runtime_bundle": "/releases/v1",
        "source_dir": "/releases/v1/source",
        "python_prefix": "/opt/python",
        "node_prefix": "/opt/node",
    }
    result = {
        "matched": condition != "drift",
        "runtime": {key: runtime.get(key) for key in ("source_dir", "python_prefix", "node_prefix")},
    }
    if condition != "drift":
        result["runtime"][
            {"source": "source_dir", "python": "python_prefix", "node": "node_prefix"}[condition]
        ] = "/different"
    monkeypatch.setattr(bundle, "verify_bundle", lambda _: result)
    with pytest.raises(RunnerError):
        bundle.require_bundle_config(runtime)
