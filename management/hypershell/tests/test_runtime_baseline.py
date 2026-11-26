"""Unknown observations and corrupt references can never become a match."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import stat
from types import SimpleNamespace
from uuid import uuid4
import sys

import pytest

from hypershell.runner import runtime_baseline as baseline
from hypershell.runner.provenance import PACKAGES


def _fixture_digest(value):
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _seal(manifest):
    manifest["manifest_digest"] = _fixture_digest({k: v for k, v in manifest.items() if k != "manifest_digest"})
    return manifest


def _manifest():
    def code(letter):
        return {
            "status": "ok",
            "sha256": letter * 64,
            "files": 1,
            "unavailable_files": 0,
            "scope": {"suffixes": [".py"], "package_roots": ["package"]},
        }

    def file(letter):
        return {"path": "/arbitrary/location", "status": "ok", "sha256": letter * 64}

    return _seal(
        {
            "schema_version": 1,
            "kind": "observed",
            "hypershell": {"version": "0.1.0.dev0", "code": code("a"), "source": {"status": "unknown"}},
            "application": {
                "code": code("b"),
                "source": {"status": "unknown"},
                "interpreter": {
                    "status": "ok",
                    "python": {"version": "3.11.9", "implementation": "CPython", "executable": "/runtime/python"},
                    "packages": {name: {"status": "not_installed", "version": None} for name in PACKAGES},
                    "backend_code": {
                        **code("c"),
                        "scope": "jiuwenbox import roots; source/native code only; no symlinks, data or caches",
                        "bytes": 100,
                        "roots": ["/backend"],
                        "limits": {"files": 20000, "bytes": 268435456, "entries": 100000},
                    },
                    "distributions": {
                        "status": "ok",
                        "count": 1,
                        "sha256": _fixture_digest([{"name": "fixture", "version": "1.0"}]),
                        "entries": [{"name": "fixture", "version": "1.0"}],
                        "limit": 10000,
                        "scope": "PEP 503 normalized name and validated metadata version only",
                        "unavailable_entries": 0,
                    },
                },
            },
            "collector_python": {"version": "3.11.9", "implementation": "CPython", "executable": "/control/python"},
            "platform": {"system": "Linux", "release": "5.15.0", "version": "build", "machine": "x86_64"},
            "configuration": {"admin": file("e"), "runtime": file("f"), "requests": {"u1": file("1"), "u2": file("2")}},
            "dependency_overlay": None,
        }
    )


def _change(value, path, replacement):
    for key in path[:-1]:
        value = value[key]
    value[path[-1]] = replacement


def test_complete_observed_coverage_can_be_captured_and_matched():
    manifest = _manifest()
    reference = baseline.make_baseline(manifest)
    assert baseline.validate_baseline(reference) == reference
    result = baseline.compare_baseline(reference, manifest)
    assert result["matched"] and result["differences"] == []
    assert reference["limitations"] == baseline.LIMITATIONS


def test_paths_git_state_and_capture_context_do_not_pollute_content_fingerprint():
    initial = _manifest()
    reference = baseline.make_baseline(initial)
    other = deepcopy(initial)
    other["hypershell"]["source"] = {"status": "ok", "commit": "new", "dirty": True, "path": "/other-checkout"}
    other["application"]["source"] = {"status": "unknown", "path": "/relocated"}
    other["collector_python"]["executable"] = "/another/control/python"
    other["application"]["interpreter"]["python"]["executable"] = "/another/application/python"
    other["configuration"]["admin"]["path"] = "/another/configuration"
    assert baseline.compare_baseline(reference, _seal(other))["matched"]


@pytest.mark.parametrize(
    "path,replacement,field",
    [
        (("hypershell", "code", "sha256"), "3" * 64, "hypershell_code_sha256"),
        (("application", "code", "sha256"), "3" * 64, "application_code_sha256"),
        (("application", "interpreter", "backend_code", "sha256"), "3" * 64, "backend_code_sha256"),
        (("application", "interpreter", "distributions", "sha256"), "3" * 64, "distributions_sha256"),
        (("application", "interpreter", "python", "version"), "3.12.0", "application_python.version"),
        (("platform", "release"), "6.1.0", "platform.release"),
        (("configuration", "requests", "u1", "sha256"), "3" * 64, "configuration.requests.u1"),
    ],
)
def test_each_measured_component_reports_drift_without_adopting_it(path, replacement, field):
    initial = _manifest()
    reference = baseline.make_baseline(initial)
    saved = deepcopy(reference)
    changed = deepcopy(initial)
    _change(changed, path, replacement)
    if path == ("application", "interpreter", "distributions", "sha256"):
        changed["application"]["interpreter"]["distributions"]["entries"][0]["version"] = "2.0"
        changed["application"]["interpreter"]["distributions"]["sha256"] = _fixture_digest(
            changed["application"]["interpreter"]["distributions"]["entries"]
        )
    result = baseline.compare_baseline(reference, _seal(changed))
    assert not result["matched"] and result["status"] == "drift"
    assert any(item["field"] == field for item in result["differences"])
    assert reference == saved


@pytest.mark.parametrize(
    "path,value",
    [
        (("hypershell", "code", "status"), "unknown"),
        (("application", "code", "status"), "incomplete"),
        (("application", "interpreter", "status"), "unknown"),
        (("application", "interpreter", "backend_code", "status"), "unknown"),
        (("application", "interpreter", "backend_code", "unavailable_files"), True),
        (("application", "interpreter", "distributions", "status"), "incomplete"),
        (("application", "interpreter", "packages", "jiuwenbox", "status"), "unknown"),
        (("configuration", "admin", "sha256"), None),
        (("configuration", "requests"), {}),
    ],
)
def test_missing_unknown_and_incomplete_observations_refuse_capture(path, value):
    manifest = _manifest()
    _change(manifest, path, value)
    with pytest.raises(baseline.BaselineError):
        baseline.make_baseline(_seal(manifest))


def test_a_subset_of_users_is_a_real_coverage_change():
    original = _manifest()
    reference = baseline.make_baseline(original)
    del original["configuration"]["requests"]["u2"]
    result = baseline.compare_baseline(reference, _seal(original))
    assert result["status"] == "drift"
    assert any(item["field"] == "configuration.requests.u2" for item in result["differences"])


def test_disabled_and_enabled_overlay_are_distinct():
    original = _manifest()
    reference = baseline.make_baseline(original)
    original["dependency_overlay"] = {"status": "ok", "kind": "directory", "sha256": "a" * 64}
    result = baseline.compare_baseline(reference, _seal(original))
    assert result["status"] == "drift" and result["differences"][0]["field"] == "overlay"


def test_corrupt_manifest_or_reference_digests_fail():
    manifest = _manifest()
    reference = baseline.make_baseline(manifest)
    manifest["platform"]["release"] = "modified"
    with pytest.raises(baseline.BaselineError, match="manifest digest"):
        baseline.make_baseline(manifest)
    reference["fingerprint"]["platform"]["release"] = "modified"
    with pytest.raises(baseline.BaselineError, match="document digest"):
        baseline.validate_baseline(reference)


def test_resealed_reference_still_rejects_unsupported_schema():
    reference = baseline.make_baseline(_manifest())
    reference["fingerprint"]["extra"] = "not-supported"
    reference["fingerprint_digest"] = _fixture_digest(reference["fingerprint"])
    reference["baseline_digest"] = _fixture_digest({k: v for k, v in reference.items() if k != "baseline_digest"})
    with pytest.raises(baseline.BaselineError, match="fingerprint schema"):
        baseline.validate_baseline(reference)


@pytest.mark.parametrize("text", ['{"schema_version":1,"schema_version":1}', '{"value":NaN}'])
def test_strict_json_loader_rejects_duplicate_and_nonfinite_values(monkeypatch, text):
    class Document:
        @staticmethod
        def lstat():
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_nlink=1, st_size=len(text))

        @staticmethod
        def read_text(**kwargs):
            return text

    monkeypatch.setattr(baseline, "trusted", lambda _: Document())
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline(Path("reference"))


def test_check_cannot_overwrite_reference_or_runtime_inputs(monkeypatch, capsys):
    monkeypatch.setattr(baseline, "require_admin", lambda: None)
    monkeypatch.setattr(baseline, "trusted", lambda value, **kwargs: value)
    monkeypatch.setattr(baseline, "_observe", lambda _: pytest.fail("must reject before collection"))
    for output in ("reference.json", "admin.yaml", "runtime.yaml", "request-u1.yaml"):
        assert (
            baseline.main(
                [
                    "check",
                    "--users",
                    "u1",
                    "--config",
                    "admin.yaml",
                    "--runtime",
                    "runtime.yaml",
                    "--baseline",
                    "reference.json",
                    "--output",
                    output,
                ]
            )
            == 2
        )
    assert "overwrite" in capsys.readouterr().err


def test_cli_check_preserves_reference_and_reports_drift(monkeypatch, capsys):
    observed = _manifest()
    reference = baseline.make_baseline(observed)
    saved = deepcopy(reference)
    observed["platform"]["release"] = "changed"
    _seal(observed)
    monkeypatch.setattr(baseline, "require_admin", lambda: None)
    monkeypatch.setattr(baseline, "load_baseline", lambda _: reference)
    monkeypatch.setattr(baseline, "_observe", lambda _: observed)
    assert baseline.main(["check", "--users", "u1", "u2", "--baseline", "reference.json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "drift"
    assert reference == saved


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, 2, None])
def test_runtime_version_is_an_exact_supported_integer(tmp_path, monkeypatch, capsys, version):
    monkeypatch.setattr(baseline, "require_admin", lambda: None)
    monkeypatch.setattr(baseline, "trusted", lambda path, **kwargs: path)
    monkeypatch.setattr(baseline.AdminConfig, "load", lambda _: SimpleNamespace(users={"u1": object()}))
    monkeypatch.setattr(baseline, "load_document", lambda _: {"version": version})
    output = tmp_path / "baseline.json"
    assert baseline.main(["capture", "--users", "u1", "--output", str(output)]) == 2
    assert "unsupported runtime version" in capsys.readouterr().err
    assert not output.exists()


def test_missing_overlay_cannot_be_frozen_as_explicitly_disabled():
    manifest = _manifest()
    del manifest["dependency_overlay"]
    with pytest.raises(baseline.BaselineError, match="overlay state is unknown"):
        baseline.make_baseline(_seal(manifest))


def test_stored_distribution_entries_must_match_their_internal_digest():
    manifest = _manifest()
    manifest["application"]["interpreter"]["distributions"]["entries"][0]["version"] = "changed"
    with pytest.raises(baseline.BaselineError, match="internally inconsistent"):
        baseline.make_baseline(_seal(manifest))


def test_output_inside_source_tree_is_rejected_even_for_replace(tmp_path, monkeypatch, capsys):
    source = tmp_path / "measured-source"
    source.mkdir()
    manifest = _manifest()
    manifest["application"]["code"]["path"] = str(source)
    monkeypatch.setattr(baseline, "require_admin", lambda: None)
    monkeypatch.setattr(baseline, "_observe", lambda _: manifest)
    monkeypatch.setattr(baseline, "trusted", lambda path, **kwargs: path)
    monkeypatch.setattr(baseline, "load_document", lambda _: {"source_dir": str(source).replace("\\", "/")})
    # Avoid Linux-path syntax validation on Windows; output ancestry is the
    # property exercised here, while runtime syntax has independent tests.
    monkeypatch.setattr(baseline, "_path", lambda value, label: value)
    output = source / "module.py"
    assert baseline.main(["capture", "--users", "u1", "--output", str(output), "--replace"]) == 2
    assert "outside measured source" in capsys.readouterr().err
    assert not output.exists()


@pytest.mark.skipif(sys.platform != "linux", reason="private atomic publishing uses Linux file primitives")
def test_competing_captures_cannot_clobber_an_existing_reference(monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    folder = Path(__file__).resolve().parents[1] / ".test-tmp" / ("baseline-race-" + uuid4().hex)
    folder.mkdir(parents=True)
    target = folder / "reference.json"
    monkeypatch.setattr(baseline, "require_admin", lambda: None)
    monkeypatch.setattr(baseline, "trusted", lambda path, **kwargs: path)
    monkeypatch.setattr(baseline, "load_document", lambda _: {})
    start = Barrier(2)
    manifests = {f"candidate-{index}.yaml": _manifest() for index in (1, 2)}
    for name, manifest in manifests.items():
        manifest["platform"]["release"] = name
        _seal(manifest)

    def observe(args):
        # Both captures must pass the preflight existence check before either publishes.
        start.wait(timeout=5)
        manifest = manifests.get(args.config.name)
        assert manifest is not None
        return manifest

    monkeypatch.setattr(baseline, "_observe", observe)

    def capture(name):
        return baseline.main(["capture", "--config", name, "--users", "u1", "u2", "--output", str(target)])

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(capture, manifests))
    assert sorted(results) == [0, 2]
    published = baseline.validate_baseline(json.loads(target.read_text(encoding="utf-8")))
    winner = list(manifests.values())[results.index(0)]
    assert published["observed_manifest_digest"] == winner["manifest_digest"]
    assert target.stat().st_mode & 0o777 == 0o600
    assert target.stat().st_nlink == 1
