"""The shell bootstrap must drop caller Python settings before Python starts."""

import importlib.util
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.skipif(sys.platform != "linux", reason="requires POSIX shell")
def test_control_bootstrap_clears_caller_env_and_preserves_arguments(tmp_path):
    path = Path(__file__).resolve().parents[1] / "examples/demo/install_vm_demo.py"
    spec = importlib.util.spec_from_file_location("runtime_lab_installer", path)
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)
    control = tmp_path / "control interpreter"
    control.write_text("#!/bin/sh\n/usr/bin/env\nprintf 'ARG=<%s>\\n' \"$@\"\n")
    control.chmod(0o755)
    wrapper = tmp_path / "hypershell-demo"
    wrapper.write_text(installer.control_wrapper(control))
    wrapper.chmod(0o755)
    result = subprocess.run(
        [str(wrapper), "status", "a b", "$(untrusted)"],
        env={"PYTHONHOME": "/caller/unsafe", "PYTHONPATH": "/caller/unsafe", "PRIVATE_MODEL_KEY": "DO_NOT_INHERIT"},
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    assert "DO_NOT_INHERIT" not in result.stdout and "/caller/unsafe" not in result.stdout
    assert "PYTHONPATH=/opt/hypershell-demo" in result.stdout
    assert "ARG=<-P>" in result.stdout and "ARG=<-B>" in result.stdout
    assert "ARG=<a b>" in result.stdout and "ARG=<$(untrusted)>" in result.stdout


@pytest.mark.skipif(
    sys.platform != "linux" or not hasattr(os, "geteuid") or os.geteuid() != 0,
    reason="requires a Linux administrator to verify pre-import refusal",
)
def test_installer_rejects_mutable_source_before_importing_control_code(tmp_path):
    import shutil

    repository = Path(__file__).resolve().parents[1]
    stage = tmp_path / "checkout"
    script = stage / "examples/demo/install_vm_demo.py"
    script.parent.mkdir(parents=True)
    shutil.copyfile(repository / "examples/demo/install_vm_demo.py", script)
    package = stage / "hypershell"
    package.mkdir()
    marker = tmp_path / "untrusted-code-executed"
    (package / "__init__.py").write_text(f"from pathlib import Path\nPath({str(marker)!r}).touch()\n")
    stage.chmod(0o777)
    result = subprocess.run(
        [
            sys.executable,
            "-P",
            "-B",
            str(script),
            "--runtime-bundle",
            "/absent-bundle",
            "--control-python",
            sys.executable,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode != 0 and "root-controlled source directory" in result.stderr
    assert not marker.exists()
