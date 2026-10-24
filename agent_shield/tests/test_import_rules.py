# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Guard the import layout of the agent_shield package.

Rules:
- The package root exports nothing and loads no submodule on import.
- Each submodule is its own facade; callers import from ``agent_shield.<sub>``.
- Inside a submodule, imports are relative.  Across submodules, only the other
  submodule's root may be imported (never its internals).
- Code outside agent_shield (jiuwenbox, agent_ssas) imports at most one level
  below the package root, and agent_shield never imports those projects.
"""

from __future__ import annotations

import ast
import subprocess
import sys
from pathlib import Path

import pytest

import agent_shield.tool_permission as tool_permission

PACKAGE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = PACKAGE_DIR.parent
SUBMODULES = ("tool_permission", "detection")


def _python_files(root: Path):
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts or "build" in path.relative_to(root).parts:
            continue
        yield path


def _imports(path: Path):
    """Yield (module, level) for every import statement in a file."""

    tree = ast.parse(path.read_bytes(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            yield node.module or "", node.level
        elif isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, 0


def test_package_root_loads_nothing() -> None:
    code = (
        "import sys, agent_shield\n"
        "loaded = [m for m in sys.modules if m.startswith('agent_shield.')]\n"
        "assert not loaded, loaded\n"
        "assert not [n for n in dir(agent_shield) if not n.startswith('_')]\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_tool_permission_facade_names_resolve() -> None:
    for name in tool_permission.__all__:
        assert hasattr(tool_permission, name), name


def test_guard_components_are_not_public() -> None:
    internal = {"NetGuardComponent", "FileGuardComponent", "HostGuardComponent",
                "TieredPolicyComponent", "InjectionComponent"}
    assert not internal & set(tool_permission.__all__)


@pytest.mark.parametrize("submodule", SUBMODULES)
def test_submodule_imports_are_relative_or_through_other_facade(submodule: str) -> None:
    offenders = []
    for path in _python_files(PACKAGE_DIR / submodule):
        for module, level in _imports(path):
            if level:
                continue
            parts = module.split(".")
            if parts[0] != "agent_shield":
                continue
            # Absolute self-imports must be relative; other submodules only via root.
            if len(parts) != 2 or parts[1] == submodule:
                offenders.append(f"{path.relative_to(PACKAGE_DIR)}: {module}")
    assert not offenders, offenders


def test_agent_shield_does_not_import_sibling_projects() -> None:
    offenders = []
    for path in _python_files(PACKAGE_DIR):
        if "tests" in path.relative_to(PACKAGE_DIR).parts:
            continue
        for module, _ in _imports(path):
            if module.split(".")[0] in {"jiuwenbox", "agent_ssas"}:
                offenders.append(f"{path.relative_to(PACKAGE_DIR)}: {module}")
    assert not offenders, offenders


@pytest.mark.parametrize("project", ("jiuwenbox", "agent_ssas"))
def test_other_projects_use_submodule_roots_only(project: str) -> None:
    root = REPO_ROOT / project
    if not root.is_dir():
        pytest.skip(f"{project} not present")
    offenders = []
    for path in _python_files(root):
        for module, level in _imports(path):
            parts = module.split(".")
            if not level and parts[0] == "agent_shield" and len(parts) > 2:
                offenders.append(f"{path.relative_to(REPO_ROOT)}: {module}")
    assert not offenders, offenders
