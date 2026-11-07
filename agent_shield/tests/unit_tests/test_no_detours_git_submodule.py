# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Regression: Detours must not be a git submodule of this repo.

jiuwenswarm CI `uv sync` clones agent-security; a GitHub Detours submodule
makes install hang/fail on machines that cannot reach github.com.
"""

from __future__ import annotations

from pathlib import Path

# agent_shield/tests/unit_tests/this_file.py → repo root is parents[3]
_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_repo_has_no_gitmodules() -> None:
    assert not (_REPO_ROOT / ".gitmodules").exists(), (
        ".gitmodules must not exist; Detours is an external build-time checkout"
    )


def test_detours_is_not_a_gitlink() -> None:
    detours = (
        _REPO_ROOT
        / "agent_shield"
        / "native"
        / "windows-process-guard"
        / "third_party"
        / "detours"
    )
    # Path may be absent (gitignored) or a plain directory checkout — never a
    # gitlink recorded in the index. `.git` file inside would mean submodule.
    if detours.exists():
        assert not (detours / ".git").exists(), (
            "third_party/detours must not be a git submodule checkout"
        )
