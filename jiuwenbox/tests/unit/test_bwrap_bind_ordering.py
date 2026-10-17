# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for the bwrap bind ordering fixes (design doc section 4.4).

These are pure ``BwrapConfig.to_args()`` tests: no bwrap binary or Linux
kernel is needed. They pin the ordering invariants from the dev-stable
patches ``32a5caead`` (depth-partitioned binds) and ``fb0dc85de`` (rw parent
emitted before nested ro child).

``BwrapConfig`` is built directly (rather than via ``from_policy``) so the
ordering logic is exercised without the policy path-expansion / uid-gid
resolution that is platform-specific.
"""

from __future__ import annotations

from jiuwenbox.supervisor.bwrap import BwrapConfig


def _bind_pairs(args: list[str]) -> list[tuple[str, str, str]]:
    """Return ``[(flag, source, target), ...]`` for all bind mounts in order."""
    pairs: list[tuple[str, str, str]] = []
    i = 0
    while i < len(args):
        if args[i] in ("--ro-bind", "--bind", "--dev-bind"):
            pairs.append((args[i], args[i + 1], args[i + 2]))
            i += 3
        else:
            i += 1
    return pairs


def _config(ro: list[tuple[str, str]], rw: list[tuple[str, str]]) -> BwrapConfig:
    cfg = BwrapConfig(command=["true"])
    cfg.ro_binds = list(ro)
    cfg.rw_binds = list(rw)
    return cfg


class TestBindOrdering:
    def test_rw_parent_emitted_before_ro_child(self):
        """fb0dc85de: a ro child nested in an rw parent must come after the
        rw parent so the child's read-only mount wins."""
        args = _config(
            ro=[("/h/ro", "/app/cache")],
            rw=[("/h/rw", "/app")],
        ).to_args()
        binds = _bind_pairs(args)
        rw_parent_idx = next(
            i for i, (f, s, d) in enumerate(binds) if f == "--bind" and d == "/app"
        )
        ro_child_idx = next(
            i
            for i, (f, s, d) in enumerate(binds)
            if f == "--ro-bind" and d == "/app/cache"
        )
        assert rw_parent_idx < ro_child_idx, binds

    def test_ro_child_same_depth_sibling_ordering_is_stable(self):
        """Same-depth binds keep ro before rw (32a5caead)."""
        args = _config(
            ro=[("/h/a", "/x")],
            rw=[("/h/b", "/y")],
        ).to_args()
        binds = _bind_pairs(args)
        ro_idx = next(
            i for i, (f, s, d) in enumerate(binds) if f == "--ro-bind" and d == "/x"
        )
        rw_idx = next(
            i for i, (f, s, d) in enumerate(binds) if f == "--bind" and d == "/y"
        )
        assert ro_idx < rw_idx, binds

    def test_multi_level_nesting_deepest_last(self):
        """Multi-level nesting orders by depth: shallowest first, deepest last."""
        args = _config(
            ro=[("/h/ro", "/a/b/c/d")],
            rw=[("/h/rw", "/a")],
        ).to_args()
        binds = _bind_pairs(args)
        depths = [len(d.rstrip("/").split("/")) for f, s, d in binds if d != "/"]
        assert depths == sorted(depths), binds

    def test_same_path_rw_overrides_ro(self):
        """Same target path: ro emitted first, rw second (rw wins)."""
        args = _config(
            ro=[("/h/ro", "/shared")],
            rw=[("/h/rw", "/shared")],
        ).to_args()
        binds = _bind_pairs(args)
        shared = [(f, s) for f, s, d in binds if d == "/shared"]
        assert shared == [("--ro-bind", "/h/ro"), ("--bind", "/h/rw")], binds

    def test_policy_binds_not_shadowed_by_directories(self):
        """32a5caead: the bind target parent dirs must be created (and sorted)
        so policy bind mounts are not shadowed by ordinary directories."""
        args = _config(
            ro=[("/h/ro", "/opt/tool")],
            rw=[],
        ).to_args()
        binds = _bind_pairs(args)
        # The ro bind survives and is present exactly once.
        ro_binds = [(f, s, d) for f, s, d in binds if d == "/opt/tool"]
        assert ro_binds == [("--ro-bind", "/h/ro", "/opt/tool")], binds