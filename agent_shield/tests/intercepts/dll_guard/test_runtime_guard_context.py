"""Execution-scoped grants use the SDK matcher and never broaden approvals."""

import pytest

from agent_shield.intercepts.native_call.dll_guard.context import RuntimeGuardContext
from agent_shield.tool_permission.runtime.grants import (
    build_operation_grant,
    operation_subject,
)


def _grant(path):
    return build_operation_grant("read_file", {"file_path": str(path)}, {}, path.parent)


def _matches(ctx, path, tool="read_file", **overrides):
    subject = operation_subject(tool, {"file_path": str(path)}, {}, path.parent)
    return ctx.matches(
        subject,
        **{
            "execution_id": ctx.execution_id,
            "policy_version": ctx.policy_version,
            **overrides,
        },
    )


def test_once_is_execution_scoped_and_reusable(tmp_path):
    path = tmp_path / "a.txt"
    ctx = RuntimeGuardContext("session", "call", "v1")
    ctx.remember("read_file", _grant(path), policy_version="v1")
    assert _matches(ctx, path)
    assert _matches(ctx, path)
    assert not _matches(ctx, path, "write_file")
    assert not _matches(ctx, tmp_path / "b.txt")
    next_call = RuntimeGuardContext("session", "call", "v1")
    assert not _matches(next_call, path)
    assert not _matches(ctx, path, execution_id=next_call.execution_id)


def test_host_grant_is_copied_and_source_is_checked(tmp_path):
    path = tmp_path / "a.txt"
    grant = _grant(path)
    ctx = RuntimeGuardContext("session", "call", "v1")
    with pytest.raises(ValueError, match="source tool"):
        ctx.remember("bash", grant, policy_version="v1")
    ctx.remember("read_file", grant, policy_version="v1")
    grant["pattern"] = "changed"
    assert _matches(ctx, path)


def test_duplicate_grants_keep_distinct_exact_and_parent_scopes(tmp_path):
    path = tmp_path / "dir" / "a.txt"
    ctx = RuntimeGuardContext("session", "call", "v1")
    parent = build_operation_grant(
        "read_file", {"file_path": str(path)}, {}, tmp_path, mode="allow_with_scope", scope="parent"
    )
    for _ in range(5):
        ctx.remember("read_file", parent, policy_version="v1")
    assert len(getattr(ctx, "_grants")) == 1
    assert not _matches(ctx, path, exact_only=True)

    exact = _grant(path)
    for _ in range(5):
        ctx.remember("read_file", exact, policy_version="v1")
    assert len(getattr(ctx, "_grants")) == 2
    assert _matches(ctx, path, exact_only=True)
    assert _matches(ctx, path.parent / "b.txt")
    assert not _matches(ctx, path.parent / "b.txt", exact_only=True)
    with pytest.raises(ValueError, match="source tool"):
        ctx.remember("bash", exact, policy_version="v1")
    with pytest.raises(ValueError, match="stale"):
        ctx.remember("read_file", exact, policy_version="v0")


def test_policy_change_and_finish_invalidate_grants(tmp_path):
    path = tmp_path / "a.txt"
    ctx = RuntimeGuardContext("session", "call", "v1")
    ctx.remember("read_file", _grant(path), policy_version="v1")
    ctx.update_policy_version("v2")
    assert not _matches(ctx, path)
    assert not _matches(ctx, path, policy_version="v1")
    with pytest.raises(ValueError, match="stale"):
        ctx.remember("read_file", _grant(path), policy_version="v1")
    ctx.remember("read_file", _grant(path), policy_version="v2")
    ctx.finish()
    ctx.finish()
    assert not ctx.active
    assert not _matches(ctx, path)
    with pytest.raises(ValueError, match="ended"):
        ctx.remember("read_file", _grant(path), policy_version="v2")


def test_parent_scope_stays_inside_execution_and_action(tmp_path):
    path = tmp_path / "dir" / "a.txt"
    ctx = RuntimeGuardContext("session", "call", "v1")
    grant = build_operation_grant(
        "read_file", {"file_path": str(path)}, {}, tmp_path, mode="allow_with_scope", scope="parent"
    )
    ctx.remember("read_file", grant, policy_version="v1")
    assert _matches(ctx, path.parent / "b.txt")
    assert not _matches(ctx, tmp_path / "b.txt")
    assert not _matches(ctx, path, "write_file")


@pytest.mark.parametrize(
    "values", [("", "call", "v1"), ("session", "", "v1"), ("session", "call", "")]
)
def test_context_requires_explicit_identity(values):
    with pytest.raises(ValueError, match="non-empty"):
        RuntimeGuardContext(*values)
