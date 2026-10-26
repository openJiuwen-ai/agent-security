# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.routing import (
    CandidateKind,
    CommandDialect,
    RouteContext,
)
from agent_shield.tool_permission.toolguard.destructive_warning import (
    DestructiveWarningComponent,
)


def run(awaitable):
    return asyncio.run(awaitable)


def _shell_route(dialect: CommandDialect = CommandDialect.POSIX_SHELL) -> RouteContext:
    return RouteContext(
        kind=CandidateKind.ORIGINAL, command_dialect=dialect, is_shell=True
    )


@pytest.mark.parametrize(
    ("tool_name", "command", "expected"),
    [
        ("bash", "git reset --hard", "May discard uncommitted changes"),
        ("bash", "git push origin main --force", "May overwrite remote history"),
        ("bash", "DROP TABLE users", "May drop database objects"),
        ("powershell", "Remove-Item -Recurse -Force C:\\data",
         "May permanently remove files or directories"),
        ("pwsh", "Set-Content file.txt value", "May overwrite file contents"),
    ],
)
def test_warning_for_documented_destructive_command(tool_name, command, expected):
    result = run(PermissionEngine({"shell_allowlist": None}).check_permission(
        tool_name, {"command": command}
    ))

    assert result.warnings == [expected]


def test_warning_does_not_change_permission_level():
    engine = PermissionEngine({"shell_allowlist": None})
    baseline = run(engine.check_permission("bash", {"command": "echo safe"}))

    result = run(engine.check_permission("bash", {"command": "git reset --hard"}))

    assert result.permission is baseline.permission
    assert result.warnings


def test_component_uses_route_dialect_and_first_matching_rule():
    component = DestructiveWarningComponent()
    route = _shell_route()

    component.configure({"unrelated": "ignored"})
    result = run(
        component.evaluate(
            "bash",
            {"command": "git reset --hard && terraform destroy"},
            route=route,
        )
    )

    assert result is not None
    assert len(result.warnings) == 1
    assert result.warnings == ["May discard uncommitted changes"]
    assert result.permission is None
    assert result.matched_rule is None
    assert result.reason is None


@pytest.mark.parametrize(
    ("tool_name", "tool_args"),
    [
        ("bash", {"command": "echo safe"}),
        ("bash", {}),
        ("bash", {"command": 123}),
        ("cmd", {"command": "git reset --hard"}),
        ("read_file", {"path": "file.txt"}),
    ],
)
def test_no_warning_for_nonmatching_or_unhandled_input(tool_name, tool_args):
    result = run(PermissionEngine({"shell_allowlist": None}).check_permission(tool_name, tool_args))

    assert result.warnings == []


def test_warning_component_has_no_route_interests():
    assert not hasattr(DestructiveWarningComponent, "interests") or (
        getattr(DestructiveWarningComponent, "interests", None) is None
    )


@pytest.mark.parametrize(
    ("dialect", "command", "expected"),
    [
        (CommandDialect.POSIX_SHELL, "git branch -d feature", []),
        (CommandDialect.POSIX_SHELL, "GIT RESET --HARD", []),
        (CommandDialect.POSIX_SHELL, "drop table users", ["May drop database objects"]),
        (CommandDialect.POSIX_SHELL, "git clean -fd", ["May permanently delete untracked files"]),
        (CommandDialect.POSIX_SHELL, "git checkout -- .", ["May discard all unstaged changes"]),
        (CommandDialect.POSIX_SHELL, "git stash clear", ["May permanently discard stashed changes"]),
        (CommandDialect.POSIX_SHELL, "git branch -D feature", ["May force-delete a branch"]),
        (CommandDialect.POSIX_SHELL, "git commit --amend", ["May rewrite the last commit"]),
        (CommandDialect.POSIX_SHELL, "git merge --no-verify", ["May skip safety hooks"]),
        (CommandDialect.POSIX_SHELL, "TRUNCATE TABLE users", ["May truncate database table"]),
        (CommandDialect.POSIX_SHELL, "kubectl delete pod demo", ["May delete Kubernetes resources"]),
        (CommandDialect.POSIX_SHELL, "terraform destroy", ["May destroy Terraform infrastructure"]),
        (CommandDialect.POSIX_SHELL, "sudo true", [
            "sudo may require a password in non-interactive mode; configure NOPASSWD or run as root"
        ]),
        (CommandDialect.POSIX_SHELL, "Remove-Item -Force data", []),
        (CommandDialect.POWERSHELL, "Remove-Item -Force data",
         ["May permanently remove files or directories"]),
        (CommandDialect.POWERSHELL, "Remove-Item -Recurse data",
         ["May permanently remove files or directories"]),
        (CommandDialect.POWERSHELL, "Remove-Item data", []),
        (CommandDialect.POWERSHELL, "CLEAR-CONTENT file", ["May remove file contents"]),
        (CommandDialect.POWERSHELL, "Rename-Item a b", ["May rename or replace files"]),
        (CommandDialect.POWERSHELL, "Move-Item a b", ["May move or overwrite files"]),
        (CommandDialect.POWERSHELL, "git reset --hard", ["May discard uncommitted changes"]),
        (CommandDialect.POWERSHELL, "git push -f", ["May overwrite remote history"]),
        (CommandDialect.POWERSHELL, "git commit --amend", ["May rewrite the last commit"]),
        (CommandDialect.POWERSHELL, "terraform destroy", []),
    ],
)
def test_migrated_rule_behavior(dialect, command, expected):
    component = DestructiveWarningComponent()

    result = run(component.evaluate(
        "tool-name-is-not-used-for-dispatch",
        {"command": command},
        route=_shell_route(dialect),
    ))

    assert result == PermissionResult(warnings=expected)


@pytest.mark.parametrize("route", [
    None,
    RouteContext(kind=CandidateKind.ORIGINAL, is_shell=False),
    RouteContext(
        kind=CandidateKind.ORIGINAL,
        command_dialect=CommandDialect.CMD,
        is_shell=True,
    ),
    RouteContext(
        kind=CandidateKind.ORIGINAL,
        command_dialect=CommandDialect.UNKNOWN,
        is_shell=True,
    ),
])
def test_unsupported_route_does_not_contribute_a_result(route):
    result = run(DestructiveWarningComponent().evaluate(
        "bash", {"command": "git reset --hard"}, route=route,
    ))

    assert result is None


def test_generic_command_tool_uses_explicit_dialect():
    engine = PermissionEngine({"shell_allowlist": None})

    unknown = run(engine.check_permission("mcp_exec_command", {"command": "git reset --hard"}))
    known = run(engine.check_permission("mcp_exec_command", {
        "command": "git reset --hard", "shell": "bash",
    }))

    assert unknown.warnings == []
    assert known.warnings == ["May discard uncommitted changes"]


def test_configuration_refresh_does_not_change_warning_rules():
    engine = PermissionEngine({"shell_allowlist": None})
    args = {"command": "git reset --hard"}
    before = run(engine.check_permission("bash", args))

    engine.update_config({
        "dangerous_patterns": [],
        "tool_mode": {"mode": "bypass"},
        "rules": [],
        "shell_allowlist": None,
    })
    after = run(engine.check_permission("bash", args))

    assert after.warnings == before.warnings == ["May discard uncommitted changes"]


@pytest.mark.parametrize("level", list(PermissionLevel))
def test_warning_partial_result_preserves_permission_fields(level):
    warning = run(DestructiveWarningComponent().evaluate(
        "bash", {"command": "git reset --hard"},
        route=_shell_route(),
    ))
    assert warning is not None
    decision = PermissionResult(permission=level, matched_rule="rule", reason="reason")

    merged = PermissionEngine.merge_results([decision, warning])

    assert merged.permission is level
    assert merged.matched_rule == decision.matched_rule
    assert merged.reason == decision.reason
    assert merged.warnings == ["May discard uncommitted changes"]
