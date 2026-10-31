# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""PermissionEngine wiring for W1b host guard and W2 file / control-plane guards.

Covers component construction, whole-config replacement, and evaluate results.
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel, PermissionResult
from agent_shield.tool_permission.fileguard.component import (
    FileGuardComponent,
    ImmutableControlPlaneComponent,
)
from agent_shield.tool_permission.hostguard import HostGuardComponent

_QUIET = {
    "tools": {
        "bash": "allow",
        "powershell": "allow",
        "mcp_exec_command": "allow",
        "write_file": "allow",
    },
    "package_builtin_rules": False,
    "shell_allowlist": None,
    "guard_actions": {"parse_unavailable": "allow"},
}


def _run(awaitable):
    return asyncio.run(awaitable)


def _check(engine: PermissionEngine, tool: str, args: dict[str, object]) -> PermissionResult:
    return _run(engine.check_permission(tool, args))


def _base(**overrides: object) -> dict[str, object]:
    config: dict[str, object] = dict(_QUIET)
    config.update(overrides)
    return config


class _RecordingEngine(PermissionEngine):
    """Records each component tuple produced by ``_build_components``."""

    def __init__(self, config: dict[str, object] | None = None) -> None:
        self.built: list[tuple[object, ...]] = []
        super().__init__(config)

    def _build_components(self):
        components = super()._build_components()
        self.built.append(components)
        return components


def test_build_components_registers_w1b_and_w2() -> None:
    engine = _RecordingEngine(_base())

    assert len(engine.built) == 1
    kinds = [type(component) for component in engine.built[0]]
    assert HostGuardComponent in kinds
    assert FileGuardComponent in kinds
    assert ImmutableControlPlaneComponent in kinds
    assert kinds.index(HostGuardComponent) < kinds.index(FileGuardComponent)
    assert kinds.index(FileGuardComponent) < kinds.index(ImmutableControlPlaneComponent)


def test_update_config_rebuilds_components() -> None:
    engine = _RecordingEngine(_base())
    first = engine.built[0]

    engine.update_config(_base(host_guard={"enabled": True}))

    assert len(engine.built) == 2
    assert engine.built[1] is not first
    assert all(left is not right for left, right in zip(first, engine.built[1], strict=True))


def test_host_guard_update_config_toggles_kill_and_shell_mismatch() -> None:
    off = _base(host_guard={"enabled": False})
    engine = PermissionEngine(off)
    quiet = _check(engine, "bash", {"command": "pkill -f jiuwenswarm"})
    assert quiet.matched_rule != "host_guard:safety"

    engine.update_config(
        _base(host_guard={"enabled": True, "shell_mismatch": True})
    )
    killed = _check(engine, "bash", {"command": "pkill -f jiuwenswarm"})
    assert killed.permission is PermissionLevel.DENY
    assert killed.matched_rule == "host_guard:safety"
    mismatch = _check(engine, "bash", {"command": "Get-ChildItem"})
    assert mismatch.permission is PermissionLevel.DENY
    assert mismatch.matched_rule == "host_guard:shell_mismatch"

    engine.update_config(
        _base(host_guard={"enabled": True, "shell_mismatch": False})
    )
    allowed = _check(engine, "bash", {"command": "Get-ChildItem"})
    assert allowed.matched_rule != "host_guard:shell_mismatch"


def test_host_guard_reads_cmd_and_core_powershell() -> None:
    engine = PermissionEngine(_base(host_guard={"enabled": True}))
    via_cmd = _check(engine, "bash", {"cmd": "pkill -f jiuwenswarm"})
    assert via_cmd.permission is PermissionLevel.DENY
    assert via_cmd.matched_rule == "host_guard:safety"
    via_core = _check(engine, "core.powershell", {"command": "pkill -f jiuwenswarm"})
    assert via_core.permission is PermissionLevel.DENY
    assert via_core.matched_rule == "host_guard:safety"


def test_mcp_exec_kill_is_denied_but_worktree_is_not() -> None:
    with tempfile.TemporaryDirectory() as root:
        engine = PermissionEngine(_base(
            host_guard={"enabled": True, "worktree_guard": True},
            runtime={"workspace_root": root, "project_root": root},
        ))
        killed = _check(engine, "mcp_exec_command", {"command": "pkill -f jiuwenswarm"})
        assert killed.permission is PermissionLevel.DENY
        assert killed.matched_rule == "host_guard:safety"

        outside = _check(
            engine,
            "mcp_exec_command",
            {"command": "git worktree add ../outside-wt -b feature HEAD"},
        )
        assert outside.matched_rule != "host_guard:safety"

        bash_outside = _check(
            engine,
            "bash",
            {"command": "git worktree add ../outside-wt -b feature HEAD"},
        )
        assert bash_outside.permission is PermissionLevel.DENY
        assert bash_outside.matched_rule == "host_guard:safety"
        assert bash_outside.reason is not None
        assert "worktree" in bash_outside.reason


def test_worktree_words_outside_git_add_are_allowed() -> None:
    with tempfile.TemporaryDirectory() as root:
        engine = PermissionEngine(_base(
            host_guard={
                    "enabled": True,
                    "worktree_guard": True,
                    "shell_mismatch": False,
                },
            runtime={"workspace_root": root, "project_root": root},
        ))
        for command in (
            'git commit -m "fix worktree add bug"',
            'grep -rn "worktree add" docs/',
            "echo worktree add",
        ):
            result = _check(engine, "bash", {"command": command})
            assert result.matched_rule != "host_guard:safety", command


def test_quoted_worktree_targets_cannot_leave_the_project() -> None:
    with tempfile.TemporaryDirectory() as root:
        engine = PermissionEngine(_base(
            host_guard={
                    "enabled": True,
                    "worktree_guard": True,
                    "shell_mismatch": False,
                },
            runtime={"workspace_root": root, "project_root": root},
        ))
        outside = (
            'git worktree add "../x"',
            'git worktree add -b f "../y" HEAD',
            "git worktree add ../x",
            "git -C ../other worktree add ../x",
            "cd /tmp && git worktree add ../x",
        )
        if os.name == "nt":
            outside = (
                *outside,
                'git worktree add "C:/Windows/evil"',
                r"git worktree add C:\outside\wt",
            )
        for command in outside:
            result = _check(engine, "bash", {"command": command})
            assert result.permission is PermissionLevel.DENY, command
            assert result.matched_rule == "host_guard:safety", command
        inside = _check(
            engine,
            "bash",
            {"command": 'git worktree add ".worktrees/ok"'},
        )
        assert inside.matched_rule != "host_guard:safety"


def test_permissions_enabled_false_disables_checks() -> None:
    engine = PermissionEngine({
        "enabled": False,
        "host_guard": {"enabled": True},
        "tools": {"bash": "allow"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
    })
    result = _check(engine, "bash", {"command": "pkill -f jiuwenswarm"})
    assert result.permission is PermissionLevel.ALLOW
    assert result.reason == "Permission system is disabled"


_BUILTIN_SENSITIVE_PATHS = (
    {"id": "any_ssh", "path": "**/.ssh/**", "match": "glob", "action": "deny"},
    {"id": "any_env", "path": "**/.env", "match": "glob", "action": "deny"},
    {"id": "any_pem", "path": "**/*.pem", "match": "glob", "action": "deny"},
)


def test_builtin_sensitive_paths_keep_the_original_floor() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        root = Path(workspace)
        ssh_key = root / ".ssh" / "id_rsa"
        env_file = root / ".env"
        pem = root / "keys" / "server.pem"
        notes = root / "notes.txt"
        guard = {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
        }
        open_config = _base(
            package_builtin_rules=True,
            file_guard=guard,
            runtime={"workspace_root": workspace},
        )
        closed = PermissionEngine(_base(
            package_builtin_rules=True,
            file_guard=guard,
            runtime={"workspace_root": workspace},
            builtin={"sensitive_paths": list(_BUILTIN_SENSITIVE_PATHS)},
        ))
        widened = PermissionEngine(_base(
            package_builtin_rules=True,
            file_guard={
                    **guard,
                    "paths": [{
                        "path": "**/.ssh/**",
                        "match": "glob",
                        "read": "allow",
                        "write": "allow",
                        "exec": "allow",
                    }],
                },
            runtime={"workspace_root": workspace},
            builtin={"sensitive_paths": list(_BUILTIN_SENSITIVE_PATHS)},
        ))
        disabled = PermissionEngine(_base(
            file_guard=guard,
            runtime={"workspace_root": workspace},
            builtin={"sensitive_paths": list(_BUILTIN_SENSITIVE_PATHS)},
        ))
        plain = PermissionEngine(open_config)
        assert _check(plain, "read_file", {"path": str(ssh_key)}).permission is not PermissionLevel.DENY
        for engine in (closed, widened):
            for path in (ssh_key, env_file, pem):
                result = _check(engine, "read_file", {"path": str(path)})
                assert result.permission is PermissionLevel.DENY, path
            assert _check(engine, "read_file", {"path": str(notes)}).permission is not PermissionLevel.DENY
        skipped = _check(disabled, "read_file", {"path": str(ssh_key)})
        assert skipped.permission is not PermissionLevel.DENY


def test_file_guard_and_immutable_follow_update_config() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        secret = Path(workspace) / "secret.txt"
        control = Path(workspace) / "control"
        control.mkdir()
        target = control / "config.yaml"
        disabled = _base(
            file_guard={"enabled": False},
            runtime={"workspace_root": workspace},
        )
        engine = PermissionEngine(disabled)
        open_write = _check(engine, "write_file", {"path": str(target)})
        assert open_write.matched_rule != "immutable_control_plane"

        engine.update_config(_base(
            file_guard={
                    "enabled": True,
                    "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
                    "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
                },
            runtime={"workspace_root": workspace, "immutable_control_roots": [str(control)]},
        ))
        outside = Path(workspace).parent / "outside.txt"
        denied = _check(engine, "read_file", {"path": str(outside)})
        assert denied.permission is PermissionLevel.DENY
        assert denied.matched_rule is not None
        assert denied.matched_rule.startswith("file_guard")

        protected = _check(engine, "write_file", {"path": str(target)})
        assert protected.permission is PermissionLevel.DENY
        assert protected.matched_rule == "immutable_control_plane"

        inside = _check(engine, "read_file", {"path": str(secret)})
        assert inside.permission is not PermissionLevel.DENY


def test_failed_update_config_keeps_previous_host_guard() -> None:
    engine = PermissionEngine(_base(host_guard={"enabled": True}))
    killed = _check(engine, "bash", {"command": "pkill -f jiuwenswarm"})
    assert killed.matched_rule == "host_guard:safety"

    with pytest.raises(TypeError, match="host_guard.enabled"):
        engine.update_config(_base(host_guard={"enabled": "yes"}))

    assert engine.config["host_guard"]["enabled"] is True
    still_killed = _check(engine, "bash", {"command": "pkill -f jiuwenswarm"})
    assert still_killed.matched_rule == "host_guard:safety"


def test_shell_paths_reach_file_guard_and_immutable() -> None:
    with tempfile.TemporaryDirectory() as workspace:
        control = Path(workspace) / "control"
        control.mkdir()
        target = (control / "config.yaml").as_posix()
        engine = PermissionEngine(_base(
            file_guard={
                    "enabled": True,
                    "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
                    "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
                },
            runtime={
                "workspace_root": workspace,
                "immutable_control_roots": [str(control)],
            },
        ))
        outside = (Path(workspace).parent / "outside.txt").as_posix()
        denied = _check(engine, "bash", {"command": f"cat {outside}"})
        assert denied.permission is PermissionLevel.DENY
        assert denied.matched_rule is not None
        assert denied.matched_rule.startswith("file_guard")

        protected = _check(engine, "mcp_exec_command", {"command": f"rm {target}"})
        assert protected.permission is PermissionLevel.DENY
        assert protected.matched_rule == "immutable_control_plane"


def test_failed_update_keeps_the_previous_workspace() -> None:
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as other:
        inside = Path(workspace) / "notes.txt"
        elsewhere = Path(other) / "notes.txt"
        engine = PermissionEngine(_base(
            file_guard={
                    "enabled": True,
                    "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
                    "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
                },
            runtime={"workspace_root": workspace},
        ))
        assert _check(engine, "read_file", {"path": str(inside)}).permission is not PermissionLevel.DENY
        assert _check(engine, "read_file", {"path": str(elsewhere)}).permission is PermissionLevel.DENY

        with pytest.raises(ValueError, match="net_guard.enabled"):
            engine.update_config(_base(
                file_guard={"enabled": True},
                runtime={"workspace_root": other},
                net_guard={"enabled": "nope"},
            ))

        assert engine.config["runtime"]["workspace_root"] == workspace
        assert _check(engine, "read_file", {"path": str(inside)}).permission is not PermissionLevel.DENY
        assert _check(engine, "read_file", {"path": str(elsewhere)}).permission is PermissionLevel.DENY


def test_top_level_tools_and_host_guard() -> None:
    engine = PermissionEngine({
        "tools": {"bash": "deny"},
        "package_builtin_rules": False,
        "shell_allowlist": None,
        "host_guard": {"enabled": True, "shell_mismatch": False},
    })
    baseline = _check(engine, "bash", {"command": "echo hi"})
    assert baseline.permission is PermissionLevel.DENY
    killed = _check(engine, "powershell", {"command": "pkill -f jiuwenswarm"})
    assert killed.permission is PermissionLevel.DENY
    assert killed.matched_rule == "host_guard:safety"


def test_evaluate_global_policy_directly_sees_host_guard() -> None:
    engine = PermissionEngine(_base(host_guard={"enabled": True}))
    level, rule = _run(
        engine.evaluate_global_policy_directly("bash", {"command": "pkill -f jiuwenswarm"})
    )
    assert level is PermissionLevel.DENY
    assert rule == "host_guard:safety"


def test_protected_patterns_apply_to_mcp_exec() -> None:
    engine = PermissionEngine(_base(host_guard={
            "enabled": True,
            "protected_patterns": [
                {"pattern": r"\bdo-not-run\b", "reason": "blocked custom"},
            ],
        }))
    builtin = _check(engine, "mcp_exec_command", {"command": "pkill -f jiuwenswarm"})
    assert builtin.permission is PermissionLevel.DENY
    assert builtin.matched_rule == "host_guard:safety"
    replaced = _check(
        engine,
        "mcp_exec_command",
        {"command": "echo jiuwenswarm | xargs kill"},
    )
    assert replaced.matched_rule != "host_guard:safety"
    custom = _check(engine, "mcp_exec_command", {"command": "do-not-run"})
    assert custom.permission is PermissionLevel.DENY
    assert custom.matched_rule == "host_guard:safety"
    assert custom.reason == "blocked custom"


def test_immutable_relative_paths_follow_workspace_or_runtime_cwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = Path.cwd()
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as elsewhere:
        root = Path(workspace)
        control = root / "control"
        control.mkdir()
        target = control / "config.yaml"
        target.write_text("x", encoding="utf-8")
        try:
            monkeypatch.chdir(root)
            with pytest.raises(ValueError, match="immutable_control_roots"):
                PermissionEngine(_base(
                    file_guard={"enabled": False},
                    runtime={"immutable_control_roots": [str(control)]},
                ))

            other = PermissionEngine(_base(
                file_guard={"enabled": False},
                runtime={
                    "cwd": elsewhere,
                    "immutable_control_roots": [str(control)],
                },
            ))
            relative = _check(other, "write_file", {"path": "control/config.yaml"})
            assert relative.matched_rule != "immutable_control_plane"
            absolute = _check(other, "write_file", {"path": str(target)})
            assert absolute.permission is PermissionLevel.DENY
            assert absolute.matched_rule == "immutable_control_plane"

            via_cwd = PermissionEngine(_base(
                file_guard={"enabled": False},
                runtime={
                    "cwd": str(root),
                    "immutable_control_roots": [str(control)],
                },
            ))
            cwd_relative = _check(via_cwd, "write_file", {"path": "control/config.yaml"})
            assert cwd_relative.permission is PermissionLevel.DENY
            assert cwd_relative.matched_rule == "immutable_control_plane"
            cwd_shell = _check(via_cwd, "bash", {"command": "rm control/config.yaml"})
            assert cwd_shell.matched_rule == "immutable_control_plane"

            bound = PermissionEngine(_base(
                file_guard={"enabled": False},
                runtime={
                    "workspace_root": str(root),
                    "immutable_control_roots": [str(control)],
                },
            ))
            bound_relative = _check(bound, "write_file", {"path": "control/config.yaml"})
            assert bound_relative.matched_rule == "immutable_control_plane"
            bound_shell = _check(bound, "bash", {"command": "rm control/config.yaml"})
            assert bound_shell.matched_rule == "immutable_control_plane"
        finally:
            os.chdir(start)


def test_host_guard_matches_original_segment_and_continuation_rules() -> None:
    engine = PermissionEngine(_base(host_guard={"enabled": True, "shell_mismatch": False}))
    for command in (
        "kill jiuwenclaw",
        "kill -9 jiuwenclaw",
        "Stop-Process -Name jiuwenswarm",
        "taskkill /IM jiuwenswarm.exe",
        "pkill \\\n-f jiuwenswarm",
    ):
        result = _check(engine, "bash", {"command": command})
        assert result.permission is PermissionLevel.DENY, command
        assert result.matched_rule == "host_guard:safety", command

    powershell = _check(
        engine,
        "powershell",
        {"command": "Stop-Process `\n-Name jiuwenswarm"},
    )
    assert powershell.permission is PermissionLevel.DENY
    cmd = _check(
        engine,
        "mcp_exec_command",
        {"command": "taskkill ^\n/IM jiuwenswarm.exe", "shell_type": "cmd"},
    )
    assert cmd.permission is PermissionLevel.DENY

    tools = dict(_QUIET["tools"])
    for name in ("sh", "zsh", "cmd", "create_terminal"):
        tools[name] = "allow"
    unhooked = PermissionEngine(_base(
        tools=tools,
        host_guard={"enabled": True, "shell_mismatch": False},
    ))
    for name in ("sh", "zsh", "cmd", "create_terminal"):
        skipped = _check(unhooked, name, {"command": "pkill -f jiuwenswarm"})
        assert skipped.matched_rule != "host_guard:safety", name


def test_python_name_kill_follows_original_rule_two() -> None:
    engine = PermissionEngine(_base(host_guard={
            "enabled": True,
            "shell_mismatch": False,
            "python_name_kill": True,
        }))
    for command in ("kill python", "kill -9 python3", "taskkill /IM python.exe /F"):
        result = _check(engine, "bash", {"command": command})
        assert result.permission is PermissionLevel.DENY, command
        assert result.matched_rule == "host_guard:safety", command
    for command in (
        'taskkill /FI "IMAGENAME eq python.exe"',
        "taskkill /IM py.exe",
        "Stop-Process -Id 1234 -Name python",
    ):
        result = _check(engine, "powershell", {"command": command})
        assert result.matched_rule != "host_guard:safety", command

    off = PermissionEngine(_base(host_guard={"enabled": True, "shell_mismatch": False}))
    plain = _check(off, "bash", {"command": "kill python"})
    assert plain.matched_rule != "host_guard:safety"


def test_glob_and_outbound_resolve_against_runtime_cwd() -> None:
    guard = {
        "enabled": True,
        "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
        "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
    }
    tools = dict(_QUIET["tools"])
    tools["glob"] = "allow"
    tools["send_file_to_user"] = "allow"
    with tempfile.TemporaryDirectory() as workspace, tempfile.TemporaryDirectory() as cwd:
        split = PermissionEngine(_base(
            tools=tools,
            file_guard=guard,
            runtime={"workspace_root": workspace, "cwd": cwd},
        ))
        globbed = _check(split, "glob", {})
        assert globbed.permission is PermissionLevel.DENY
        assert globbed.matched_rule is not None
        assert globbed.matched_rule.startswith("file_guard")
        sent = _check(split, "send_file_to_user", {"abs_file_path_list": ["note.txt"]})
        assert sent.permission is PermissionLevel.DENY
        assert sent.matched_rule is not None
        assert sent.matched_rule.startswith("file_guard")

        same = PermissionEngine(_base(
            tools=tools,
            file_guard=guard,
            runtime={"workspace_root": workspace},
        ))
        assert _check(same, "glob", {}).permission is not PermissionLevel.DENY
        assert _check(
            same, "send_file_to_user", {"abs_file_path_list": ["note.txt"]},
        ).permission is not PermissionLevel.DENY


def test_file_guard_enabled_uses_bool_not_string_parser() -> None:
    guard = {
        "defaults": {"read": "deny", "write": "deny", "exec": "deny"},
        "workspace": {"read": "allow", "write": "allow", "exec": "allow"},
    }
    with tempfile.TemporaryDirectory() as workspace:
        outside = str(Path(workspace).parent / "outside-secret.txt")
        string_false = PermissionEngine(_base(
            file_guard={**guard, "enabled": "false"},
            runtime={"workspace_root": workspace},
        ))
        assert _check(
            string_false, "read_file", {"path": outside},
        ).permission is PermissionLevel.DENY
        numeric_off = PermissionEngine(_base(
            file_guard={**guard, "enabled": 0},
            runtime={"workspace_root": workspace},
        ))
        assert _check(
            numeric_off, "read_file", {"path": outside},
        ).permission is not PermissionLevel.DENY


def test_python_name_prefixes_stay_unparsed_like_the_original() -> None:
    engine = PermissionEngine(_base(host_guard={
            "enabled": True,
            "shell_mismatch": False,
            "python_name_kill": True,
        }))
    direct = _check(engine, "bash", {"command": "pkill python"})
    assert direct.matched_rule == "host_guard:safety"
    for command in (
        "sudo pkill python",
        "timeout 5 pkill python",
        "nohup pkill python",
        "env X=1 pkill python",
        "sleep 1 & pkill python",
        "(pkill python)",
        "{ pkill python; }",
    ):
        result = _check(engine, "bash", {"command": command})
        assert result.matched_rule != "host_guard:safety", command
    wrapped_product = _check(engine, "bash", {"command": "sudo pkill jiuwenswarm"})
    assert wrapped_product.matched_rule == "host_guard:safety"


def test_name_rules_match_text_outside_the_kill_command() -> None:
    engine = PermissionEngine(_base(host_guard={"enabled": True, "shell_mismatch": False}))
    for command in (
        'echo "kill jiuwenswarm is forbidden"',
        'git log --grep="pkill jiuwenswarm"',
        "kill 1234 # jiuwenswarm",
    ):
        result = _check(engine, "bash", {"command": command})
        assert result.permission is PermissionLevel.DENY, command
        assert result.matched_rule == "host_guard:safety", command
