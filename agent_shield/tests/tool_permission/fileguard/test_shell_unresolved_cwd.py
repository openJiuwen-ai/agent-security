# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""An unknown directory must never become a definite reusable file grant."""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.fileguard import path_extract as paths


def _config(root, level="allow"):
    return {
        "package_builtin_rules": False, "shell_allowlist": None,
        "tools": {"bash": "allow"}, "runtime": {"workspace_root": str(root)},
        "guard_actions": {
            "too_complex": "allow", "parse_unavailable": "allow",
        },
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            "paths": [{"path": str(root / "secret"), "read": level, "write": level, "exec": level}],
        },
    }


@pytest.mark.parametrize("dialect,operand", [
    ("bash", "$DEST"), ("sh", "${DEST}"), ("cmd", "%DEST%"),
    ("powershell", "$DEST"), ("powershell", "$env:DEST"),
])
@pytest.mark.parametrize("connector", ["&&", ";", "||"])
@pytest.mark.parametrize("old_directory_policy", ["allow", "ask", "deny"])
@pytest.mark.parametrize("approved", [False, True])
def test_unresolved_cd_never_uses_old_directory_or_reusable_grant(
    tmp_path, dialect, operand, connector, old_directory_policy, approved,
):
    command = f"cd {operand} {connector} cat ./secret"
    config = _config(tmp_path, old_directory_policy)
    tool = "mcp_exec_command"
    config["tools"] = {tool: "allow"}
    config["approval_overrides"] = [{
        "id": "remembered", "tools": [tool], "pattern": command, "action": "allow",
    }] if approved else []
    engine = PermissionEngine(config)
    args = {"command": command, "shell_type": dialect}
    result = asyncio.run(engine.check_permission(tool, args))
    assert result.permission is (L.ALLOW if approved else L.DENY)
    if approved:
        assert "approval_overrides" in result.matched_rule
    else:
        assert result.matched_rule == "file_guard:unresolved_cwd"
    assert result.external_paths == []
    assert result.ask_accesses == []
    assert engine.collect_file_guard_ask_accesses(tool, args) == []


@pytest.mark.parametrize("extractor", [paths.extract_shell_path_accesses, paths.extract_path_aware_command_accesses])
@pytest.mark.parametrize("dialect,operand", [
    ("bash", "$DEST"), ("cmd", "%DEST%"), ("powershell", "$DEST"),
])
def test_direct_extraction_refuses_partial_unknown_cwd_analysis(tmp_path, extractor, dialect, operand):
    with pytest.raises(ValueError, match="working directory"):
        extractor(f"cat ./known && cd {operand} && cat ./secret", tmp_path, shell_type=dialect)


def test_unknown_child_directory_cannot_hide_following_denied_access(tmp_path):
    engine = PermissionEngine(_config(tmp_path, "deny"))
    result = asyncio.run(engine.check_permission("bash", {
        "command": "bash -c 'cd $DEST && cat ./inside' && cat ./secret", "shell_type": "bash",
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:unresolved_cwd"
    assert result.ask_accesses == []


def test_unresolved_cd_keeps_control_plane_closed_with_file_guard_disabled(tmp_path):
    config = _config(tmp_path)
    config["file_guard"] = {"enabled": False}
    config["runtime"]["immutable_control_roots"] = [str(tmp_path / "settings")]
    result = asyncio.run(PermissionEngine(config).check_permission("bash", {
        "command": "cd $DEST && echo ok > ./settings/token", "shell_type": "bash",
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:unresolved_cwd"
    assert result.ask_accesses == []


@pytest.mark.parametrize("disabled", ["file_guard", "engine"])
def test_unresolved_cd_does_not_override_existing_disabled_switch(tmp_path, disabled):
    config = _config(tmp_path)
    if disabled == "engine":
        config["enabled"] = False
    else:
        config["file_guard"] = {"enabled": False}
    result = asyncio.run(PermissionEngine(config).check_permission("bash", {
        "command": "cd $DEST && cat ./secret", "shell_type": "bash",
    }))
    assert result.permission is L.ALLOW


@pytest.mark.parametrize("command", ["cd ./child* && cat ./secret", "cd ./a ./b && cat ./secret"])
def test_nonliteral_or_ambiguous_cd_does_not_invent_a_single_directory(tmp_path, command):
    result = asyncio.run(PermissionEngine(_config(tmp_path)).check_permission("bash", {
        "command": command, "shell_type": "bash",
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:unresolved_cwd"


@pytest.mark.parametrize("dialect,command", [
    ("bash", "cd './a[b]' && cat ./secret"),
    ("sh", r"cd ./a\[b\] && cat ./secret"),
    ("powershell", "cd -LiteralPath './a[b]' && Get-Content ./secret"),
])
def test_literal_cd_with_glob_character_keeps_literal_directory(tmp_path, dialect, command):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type=dialect)
    assert (tmp_path / "a[b]" / "secret", "read") in accesses


def test_literal_home_cd_still_uses_explicit_home(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda cls: home))
    accesses = paths.extract_shell_path_accesses("cd && cat ./secret", tmp_path, shell_type="bash")
    assert (home / "secret", "read") in accesses


def test_powershell_quoted_wildcard_still_requires_literalpath(tmp_path):
    with pytest.raises(ValueError, match="working directory"):
        paths.extract_shell_path_accesses("cd './a[b]' && Get-Content ./secret", tmp_path, shell_type="powershell")


def test_failed_directory_normalization_does_not_reuse_old_cwd(tmp_path, monkeypatch):
    resolve = paths.Path.resolve

    def fail_target(path, *args, **kwargs):
        if path == tmp_path / "child":
            raise OSError("unresolvable directory")
        return resolve(path, *args, **kwargs)

    monkeypatch.setattr(paths.Path, "resolve", fail_target)
    result = asyncio.run(PermissionEngine(_config(tmp_path)).check_permission("bash", {
        "command": "cd ./child && cat ./secret", "shell_type": "bash",
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:unresolved_cwd"
    assert result.ask_accesses == []


def test_unknown_cd_without_workspace_cannot_produce_relative_resources():
    with pytest.raises(ValueError, match="working directory"):
        paths.extract_shell_path_accesses("cd ./child && cat ./secret", None, shell_type="bash")


def test_default_structure_ask_does_not_hide_unresolved_file_cwd(tmp_path):
    config = _config(tmp_path)
    config.pop("guard_actions")
    result = asyncio.run(PermissionEngine(config).check_permission("bash", {
        "command": "cd $DEST && cat ./secret", "shell_type": "bash",
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:unresolved_cwd"
    assert result.ask_accesses == []
