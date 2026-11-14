# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Unsupported shell structure must not turn a real file operation into abstention."""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.engine import PermissionEngine
from agent_shield.tool_permission.fileguard import path_extract as paths


def _engine(root, guard):
    return PermissionEngine({
        "package_builtin_rules": False, "shell_allowlist": None,
        "tools": {"mcp_exec_command": "allow"},
        "guard_actions": {"parse_unavailable": "allow", "too_complex": "allow"},
        "runtime": {"workspace_root": str(root),
                    "immutable_control_roots": [str(root / "settings")] if guard == "control" else []},
        "file_guard": {"enabled": guard == "file",
                       "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                       "paths": [{"path": str(root / "settings"), "write": "deny"}]},
    })


@pytest.mark.parametrize("extractor", [paths.extract_shell_path_accesses, paths.extract_path_aware_command_accesses])
@pytest.mark.parametrize("command", [
    'bash -c "echo \'cost is $5\' > ./settings/token"',
    'bash -c "echo ok > ./settings/token && echo $HOME"',
    'sh -lc "echo ok > ./settings/token && echo `whoami`"',
    'bash -c "$BODY"',
    "bash -c",
    'bash -c "echo ok > ./settings/token',
    'bash --unknown-option value -c "echo ok > ./settings/token"',
])
def test_unverifiable_inline_shell_body_is_not_an_empty_path_list(tmp_path, extractor, command):
    with pytest.raises(ValueError, match="shell"):
        extractor(command, tmp_path, shell_type="bash")


@pytest.mark.parametrize("guard", ["file", "control"])
@pytest.mark.parametrize("command", [
    'bash -c "echo \'cost is $5\' > ./settings/token"',
    'bash -c "echo ok > ./settings/token && echo $HOME"',
    'sh -c "echo ok > ./settings/token && echo `whoami`"',
])
def test_unverifiable_inline_body_denies_without_reusable_paths(tmp_path, guard, command):
    engine = _engine(tmp_path, guard)
    args = {"command": command, "shell_type": "bash"}
    result = asyncio.run(engine.check_permission("mcp_exec_command", args))
    assert result.permission is L.DENY
    assert result.ask_accesses == []
    assert engine.collect_file_guard_ask_accesses("mcp_exec_command", args) == []


def test_positional_expansion_in_inline_body_is_denied_with_default_structure_actions(tmp_path):
    config = dict(_engine(tmp_path, "control").config)
    config.pop("guard_actions")
    result = asyncio.run(PermissionEngine(config).check_permission("mcp_exec_command", {
        "command": 'bash -c "echo \'cost is $5\' > ./settings/token"', "shell_type": "bash",
    }))
    assert result.permission is L.DENY


def test_inline_body_decode_failure_is_not_absence_of_a_child(tmp_path, monkeypatch):
    split = paths.shlex.split

    def fail_body(text, *args, **kwargs):
        if text == '"echo ok > ./settings/token"':
            raise ValueError("decode failure")
        return split(text, *args, **kwargs)

    monkeypatch.setattr(paths.shlex, "split", fail_body)
    with pytest.raises(ValueError, match="shell"):
        paths.extract_shell_path_accesses('bash -c "echo ok > ./settings/token"', tmp_path, shell_type="bash")


@pytest.mark.parametrize("command", [
    'bash -c "echo ok > ./settings/token"',
    "bash -c 'echo ok > ./settings/token && echo $HOME'",
    "bash -o pipefail -c 'echo ok > ./settings/token'",
    "command bash -c 'echo ok > ./settings/token'",
    "bash --rcfile ./startup -c 'echo ok > ./settings/token'",
    "bash --init-file ./startup -c 'echo ok > ./settings/token'",
])
def test_literal_child_write_is_still_extracted(tmp_path, command):
    assert (tmp_path / "settings/token", "write") in paths.extract_shell_path_accesses(
        command, tmp_path, shell_type="bash",
    )


def test_empty_literal_child_is_a_known_noop(tmp_path):
    assert paths.extract_shell_path_accesses('bash -c ""', tmp_path, shell_type="bash") == []


@pytest.mark.parametrize("separator", ["&&", "&"])
def test_cmd_apostrophes_do_not_hide_a_second_command_or_its_real_filename(tmp_path, separator):
    command = f"echo 'foo {separator} echo ok > ./settings/token'"
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd")
    assert (tmp_path / "settings" / "token'", "write") in accesses


@pytest.mark.parametrize("guard", ["file", "control"])
@pytest.mark.parametrize("separator", ["&&", "&"])
def test_cmd_apostrophe_wrapped_write_is_denied_by_either_resource_guard(tmp_path, guard, separator):
    result = asyncio.run(_engine(tmp_path, guard).check_permission("mcp_exec_command", {
        "command": f"echo 'foo {separator} echo ok > ./settings/token'", "shell_type": "cmd",
    }))
    assert result.permission is L.DENY


@pytest.mark.skipif(paths.os.name != "nt", reason="Windows auto includes CMD")
def test_windows_auto_keeps_the_cmd_write_hidden_from_other_dialects(tmp_path):
    command = "echo 'foo && echo ok > ./settings/token'"
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="auto")
    assert (tmp_path / "settings" / "token'", "write") in accesses


def test_cmd_double_quotes_still_protect_literal_operators(tmp_path):
    assert paths.extract_shell_path_accesses(
        'echo "foo && echo ok > ./settings/token"', tmp_path, shell_type="cmd",
    ) == []


def test_cmd_embedded_double_quotes_decode_a_single_redirect_filename(tmp_path):
    accesses = paths.extract_shell_path_accesses('echo ok > ./settings/"to ken"', tmp_path, shell_type="cmd")
    assert (tmp_path / "settings/to ken", "write") in accesses


def test_cmd_semicolon_is_a_literal_directory_character(tmp_path):
    accesses = paths.extract_shell_path_accesses("cd child;dir && type ./secret", tmp_path, shell_type="cmd")
    assert (tmp_path / "child;dir/secret", "read") in accesses


@pytest.mark.parametrize("command", [
    "(cd ./child && cat ./secret)",
    "pushd ./child && cat ./secret",
    "popd && cat ./secret",
])
def test_unmodeled_directory_scope_never_invents_a_parent_path(tmp_path, command):
    with pytest.raises(ValueError):
        paths.extract_shell_path_accesses(command, tmp_path, shell_type="bash")


@pytest.mark.parametrize("dialect,command", [
    ("bash", "command cd ./child && cat ./secret"),
    ("bash", "builtin cd ./child && cat ./secret"),
    ("powershell", "Set-Location ./child; Get-Content ./secret"),
    ("powershell", "sl ./child; Get-Content ./secret"),
    ("cmd", "chdir ./child && type ./secret"),
    ("cmd", 'c"d" ./child && type ./secret'),
])
def test_known_directory_aliases_and_builtin_prefixes_use_the_child_directory(tmp_path, dialect, command):
    assert (tmp_path / "child/secret", "read") in paths.extract_shell_path_accesses(
        command, tmp_path, shell_type=dialect,
    )


def test_command_lookup_query_does_not_change_directory(tmp_path):
    accesses = paths.extract_shell_path_accesses("command -v cd && cat ./secret", tmp_path, shell_type="bash")
    assert (tmp_path / "secret", "read") in accesses


def test_disabled_engine_still_bypasses_resource_analysis(tmp_path):
    config = dict(_engine(tmp_path, "file").config)
    config["enabled"] = False
    result = asyncio.run(PermissionEngine(config).check_permission("mcp_exec_command", {
        "command": 'bash -c "$BODY"', "shell_type": "bash",
    }))
    assert result.permission is L.ALLOW


@pytest.mark.parametrize("guard", ["file", "control"])
@pytest.mark.parametrize("command", [
    "(cd ./child && echo ok > ./settings/token)",
    "pushd ./child && echo ok > ./settings/token",
    "popd && echo ok > ./settings/token",
])
def test_unknown_directory_scope_denies_without_recording_partial_accesses(tmp_path, guard, command):
    engine = _engine(tmp_path, guard)
    args = {"command": command, "shell_type": "bash"}
    result = asyncio.run(engine.check_permission("mcp_exec_command", args))
    assert result.permission is L.DENY
    assert result.ask_accesses == []
    assert engine.collect_file_guard_ask_accesses("mcp_exec_command", args) == []


@pytest.mark.parametrize("dialect,command", [
    ("bash", "command cd ./settings && echo ok > ./token"),
    ("bash", "builtin cd ./settings && echo ok > ./token"),
    ("powershell", "Set-Location ./settings; Set-Content ./token ok"),
    ("powershell", "sl ./settings; Set-Content ./token ok"),
    ("cmd", "chdir ./settings && echo ok > ./token"),
])
@pytest.mark.parametrize("guard", ["file", "control"])
def test_directory_alias_write_reaches_either_resource_guard(tmp_path, dialect, command, guard):
    result = asyncio.run(_engine(tmp_path, guard).check_permission("mcp_exec_command", {
        "command": command, "shell_type": dialect,
    }))
    assert result.permission is L.DENY


def test_cmd_caret_escaped_operators_stay_inside_the_literal_filename(tmp_path):
    accesses = paths.extract_shell_path_accesses("echo ok > ./settings/to^&ken", tmp_path, shell_type="cmd")
    assert (tmp_path / "settings/to&ken", "write") in accesses


@pytest.mark.parametrize("command", ["type ./settings/token'", "cd ./settings' && type ./token"])
def test_cmd_apostrophes_are_preserved_in_file_and_directory_operands(tmp_path, command):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd")
    target = "settings/token'" if command.startswith("type") else "settings'/token"
    assert (tmp_path / target, "read") in accesses


def test_shell_startup_file_is_an_exec_resource(tmp_path):
    accesses = paths.extract_shell_path_accesses(
        "bash --rcfile ./startup -c 'echo ok'", tmp_path, shell_type="bash",
    )
    assert (tmp_path / "startup", "exec") in accesses


def test_option_after_a_shell_script_is_not_an_inline_command(tmp_path):
    accesses = paths.extract_shell_path_accesses(
        'bash ./script.sh -c "$BODY"', tmp_path, shell_type="bash",
    )
    assert (tmp_path / "script.sh", "exec") in accesses
