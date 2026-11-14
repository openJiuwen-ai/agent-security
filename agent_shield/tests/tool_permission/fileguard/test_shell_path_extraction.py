# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Literal shell resources retain the cwd and grammar of their execution segment."""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.fileguard import path_extract as paths
from agent_shield.tool_permission.manager import new_permission_manager


def _expected_extract_path(name: str, tmp_path):
    """Match extractor resolution for Windows abs paths on POSIX hosts."""
    if paths.is_windows_abs_text(name):
        return paths.resolve_extract_path(paths.Path(name))
    path = paths.Path(name)
    if not path.is_absolute():
        path = tmp_path / name
    return paths.resolve_extract_path(path)


@pytest.mark.parametrize("tool,args,expected", [
    ("powershell", {"shell_type": "bash"}, "powershell"),
    ("core.powershell", {}, "powershell"),
    ("bash", {}, "auto"),
    ("bash", {"shell_type": "cmd"}, "cmd"),
    ("bash", {"shell_type": "bash"}, "bash"),
    ("mcp_exec_command", {"shell": "bash"}, "auto"),
])
def test_shell_context_selection_keeps_existing_contract(tool, args, expected):
    assert paths.shell_type_for_file_access(tool, args) == expected


@pytest.mark.parametrize("extractor", [paths.extract_shell_path_accesses, paths.extract_path_aware_command_accesses])
@pytest.mark.parametrize("child", [
    "bash -c 'cd ./child && cat ./inside'",
    "sh -lc 'cd ./child && cat ./inside'",
    'cmd /c "cd child && type ./inside"',
    'powershell -Command "cd child; Get-Content ./inside"',
])
def test_child_directory_changes_do_not_escape_to_parent(tmp_path, extractor, child):
    accesses = extractor(f"{child} && cat ./outside", tmp_path, shell_type="bash")
    assert (tmp_path / "child" / "inside", "read") in accesses
    assert (tmp_path / "outside", "read") in accesses
    assert (tmp_path / "child" / "outside", "read") not in accesses


@pytest.mark.parametrize("dialect,command", [
    ("bash", 'cd ./child && echo ok > "./a b.txt"'),
    ("powershell", 'cd ./child; Write-Output ok > "./a b.txt"'),
    ("cmd", 'cd /d ./child && echo ok > "./a b.txt"'),
])
def test_redirect_is_resolved_at_its_own_segment(tmp_path, dialect, command):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type=dialect)
    assert (tmp_path / "child" / "a b.txt", "write") in accesses


def test_redirect_on_cd_uses_entry_directory(tmp_path):
    accesses = paths.extract_shell_path_accesses(
        "cd ./child > ./log && cat ./inside", tmp_path, shell_type="bash")
    assert (tmp_path / "log", "write") in accesses
    assert (tmp_path / "child" / "inside", "read") in accesses
    assert (tmp_path / "child" / "log", "write") not in accesses


def test_conditional_cd_preserves_both_possible_directories(tmp_path):
    accesses = paths.extract_shell_path_accesses(
        "cd ./child; cat ./secret", tmp_path, shell_type="bash")
    assert (tmp_path / "secret", "read") in accesses
    assert (tmp_path / "child" / "secret", "read") in accesses


@pytest.mark.parametrize("command,target", [
    ("python -u ./script.py", "script.py"),
    ("node --require ./preload.js ./main.js", "preload.js"),
    ("node --require ./preload.js ./main.js", "main.js"),
])
def test_interpreter_options_do_not_hide_executed_files(tmp_path, command, target):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="bash")
    assert (tmp_path / target, "exec") in accesses


def test_tee_literal_destination_is_a_write(tmp_path):
    accesses = paths.extract_shell_path_accesses("echo ok | tee output.txt", tmp_path, shell_type="bash")
    assert (tmp_path / "output.txt", "write") in accesses


@pytest.mark.parametrize("limit,value,command", [
    ("_MAX_INLINE_DEPTH", 0, "echo ok && bash -c 'cat ./secret'"),
    ("_MAX_EXTRACTION_STEPS", 1, "echo ok && cat ./secret"),
    ("_MAX_CWD_CANDIDATES", 1, "cd ./child; cat ./secret"),
])
def test_analysis_budget_exhaustion_denies_through_manager(tmp_path, monkeypatch, limit, value, command):
    monkeypatch.setattr(paths, limit, value, raising=False)
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {"command": command, "shell_type": "bash"}, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "tools": {"bash": "allow"}, "runtime": {"workspace_root": str(tmp_path)},
        "file_guard": {"enabled": True, "defaults": {"read": "allow", "write": "allow", "exec": "allow"}},
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:analysis_limit"


@pytest.mark.parametrize("action,following", [
    ("read", "cat ./outside"), ("write", "echo ok > ./outside"), ("exec", "node ./outside"),
])
def test_parent_deny_still_applies_after_child_cd(tmp_path, action, following):
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": f"bash -c 'cd ./child && echo ok' && {following}", "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "tools": {"bash": "allow"}, "runtime": {"workspace_root": str(tmp_path)},
        "file_guard": {"enabled": True, "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                       "paths": [{"path": str(tmp_path / "outside"), action: "deny"}]},
    }))
    assert result.permission is L.DENY


def test_unknown_workspace_keeps_absolute_paths_without_process_cwd(tmp_path):
    absolute = tmp_path / "file.txt"
    accesses = paths.extract_shell_path_accesses(f'cat "{absolute}" && cat ./relative', None, shell_type="bash")
    assert (absolute, "read") in accesses
    assert all(path.is_absolute() and path != tmp_path / "relative" for path, _ in accesses)


def test_control_plane_budget_exhaustion_denies_with_file_guard_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(paths, "_MAX_EXTRACTION_STEPS", 1, raising=False)
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": "echo ok && echo changed > ./settings/token", "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "tools": {"bash": "allow"}, "file_guard": {"enabled": False},
        "runtime": {"workspace_root": str(tmp_path),
                    "immutable_control_roots": [str(tmp_path / "settings")]},
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "file_guard:analysis_limit"


@pytest.mark.parametrize("child", [
    "bash -c 'cd ./child && echo ok'",
    "sh -lc 'cd ./child && echo ok'",
    'cmd /c "cd child && echo ok"',
    'powershell -Command "cd child; Write-Output ok"',
])
@pytest.mark.parametrize("following", ["cat ./outside", "echo ok > ./outside", "node ./outside"])
def test_unwrapped_view_cannot_invent_child_directory_access(tmp_path, child, following):
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": f"{child} && {following}", "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "guard_actions": {"parse_unavailable": "allow"},
        "host_guard": {"enabled": False},
        "tools": {"bash": "allow"}, "runtime": {"workspace_root": str(tmp_path)},
        "file_guard": {"enabled": True,
                       "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                       "paths": [{"path": str(tmp_path / "child/outside"), "read": "deny"}]},
    }))
    assert result.permission is L.ALLOW


def test_unwrapped_view_cannot_invent_control_plane_write(tmp_path):
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": "bash -c 'cd ./child && echo ok' && echo ok > ./outside",
        "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "guard_actions": {"parse_unavailable": "allow"},
        "tools": {"bash": "allow"},
        "runtime": {"workspace_root": str(tmp_path),
                    "immutable_control_roots": [str(tmp_path / "child/outside")]},
    }))
    assert result.permission is L.ALLOW


@pytest.mark.parametrize("child", [
    "bash -c 'cd ./child && cat ./inside'",
    "sh -lc 'cd ./child && cat ./inside'",
    'cmd /c "cd child && type ./inside"',
    'powershell -Command "cd child; Get-Content ./inside"',
])
def test_original_view_still_denies_actual_child_access(tmp_path, child):
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": child, "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None,
        "host_guard": {"enabled": False}, "tools": {"bash": "allow"},
        "runtime": {"workspace_root": str(tmp_path)},
        "file_guard": {"enabled": True,
                       "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                       "paths": [{"path": str(tmp_path / "child/inside"), "read": "deny"}]},
    }))
    assert result.permission is L.DENY
    assert "file_guard" in result.matched_rule


def test_original_view_still_denies_actual_child_control_plane_write(tmp_path):
    manager = new_permission_manager()
    result = asyncio.run(manager.check_permission("bash", {
        "command": "bash -c 'cd ./child && echo ok > ./settings/token'", "shell_type": "bash",
    }, config={
        "package_builtin_rules": False, "shell_allowlist": None, "tools": {"bash": "allow"},
        "runtime": {"workspace_root": str(tmp_path),
                    "immutable_control_roots": [str(tmp_path / "child/settings")]},
    }))
    assert result.permission is L.DENY
    assert result.matched_rule == "immutable_control_plane"


@pytest.mark.parametrize("command", ["echo 'a > ./secret'", 'echo "a > ./secret"'])
def test_quoted_redirection_text_does_not_invent_file_access(tmp_path, command):
    assert paths.extract_shell_path_accesses(command, tmp_path, shell_type="bash") == []


def test_bash_escaped_space_is_one_file_operand(tmp_path):
    accesses = paths.extract_shell_path_accesses(r"cat ./a\ b.txt", tmp_path, shell_type="bash")
    assert accesses == [(tmp_path / "a b.txt", "read")]


@pytest.mark.parametrize("command,expected", [
    ("cp ./one ./two ./dest", {("one", "read"), ("two", "read"), ("dest", "write")}),
    ("mv ./one ./dest", {("one", "read"), ("one", "write"), ("dest", "write")}),
])
def test_copy_and_move_keep_source_and_destination_permission_axes(tmp_path, command, expected):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="bash")
    assert set(accesses) == {(tmp_path / name, action) for name, action in expected}


@pytest.mark.parametrize("operands,filenames", [
    ("'./one.txt','./two.txt'", ["one.txt", "two.txt"]),
    ('"./one.txt","./two.txt"', ["one.txt", "two.txt"]),
    ("'./one,two.txt'", ["one,two.txt"]),
])
def test_powershell_file_guard_paths_distinguish_lists_from_literal_commas(tmp_path, operands, filenames):
    accesses = paths.extract_shell_path_accesses(
        f"Remove-Item {operands}", tmp_path, shell_type="powershell",
    )
    assert set(accesses) == {(tmp_path / filename, "write") for filename in filenames}


@pytest.mark.parametrize("command,expected", [
    (
        r"Move-Item C:\tmp\a.txt C:\outside\b.txt",
        {(r"C:\tmp\a.txt", "read"), (r"C:\tmp\a.txt", "write"), (r"C:\outside\b.txt", "write")},
    ),
    (
        r"Move-Item -Path C:\tmp\a.txt -Destination C:\outside\b.txt",
        {(r"C:\tmp\a.txt", "read"), (r"C:\tmp\a.txt", "write"), (r"C:\outside\b.txt", "write")},
    ),
    (
        r"Copy-Item C:\tmp\a.txt C:\outside\b.txt",
        {(r"C:\tmp\a.txt", "read"), (r"C:\outside\b.txt", "write")},
    ),
    (
        r"Rename-Item C:\tmp\a.txt renamed.txt",
        {(r"C:\tmp\a.txt", "read"), (r"C:\tmp\a.txt", "write"), ("renamed.txt", "write")},
    ),
])
def test_powershell_transfer_cmdlets_extract_source_and_destination(tmp_path, command, expected):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="powershell")
    resolved = {(_expected_extract_path(name, tmp_path), action) for name, action in expected}
    assert set(accesses) == resolved


@pytest.mark.parametrize("command,expected", [
    (
        r"xcopy C:\tmp\a.txt C:\outside\ /Y",
        {(r"C:\tmp\a.txt", "read"), (r"C:\outside", "write")},
    ),
    (
        r"robocopy C:\tmp C:\outside /E",
        {(r"C:\tmp", "read"), (r"C:\outside", "write")},
    ),
    (
        r"robocopy C:\tmp C:\outside *.txt /E",
        {(r"C:\tmp", "read"), (r"C:\outside", "write")},
    ),
    (
        r"ren C:\tmp\a.txt b.txt",
        {(r"C:\tmp\a.txt", "read"), (r"C:\tmp\a.txt", "write"), ("b.txt", "write")},
    ),
])
def test_cmd_sync_and_rename_extract_outside_destinations(tmp_path, command, expected):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd")
    resolved = {(_expected_extract_path(name, tmp_path), action) for name, action in expected}
    assert set(accesses) == resolved


@pytest.mark.parametrize("command,expected", [
    ("unlink ./a.txt", {("a.txt", "write")}),
    ("rsync -a ./src/ ./dst/", {("src", "read"), ("dst", "write")}),
])
def test_posix_extra_file_commands_are_path_aware(tmp_path, command, expected):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="bash")
    assert set(accesses) == {
        (paths.resolve_extract_path(tmp_path / name), action) for name, action in expected
    }


@pytest.mark.parametrize("command,expected", [
    (
        r'[System.IO.File]::Delete("C:\tmp\a.txt")',
        {(r"C:\tmp\a.txt", "write")},
    ),
    (
        r"[System.IO.Directory]::Delete('C:\tmp\dir', $true)",
        {(r"C:\tmp\dir", "write")},
    ),
    (
        r'[IO.File]::WriteAllText("C:\outside\out.txt", "x")',
        {(r"C:\outside\out.txt", "write")},
    ),
    (
        r'[System.IO.File]::Copy("C:\tmp\a.txt", "C:\outside\b.txt")',
        {(r"C:\outside\b.txt", "write")},
    ),
    (
        r'[System.IO.File]::Move("C:\tmp\a.txt", "C:\outside\b.txt")',
        {(r"C:\tmp\a.txt", "write"), (r"C:\outside\b.txt", "write")},
    ),
    (
        r'cipher /w:C:\outside\wipe',
        {(r"C:\outside\wipe", "write")},
    ),
    (
        r'fsutil file setZeroData offset=0 length=1024 C:\outside\a.txt',
        {(r"C:\outside\a.txt", "write")},
    ),
    (
        r'rimraf ./stale',
        {("stale", "write")},
    ),
    (
        r'npx rimraf ./stale',
        {("stale", "write")},
    ),
    (
        r'deltree C:\outside\old',
        {(r"C:\outside\old", "write")},
    ),
])
def test_dotnet_filesystem_literals_extract_as_writes(tmp_path, command, expected):
    shell = "powershell" if "::" in command or command.startswith(("cipher", "fsutil")) else "bash"
    if command.startswith(("cipher", "fsutil", "deltree")):
        shell = "cmd"
    if command.startswith(("rimraf", "npx")):
        shell = "bash"
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type=shell)
    resolved = {(_expected_extract_path(name, tmp_path), action) for name, action in expected}
    assert set(accesses) == resolved


@pytest.mark.parametrize("command", [
    "Clear-RecycleBin -Force",
    "SendToRecycleBin -Path C:\\tmp\\a.txt",
    "$item.InvokeVerb('delete')",
    "$f.Delete()",
    "[System.IO.File]::Delete($path)",
    "New-Object -ComObject Shell.Application; $s.Namespace('C:\\tmp').ParseName('a.txt').InvokeVerb('delete')",
    "Add-Type -TypeDefinition 'DllImport(\"kernel32\") public static extern bool DeleteFile(string p);'",
    "SHFileOperation($op)",
    # Peer analyzers run per segment: a recoverable literal must not mask opaque Delete.
    r'[System.IO.File]::Delete("C:\tmp\a.txt"); $f.Delete()',
    r'Remove-Item C:\tmp\a.txt; $f.Delete()',
])
def test_opaque_windows_destruction_fail_closes(tmp_path, command):
    with pytest.raises(paths.ShellPathUnresolvedShellError):
        paths.extract_shell_path_accesses(command, tmp_path, shell_type="powershell")


@pytest.mark.parametrize("command,expected", [
    (
        r"robocopy C:\a D:\b /MOVE",
        {(r"C:\a", "read"), (r"C:\a", "write"), (r"D:\b", "write")},
    ),
    (
        r"robocopy C:\a D:\b /MOV",
        {(r"C:\a", "read"), (r"C:\a", "write"), (r"D:\b", "write")},
    ),
    (
        r"robocopy C:\a D:\b /MIR",
        {(r"C:\a", "read"), (r"D:\b", "write")},
    ),
    (
        r"robocopy C:\a D:\b /PURGE",
        {(r"C:\a", "read"), (r"D:\b", "write")},
    ),
    (
        r"robocopy C:\a D:\b /E",
        {(r"C:\a", "read"), (r"D:\b", "write")},
    ),
])
def test_robocopy_destructive_switches_mark_source_when_moving(tmp_path, command, expected):
    accesses = paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd")
    resolved = {(_expected_extract_path(name, tmp_path), action) for name, action in expected}
    assert set(accesses) == resolved


@pytest.mark.skipif(paths.os.name != "nt", reason="MSYS drive paths require Windows")
@pytest.mark.parametrize("shell_type", ["bash", "sh"])
def test_windows_msys_drive_is_not_relative_to_current_drive(tmp_path, shell_type):
    accesses = paths.extract_shell_path_accesses("cat /c/audit/secret.txt", tmp_path, shell_type=shell_type)
    assert accesses == [(paths.Path("C:/audit/secret.txt"), "read")]


def test_bash_home_expansion_respects_quoted_literal_tilde(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    expanded = paths.extract_shell_path_accesses("cat ~/secret", tmp_path, shell_type="bash")
    literal = paths.extract_shell_path_accesses("cat '~/secret'", tmp_path, shell_type="bash")
    assert expanded == [(home / "secret", "read")]
    assert literal == [(tmp_path / "~" / "secret", "read")]


@pytest.mark.parametrize("shell_type", ["bash", "cmd", "powershell"])
def test_listing_glob_reads_directory_not_a_fictitious_filename(tmp_path, shell_type):
    assert paths.extract_shell_path_accesses("ls *.txt", tmp_path, shell_type=shell_type) == [(tmp_path, "read")]


@pytest.mark.skipif(paths.os.name != "nt", reason="Windows auto has three dialect views")
@pytest.mark.parametrize("command", ["type secret.txt", "cat /c/audit/secret.txt", r"cat ./a\ b.txt"])
def test_windows_auto_retains_resources_from_all_three_views(tmp_path, command):
    expected = set()
    for dialect in ("cmd", "powershell", "sh"):
        expected.update(paths.extract_shell_path_accesses(command, tmp_path, shell_type=dialect))
    actual = paths.extract_shell_path_accesses(command, tmp_path, shell_type="auto")
    assert set(actual) == expected
    assert len(actual) == len(expected)


@pytest.mark.skipif(paths.os.name != "nt", reason="Windows auto shares work across three views")
def test_windows_auto_work_budget_is_shared_and_has_an_exact_boundary(tmp_path, monkeypatch):
    command = "echo one && echo two"
    monkeypatch.setattr(paths, "_MAX_EXTRACTION_STEPS", 2)
    assert paths.extract_shell_path_accesses(command, tmp_path, shell_type="sh") == []
    with pytest.raises(ValueError, match="work limit"):
        paths.extract_shell_path_accesses(command, tmp_path, shell_type="auto")
    monkeypatch.setattr(paths, "_MAX_EXTRACTION_STEPS", 6)
    assert paths.extract_shell_path_accesses(command, tmp_path, shell_type="auto") == []
    monkeypatch.setattr(paths, "_MAX_EXTRACTION_STEPS", 5)
    with pytest.raises(ValueError, match="work limit"):
        paths.extract_shell_path_accesses(command, tmp_path, shell_type="auto")
