# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Deletion estimates retain command cwd and link identity."""
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from agent_shield.tool_permission.delguard import del_count
from agent_shield.tool_permission.delguard.deletion_guard import DeletionGuard
from agent_shield.tool_permission.fileguard import path_extract
from agent_shield.tool_permission.models import PermissionLevel
from agent_shield.tool_permission.toolguard import shell_ast


@pytest.mark.parametrize("shell,command", [
    ("bash", "cd child && rm -rf payload"),
    ("bash", "cd child; rm -rf payload"),
    ("powershell", "Set-Location child; Remove-Item -Recurse payload"),
    ("cmd", "cd /d child & del payload"),
])
def test_deletion_after_directory_change_reaches_batch_approval(tmp_path, shell, command):
    folder = tmp_path / "child" / "payload"
    folder.mkdir(parents=True)
    for number in range(3):
        (folder / f"{number}.txt").write_text("data", encoding="utf-8")
    guard = DeletionGuard(
        permission_config={"soft_delete": {"enabled": True, "batch_delete_threshold": 3}},
        workspace_root=str(tmp_path),
    )
    result = guard.evaluate("bash", {"command": command, "shell_type": shell})
    assert result is not None
    assert result.permission is PermissionLevel.ASK
    assert str(folder) in result.external_paths


@pytest.mark.parametrize("subcommands", [None, [], ["echo ok", "rm victim"]])
def test_pipeline_deletion_is_counted_independently_of_optional_parser(tmp_path, monkeypatch, subcommands):
    target = tmp_path / "victim"
    target.write_text("data", encoding="utf-8")
    if subcommands is not None:
        monkeypatch.setattr(shell_ast, "parse_shell_for_permission", lambda _: SimpleNamespace(
            subcommands=[SimpleNamespace(text=text) for text in subcommands],
        ))
    assert del_count.count_deletion_targets("echo ok | rm victim", "bash", tmp_path) == (1, [str(target)])


@pytest.mark.parametrize("command", ["echo 'x|rm victim'", 'echo "x;rm victim"'])
@pytest.mark.parametrize("subcommands", [None, [], ["echo x", "rm victim"]])
def test_quoted_separator_is_not_a_delete_command(tmp_path, monkeypatch, command, subcommands):
    (tmp_path / "victim").write_text("data", encoding="utf-8")
    if subcommands is not None:
        monkeypatch.setattr(shell_ast, "parse_shell_for_permission", lambda _: SimpleNamespace(
            subcommands=[SimpleNamespace(text=text) for text in subcommands],
        ))
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (0, [])


def test_reparse_directory_counts_once_without_following_target(tmp_path, monkeypatch):
    target = tmp_path / "junction"
    target.mkdir()
    for number in range(3):
        (target / str(number)).write_text("data", encoding="utf-8")
    lstat = os.lstat

    def link_stat(path, *args, **kwargs):
        info = lstat(path, *args, **kwargs)
        if os.path.normpath(str(path)) == str(target):
            return SimpleNamespace(st_mode=info.st_mode, st_file_attributes=0x400)
        return info

    monkeypatch.setattr(del_count.os, "lstat", link_stat)
    assert del_count.count_deletion_targets("rm -rf junction", "bash", tmp_path) == (1, [str(target)])


@pytest.mark.parametrize("dangling", [False, True])
def test_symlink_keeps_its_identity_and_counts_once(tmp_path, dangling):
    target = tmp_path / "target"
    if not dangling:
        target.mkdir()
        for number in range(3):
            (target / str(number)).write_text("data", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert del_count.count_deletion_targets("rm -rf link", "bash", tmp_path) == (1, [str(link)])


def test_trailing_separator_counts_link_target_contents(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    for number in range(3):
        (target / str(number)).write_text("data", encoding="utf-8")
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")
    assert del_count.count_deletion_targets("rm -rf link/", "bash", tmp_path) == (3, [str(target)])


@pytest.mark.skipif(sys.platform != "win32", reason="Windows directory junction")
def test_native_junction_retains_identity_and_trailing_separator_range(tmp_path):
    import _winapi

    target = tmp_path / "target"
    target.mkdir()
    for number in range(3):
        (target / str(number)).write_text("data", encoding="utf-8")
    junction = tmp_path / "junction"
    try:
        _winapi.CreateJunction(str(target), str(junction))
    except OSError as exc:
        pytest.skip(f"junction creation unavailable: {exc}")
    try:
        assert del_count.count_deletion_targets("rm -rf junction", "bash", tmp_path) == (1, [str(junction)])
        assert del_count.count_deletion_targets("rm -rf junction/", "bash", tmp_path) == (3, [str(target)])
        count, paths = del_count.count_deletion_targets("rm -rf junction target junction", "bash", tmp_path)
        assert count == 4
        assert paths == [str(junction), str(target)]
    finally:
        os.rmdir(junction)


def test_partial_directory_scan_requests_approval_instead_of_returning_partial_count(tmp_path, monkeypatch):
    target = tmp_path / "victim"
    target.write_text("data", encoding="utf-8")
    entry = SimpleNamespace(path=str(target), is_file=lambda: True, is_symlink=lambda: False,
                            stat=lambda **_: os.lstat(target))

    def interrupted_entries():
        yield entry
        raise PermissionError("scan interrupted")

    scan = MagicMock()
    scan.__enter__.return_value = scan
    scan.__exit__.return_value = False
    scan.__iter__.side_effect = interrupted_entries
    monkeypatch.setattr(del_count.os, "scandir", lambda _: scan)
    with pytest.raises(ValueError, match="scan incomplete"):
        del_count.count_deletion_targets("rm -rf .", "bash", tmp_path)
    guard = DeletionGuard(
        permission_config={"soft_delete": {"enabled": True, "batch_delete_threshold": 100}},
        workspace_root=str(tmp_path),
    )
    result = guard.evaluate("bash", {"command": "rm -rf .", "shell_type": "bash"})
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"
    assert "扫描不完整" in result.reason


@pytest.mark.parametrize("tail", ["rm -rf payload", "echo ok | rm -rf payload"])
def test_long_successful_cd_chain_uses_single_cwd_and_counts_target(tmp_path, tail):
    current = tmp_path
    changes = []
    for number in range(8):
        name = f"d{number}"
        current = current / name
        current.mkdir()
        changes.append(f"cd {name}")
    payload = current / "payload"
    payload.mkdir()
    for number in range(3):
        (payload / str(number)).write_text("data", encoding="utf-8")
    command = " && ".join([*changes, tail])
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (3, [str(payload)])
    guard = DeletionGuard(
        permission_config={"soft_delete": {"enabled": True, "batch_delete_threshold": 3}},
        workspace_root=str(tmp_path),
    )
    result = guard.evaluate("bash", {"command": command, "shell_type": "bash"})
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"
    assert result.external_paths == [str(payload)]


def test_successful_cd_chain_keeps_absolute_targets_and_nondelete_commands_unchanged(tmp_path):
    changes = []
    for number in range(9):
        child = tmp_path / str(number)
        child.mkdir()
        changes.append(f'cd "{child.as_posix()}"')
    command = " && ".join(changes)
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (0, [])
    victim = tmp_path / "victim"
    victim.write_text("data", encoding="utf-8")
    assert del_count.count_deletion_targets(
        command + f' && rm "{victim.as_posix()}"', "bash", tmp_path,
    ) == (1, [str(victim)])


@pytest.mark.parametrize("connector", ["&&", ";", "||", "|"])
def test_file_and_deletion_guards_share_conditional_cwd_candidates(tmp_path, connector):
    child = tmp_path / "child"
    child.mkdir()
    for folder in (tmp_path, child):
        (folder / "victim").write_text("data", encoding="utf-8")
    command = f"cd child {connector} rm ./victim"
    accesses = path_extract.extract_shell_path_accesses(command, tmp_path, shell_type="bash", include_cd_reads=False)
    expected = [str(path) for path, action in accesses if action == "write"]
    count, paths = del_count.count_deletion_targets(command, "bash", tmp_path)
    assert paths == expected
    assert count == (1 if connector == "&&" else 2)


@pytest.mark.parametrize("shell,cd", [("bash", "cd"), ("powershell", "Set-Location")])
def test_bare_cd_uses_shared_home_directory_semantics(tmp_path, monkeypatch, shell, cd):
    home = tmp_path / "home"
    home.mkdir()
    target = home / "victim"
    target.write_text("data", encoding="utf-8")
    monkeypatch.setattr(path_extract.Path, "home", classmethod(lambda cls: home))
    command = f"{cd} && rm ./victim"
    assert del_count.count_deletion_targets(command, shell, tmp_path) == (1, [str(target)])
    accesses = path_extract.extract_shell_path_accesses(command, tmp_path, shell_type=shell, include_cd_reads=False)
    assert accesses == [(target, "write")]


@pytest.mark.parametrize("command", ["cd - && rm victim", "pushd child && rm victim", "popd; rm victim",
                                     "Set-Location $where; Remove-Item victim"])
def test_unknown_cwd_requests_approval_even_below_threshold(tmp_path, command):
    guard = DeletionGuard(soft_delete_enabled=True, workspace_root=str(tmp_path))
    shell = "powershell" if command.startswith("Set-") else "bash"
    with pytest.raises(ValueError):
        del_count.count_deletion_targets(command, shell, tmp_path)
    result = guard.evaluate("bash", {"command": command, "shell_type": shell})
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"


@pytest.mark.parametrize("limit,command", [
    ("_MAX_CWD_CANDIDATES", "cd child; rm victim"),
    ("_MAX_EXTRACTION_STEPS", "echo ok && rm victim"),
])
def test_deletion_count_uses_the_same_analysis_limits_as_file_guard(tmp_path, monkeypatch, limit, command):
    monkeypatch.setattr(path_extract, limit, 1)
    with pytest.raises(path_extract.ShellPathAnalysisLimitError):
        path_extract.extract_shell_path_accesses(command, tmp_path, shell_type="bash")
    with pytest.raises(ValueError, match="limit"):
        del_count.count_deletion_targets(command, "bash", tmp_path)
    result = DeletionGuard(soft_delete_enabled=True, workspace_root=str(tmp_path)).evaluate(
        "bash", {"command": command, "shell_type": "bash"},
    )
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"


def test_inline_shell_keeps_child_cwd_isolated_and_counts_parent_deletions(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    child_target, parent_target = child / "victim", tmp_path / "victim"
    for target in (child_target, parent_target):
        target.write_text("data", encoding="utf-8")
    command = "bash -c 'cd child && rm ./victim' && rm ./victim"
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (2, [str(child_target), str(parent_target)])
    assert path_extract.extract_shell_path_accesses(command, tmp_path, shell_type="bash", include_cd_reads=False) == [
        (child_target, "write"), (parent_target, "write"),
    ]


def test_skipped_or_branch_preserves_cwd_for_following_successful_delete(tmp_path):
    child = tmp_path / "child"
    child.mkdir()
    target = child / "victim"
    target.write_text("data", encoding="utf-8")
    command = "cd child || cd absent && rm ./victim"
    accesses = path_extract.extract_shell_path_accesses(command, tmp_path, shell_type="bash", include_cd_reads=False)
    assert (target, "write") in accesses
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (1, [str(target)])


@pytest.mark.parametrize("command", [
    "cd child | cd other && rm ./victim",
    "cd absent && cd child; rm ./victim",
    "cd absent && cd child || rm ./victim",
])
def test_pipeline_or_resumed_chain_cannot_drop_parent_cwd(tmp_path, command):
    (tmp_path / "child").mkdir()
    (tmp_path / "other").mkdir()
    target = tmp_path / "victim"
    target.write_text("data", encoding="utf-8")
    assert (target, "write") in path_extract.extract_shell_path_accesses(
        command, tmp_path, shell_type="bash", include_cd_reads=False,
    )
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == (1, [str(target)])


@pytest.mark.parametrize("failure", ["lstat", "entry_stat", "scandir"])
def test_unreadable_deletion_target_requests_approval(tmp_path, monkeypatch, failure):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "file").write_text("data", encoding="utf-8")
    if failure == "lstat":
        lstat = del_count.os.lstat

        def unreadable(path, *args, **kwargs):
            if str(path) == str(victim):
                raise PermissionError("target cannot be read")
            return lstat(path, *args, **kwargs)

        monkeypatch.setattr(del_count.os, "lstat", unreadable)
    else:
        scan = MagicMock()
        scan.__enter__.return_value = scan
        if failure == "entry_stat":
            entry = SimpleNamespace(
                path=str(victim / "file"), stat=MagicMock(side_effect=PermissionError("entry stat")),
            )

            def entry_iterator():
                return iter([entry])

            scan.__iter__.side_effect = entry_iterator
        else:
            scan.__enter__.side_effect = PermissionError("directory cannot be listed")
        scandir = del_count.os.scandir
        monkeypatch.setattr(del_count.os, "scandir", lambda path: scan if str(path) == str(victim) else scandir(path))
    with pytest.raises(ValueError):
        del_count.count_deletion_targets("rm -rf victim", "bash", tmp_path)
    result = DeletionGuard(soft_delete_enabled=True, workspace_root=str(tmp_path)).evaluate(
        "bash", {"command": "rm -rf victim", "shell_type": "bash"},
    )
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"


def test_workdir_alias_does_not_resolve_deleted_link_identity(tmp_path, monkeypatch):
    victim = tmp_path / "victim"
    victim.write_text("data", encoding="utf-8")

    def unexpected_resolve(*_args, **_kwargs):
        raise AssertionError("deletion counting must not resolve cwd or operands")

    monkeypatch.setattr(path_extract.Path, "resolve", unexpected_resolve)
    assert del_count.count_deletion_targets("rm victim", "bash", tmp_path) == (1, [str(victim)])


@pytest.mark.parametrize("command", ["rm victim/*", "rm victim/**/*.txt"])
def test_glob_enumeration_failure_cannot_look_like_no_deletion(tmp_path, monkeypatch, command):
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "file.txt").write_text("data", encoding="utf-8")
    scandir = del_count.os.scandir

    def scan(path):
        if str(path) == str(victim):
            raise PermissionError("glob directory cannot be listed")
        return scandir(path)

    monkeypatch.setattr(del_count.os, "scandir", scan)
    with pytest.raises(ValueError):
        del_count.count_deletion_targets(command, "bash", tmp_path)
    result = DeletionGuard(soft_delete_enabled=True, workspace_root=str(tmp_path)).evaluate(
        "bash", {"command": command, "shell_type": "bash"},
    )
    assert result is not None and result.permission is PermissionLevel.ASK
    assert result.matched_rule == "del_guard:batch_delete"


@pytest.mark.parametrize("pattern,names", [
    ("*.txt", {"one.txt"}), ("[ot]*.txt", {"one.txt"}),
    ("**/*.txt", {"one.txt", "nested/two.txt"}), ("missing/*", set()),
])
def test_glob_count_preserves_matching_and_hidden_file_semantics(tmp_path, pattern, names):
    (tmp_path / "nested").mkdir()
    for name in ["one.txt", ".hidden.txt", "other.bin", "nested/two.txt"]:
        (tmp_path / name).write_text("data", encoding="utf-8")
    count, paths = del_count.count_deletion_targets(f"rm {pattern}", "bash", tmp_path)
    assert count == len(names)
    assert set(paths) == {str(tmp_path / name) for name in names}


@pytest.mark.parametrize("command", ["echo 'x|rm victim' && echo done", "echo ok | rm victim"])
def test_real_tree_parser_with_multiple_commands_does_not_change_literal_analysis(tmp_path, command):
    victim = tmp_path / "victim"
    victim.write_text("data", encoding="utf-8")
    parsed = shell_ast.parse_shell_for_permission(command)
    if len(parsed.subcommands or ()) < 2:
        pytest.skip("optional tree parser did not produce multiple commands")
    expected = (1, [str(victim)]) if command.endswith("rm victim") else (0, [])
    assert del_count.count_deletion_targets(command, "bash", tmp_path) == expected


@pytest.mark.skipif(sys.platform != "win32", reason="CMD active-drive semantics")
@pytest.mark.parametrize("switch", ["", "/d "])
def test_cmd_drive_change_uses_same_cwd_as_file_guard(tmp_path, monkeypatch, switch):
    drive = "D:" if tmp_path.drive.lower() == "c:" else "C:"
    destination = path_extract.Path(drive, "/other")
    cwds = []

    def target(_operand, cwd, _profile=None):
        cwds.append(cwd)
        return []

    monkeypatch.setattr(del_count, "_expand_target", target)
    command = f"cd {switch}{destination} && del ./victim"
    assert del_count.count_deletion_targets(command, "cmd", tmp_path) == (0, [])
    expected = destination if switch else tmp_path
    assert cwds == [expected]
    assert path_extract.extract_shell_path_accesses(command, tmp_path, shell_type="cmd", include_cd_reads=False) == [
        (expected / "victim", "write"),
    ]
