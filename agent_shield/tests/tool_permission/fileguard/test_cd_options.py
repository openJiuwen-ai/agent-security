# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""cd options have shell-specific directory effects, not a generic flags-only no-op."""

import pytest

from agent_shield.tool_permission.fileguard import path_extract as paths


@pytest.mark.parametrize("extractor", [paths.extract_shell_path_accesses, paths.extract_path_aware_command_accesses])
@pytest.mark.parametrize("command", ["cd --help", "cd -P --help"])
def test_bash_cd_help_does_not_visit_home_or_change_following_directory(tmp_path, extractor, command):
    assert extractor(command, tmp_path, shell_type="bash") == []
    assert extractor(f"{command}; cat ./notes", tmp_path, shell_type="bash") == [(tmp_path / "notes", "read")]


@pytest.mark.parametrize("dialect,command", [
    ("bash", "cd --"), ("bash", "cd -P"), ("bash", "cd -L"), ("bash", "cd -Pe"),
    ("sh", "cd --"), ("sh", "cd -P"),
])
def test_posix_cd_options_without_directory_use_existing_home_contract(tmp_path, monkeypatch, dialect, command):
    home = tmp_path / "home"
    monkeypatch.setattr(paths.Path, "home", classmethod(lambda cls: home))
    accesses = paths.extract_shell_path_accesses(f"{command} && cat ./notes", tmp_path, shell_type=dialect)
    assert (home, "read") in accesses
    assert (home / "notes", "read") in accesses
    assert (tmp_path / "notes", "read") not in accesses


@pytest.mark.parametrize("command", ["cd -", "cd -- -", "cd -Z", "cd -P -"])
def test_previous_directory_or_unsupported_option_never_reuses_old_cwd(tmp_path, monkeypatch, command):
    monkeypatch.setenv("OLDPWD", str(tmp_path / "untrusted-host-previous"))
    with pytest.raises(ValueError, match="working directory"):
        paths.extract_shell_path_accesses(f"{command} && cat ./notes", tmp_path, shell_type="bash")


def test_end_of_options_keeps_a_dash_prefixed_literal_directory(tmp_path):
    accesses = paths.extract_shell_path_accesses("cd -- --help && cat ./notes", tmp_path, shell_type="bash")
    assert (tmp_path / "--help" / "notes", "read") in accesses


@pytest.mark.parametrize("command", ["cd", "cd /?", "cd /d"])
def test_cmd_query_help_or_missing_d_target_does_not_select_home(tmp_path, command):
    assert paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd") == []


@pytest.mark.parametrize("command", ["cd /d ./child", "cd ./child directory"])
def test_cmd_cd_recognizes_drive_option_and_unquoted_spaces(tmp_path, command):
    directory = "child" if "/d" in command else "child directory"
    accesses = paths.extract_shell_path_accesses(f"{command} && type ./notes", tmp_path, shell_type="cmd")
    assert (tmp_path / directory / "notes", "read") in accesses


@pytest.mark.parametrize("dialect,command", [("sh", "cd --help"), ("powershell", "cd --help")])
def test_bash_help_is_not_a_cross_dialect_noop(tmp_path, dialect, command):
    with pytest.raises(ValueError, match="working directory"):
        paths.extract_shell_path_accesses(command, tmp_path, shell_type=dialect)


def test_cmd_dash_prefixed_directory_is_not_bash_help(tmp_path):
    accesses = paths.extract_shell_path_accesses("cd --help && type ./notes", tmp_path, shell_type="cmd")
    assert (tmp_path / "--help" / "notes", "read") in accesses


def test_help_does_not_hide_output_redirection(tmp_path):
    accesses = paths.extract_shell_path_accesses(
        "cd --help > ./settings/token", tmp_path, shell_type="bash",
    )
    assert (tmp_path / "settings/token", "write") in accesses


def test_posix_options_keep_literal_directory_after_end_of_options(tmp_path):
    accesses = paths.extract_shell_path_accesses("cd -P -- ./child && cat ./notes", tmp_path, shell_type="bash")
    assert (tmp_path / "child/notes", "read") in accesses


@pytest.mark.skipif(paths.os.name != "nt", reason="Windows has per-drive cwd state")
@pytest.mark.parametrize("switch_drive", [False, True])
def test_cmd_changes_active_drive_only_with_d(tmp_path, switch_drive):
    other_drive = "C:" if tmp_path.drive.lower() != "c:" else "D:"
    target = paths.Path(paths.os.path.join(other_drive, paths.os.sep, "guard-target"))
    option = "/d " if switch_drive else ""
    accesses = paths.extract_shell_path_accesses(
        f"cd {option}{target.as_posix()} && type ./notes", tmp_path, shell_type="cmd",
    )
    expected = (target if switch_drive else tmp_path) / "notes"
    wrong = (tmp_path if switch_drive else target) / "notes"
    assert (expected, "read") in accesses
    assert (wrong, "read") not in accesses


@pytest.mark.skipif(paths.os.name != "nt", reason="Windows active drive requires explicit context")
def test_cmd_without_workdir_cannot_guess_active_drive(tmp_path):
    with pytest.raises(ValueError, match="working directory"):
        paths.extract_shell_path_accesses("cd C:/guard-target && type ./notes", None, shell_type="cmd")
    assert (paths.Path("C:/guard-target/notes"), "read") in paths.extract_shell_path_accesses(
        "cd /d C:/guard-target && type ./notes", None, shell_type="cmd",
    )


@pytest.mark.parametrize("command", ["cd C:", "cd D:"])
def test_cmd_drive_query_does_not_change_directory(tmp_path, command):
    assert paths.extract_shell_path_accesses(command, tmp_path, shell_type="cmd") == []


@pytest.mark.parametrize("command", [
    "cd -PassThru ./child", "cd ./child -Verbose", "cd -Path ./child -Debug",
])
def test_powershell_readonly_switches_keep_the_literal_target(tmp_path, command):
    accesses = paths.extract_shell_path_accesses(
        f"{command}; Get-Content ./notes", tmp_path, shell_type="powershell",
    )
    assert (tmp_path / "child/notes", "read") in accesses
