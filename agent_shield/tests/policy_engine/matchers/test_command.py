"""Normative command tokenizer from the rule model."""

import pytest

from agent_shield.policy_engine.matchers.command import (
    command_object_matches,
    command_rule_matches,
    command_segments,
    normalize_program,
)


@pytest.mark.parametrize(
    ("rule", "command", "windows", "expected"),
    [
        ("python", "python", False, True),
        ("python", "python.exe", True, True),
        ("python", r"C:\Tools\python.exe", True, True),
        ("python", "python.exe", False, False),
        ('cmd "a b"', 'cmd "a b"', False, True),
        ("cmd a", 'cmd "a b"', False, False),
        ("python", "python3", False, False),
        ("git push", "git push", False, True),
        ("git push", "git push origin main", False, True),
        ("git push", "git pull", False, False),
        ("docker * alpine", "docker run alpine", False, True),
        ("docker * alpine", "docker pull alpine", False, True),
        ("docker * alpine", "docker run --rm alpine", False, False),
        ("*", "git push", False, True),
        ("git*", "git push", False, False),
        ("Git Push", "git push", False, False),
        ("git PUSH", "git push", False, False),
    ],
)
def test_command_rule_table(rule, command, windows, expected):
    tokens = command.split()
    assert command_rule_matches(rule, tokens, windows) is expected


def test_compound_command_splits_before_each_segment_is_judged():
    assert command_segments("git status && rm -rf ~") == [["git", "status"], ["rm", "-rf", "~"]]
    assert command_rule_matches("git status", ["git", "status"], False)
    assert not command_rule_matches("git status", ["rm", "-rf", "~"], False)


def test_windows_only_strips_exe():
    assert normalize_program(r"C:\Windows\System32\sc.exe", True) == "sc"
    assert normalize_program("python.exe", False) == "python.exe"


def test_allow_needs_a_command_line_deny_may_use_shell_argv():
    argv = ["git", "push"]
    assert (
        command_object_matches(
            "git push", action="allow", command_tokens=argv, shell_argv=argv, windows=False, has_command_line=False
        )
        is False
    )
    assert (
        command_object_matches(
            "git push", action="deny", command_tokens=[], shell_argv=argv, windows=False, has_command_line=False
        )
        is True
    )
    assert (
        command_object_matches(
            "git push", action="ask", command_tokens=[], shell_argv=argv, windows=False, has_command_line=False
        )
        is True
    )
