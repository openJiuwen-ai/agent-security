# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Remembered approvals take priority within their whole-call or candidate scope."""

import asyncio

import pytest

from agent_shield.tool_permission import PermissionLevel as L
from agent_shield.tool_permission.manager import new_permission_manager
from agent_shield.tool_permission.toolguard import shell_ast


def _config(command, **extra):
    return {
        "package_builtin_rules": False,
        "shell_allowlist": None,
        "tools": {"bash": "ask"},
        "approval_overrides": [
            {"id": "remembered", "tools": ["bash"], "pattern": command, "action": "allow"}
        ],
        **extra,
    }


def _check(config, command, **args):
    manager = new_permission_manager()
    return asyncio.run(manager.check_permission("bash", {"command": command, **args}, config=config))


@pytest.mark.parametrize("command", ["echo audit", "bash -c 'echo audit'", "echo ok && echo audit"])
@pytest.mark.parametrize("layer", ["user", "builtin"])
def test_remembered_approval_overrides_explicit_command_deny(command, layer):
    config = _config(command, rules=[{
        "id": "blocked", "layer": layer, "tools": ["bash"],
        "pattern": "re:^echo audit$", "action": "deny",
    }])
    if layer == "builtin":
        config["package_builtin_rules"] = True
    result = _check(config, command)
    assert result.permission is L.ALLOW
    assert "approval_overrides" in result.matched_rule


@pytest.mark.parametrize("action", ["ask", "deny"])
@pytest.mark.parametrize("command", ["cat ./secret", "echo ok && cat ./secret"])
@pytest.mark.parametrize("approved", [False, True])
def test_whole_approval_overrides_file_guard_only_when_matched(tmp_path, action, command, approved):
    config = _config(command if approved else "echo other", runtime={"workspace_root": str(tmp_path)}, file_guard={
        "enabled": True,
        "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
        "paths": [{"path": str(tmp_path / "secret"), "read": action, "write": action, "exec": action}],
    }, guard_actions={"compound_chain": "allow"}, tools={"bash": "allow"})
    result = _check(config, command, shell_type="bash")
    assert result.permission is (L.ALLOW if approved else L(action))
    if approved:
        assert "approval_overrides" in result.matched_rule
        assert result.ask_accesses == []
    elif action == "ask":
        assert ((tmp_path / "secret").as_posix(), "read") in result.ask_accesses
    else:
        assert "file_guard" in result.matched_rule


@pytest.mark.parametrize("approved", [False, True])
def test_whole_approval_overrides_control_plane_only_when_matched(tmp_path, approved):
    config = _config("echo ok > ./settings/token", runtime={
        "workspace_root": str(tmp_path), "immutable_control_roots": [str(tmp_path / "settings")],
    })
    if not approved:
        config["approval_overrides"] = []
    result = _check(config, "echo ok > ./settings/token", shell_type="bash")
    assert result.permission is (L.ALLOW if approved else L.DENY)
    if approved:
        assert "approval_overrides" in result.matched_rule
    else:
        assert result.matched_rule == "immutable_control_plane"


@pytest.mark.parametrize("approved", [False, True])
def test_whole_approval_skips_batch_delete_guard_only_when_matched(tmp_path, approved):
    (tmp_path / "one.txt").write_text("one", encoding="utf-8")
    (tmp_path / "two.txt").write_text("two", encoding="utf-8")
    command = "rm ./one.txt ./two.txt"
    config = _config(command, runtime={"workspace_root": str(tmp_path)}, tools={"bash": "allow"},
                     soft_delete={"enabled": True, "batch_delete_threshold": 2})
    if not approved:
        config["approval_overrides"] = []
    result = _check(config, command, workdir=str(tmp_path), shell_type="bash")
    assert result.permission is (L.ALLOW if approved else L.ASK)
    assert ("approval_overrides" if approved else "del_guard") in result.matched_rule


@pytest.mark.parametrize("fallback", [False, True])
@pytest.mark.parametrize("command", ["echo $(cat ./secret)", "{ echo audit; }"])
def test_whole_approval_short_circuits_injection_and_structure(monkeypatch, fallback, command):
    if fallback:
        monkeypatch.setattr(shell_ast, "_get_tree_sitter_bash_parser", lambda: None)
    result = _check(_config(command), command)
    assert result.permission is L.ALLOW
    assert "approval_overrides" in result.matched_rule


def test_simple_remembered_approval_keeps_existing_baseline_override():
    result = _check(_config("echo audit", tools={"bash": "deny"}), "echo audit")
    assert result.permission is L.ALLOW
    assert "approval_overrides" in result.matched_rule


def test_unwrapped_whole_approval_overrides_tool_and_command_deny():
    config = _config("echo audit", tools={"bash": "deny"}, rules=[{
        "id": "blocked", "tools": ["bash"], "pattern": "echo audit", "action": "deny",
    }])
    result = _check(config, "bash -c 'echo audit'")
    assert result.permission is L.ALLOW
    assert "approval_overrides" in result.matched_rule


def test_regex_matching_whole_chain_approves_the_whole_call():
    config = _config("re:echo approved", tools={"bash": "deny"}, rules=[{
        "id": "blocked", "tools": ["bash"], "pattern": "echo other", "action": "deny",
    }])
    result = _check(config, "echo approved && echo other")
    assert result.permission is L.ALLOW
    assert "approval_overrides" in result.matched_rule


def test_approval_and_deny_remain_isolated_by_opaque_client_key():
    manager = new_permission_manager()
    approved = "group:bot:user:agent:a"
    blocked = "default:agent:b"
    manager.update_config(_config("echo audit"), key=approved)
    manager.update_config(_config("echo other", rules=[{
        "id": "blocked", "tools": ["bash"], "pattern": "echo audit", "action": "deny",
    }]), key=blocked)
    assert asyncio.run(manager.check_permission("bash", {"command": "echo audit"}, key=approved)).permission is L.ALLOW
    assert asyncio.run(manager.check_permission("bash", {"command": "echo audit"}, key=blocked)).permission is L.DENY
    assert "rules" not in manager.get_config(key=approved)


@pytest.mark.parametrize("key", ["default:agent:a", "group:bot:user:agent:a"])
def test_one_off_approval_does_not_mutate_registered_config(tmp_path, key):
    manager = new_permission_manager()
    base = _config("cat ./secret", runtime={"workspace_root": str(tmp_path)}, file_guard={
        "enabled": True,
        "defaults": {"read": "ask", "write": "ask", "exec": "ask"},
    })
    approval = base.pop("approval_overrides")
    manager.update_config(base, key=key)
    args = {"command": "cat ./secret", "shell_type": "bash"}
    assert asyncio.run(manager.check_permission("bash", args, key=key)).permission is L.ASK
    session = {**base, "approval_overrides": approval}
    assert asyncio.run(manager.check_permission("bash", args, key=key, config=session)).permission is L.ALLOW
    assert asyncio.run(manager.check_permission("bash", args, key=key)).permission is L.ASK
    assert manager.keys() == ("default", key)


def test_approved_leaf_does_not_duplicate_the_whole_command_warning():
    command = "echo ok && git reset --hard HEAD"
    config = _config("git reset --hard HEAD", tools={"bash": "allow"},
                     guard_actions={"compound_chain": "allow", "parse_unavailable": "allow"})
    result = _check(config, command)
    assert result.permission is L.ALLOW
    assert result.warnings == ["May discard uncommitted changes"]


def test_warning_merge_keeps_distinct_messages_in_first_seen_order():
    from agent_shield.tool_permission.engine import PermissionEngine
    from agent_shield.tool_permission.models import PermissionResult

    result = PermissionEngine.merge_results([
        PermissionResult(permission=L.ALLOW, warnings=["first", "second", "first"]),
        PermissionResult(permission=L.ASK, warnings=["second", "third"]),
    ])
    assert result.permission is L.ASK
    assert result.warnings == ["first", "second", "third"]
