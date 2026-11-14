# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""New native profile does not alter the legacy policy contract."""

import os
from unittest.mock import AsyncMock, Mock

import pytest

from agent_shield.intercepts.native_call.dll_guard import RuntimeApprovalRequests
from agent_shield.intercepts.native_call.dll_guard.context import RuntimeGuardContext
from agent_shield.intercepts.native_call.dll_guard.policy import (
    evaluate_resource,
    program_policy_args,
)
from agent_shield.tool_permission.delguard.component import DeletionGuardComponent
from agent_shield.tool_permission.models import PermissionLevel, PermissionResult
from agent_shield.tool_permission.netguard.component import NetGuardComponent
from agent_shield.tool_permission.runtime.engine import HostPolicyAdapter, PermissionEngine
from agent_shield.tool_permission.runtime.grants import build_operation_grant
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse
from agent_shield.tool_permission.runtime.models import PermissionResult as RuntimeResult
from agent_shield.tool_permission.toolguard import shell_ast


def test_loopback_profile_and_private_catalog_are_opt_in(tmp_path):
    config = {
        "file_guard": {"enabled": True, "defaults": {"read": "allow"}},
        "net_guard": {"enabled": True, "defaults": "deny"},
    }
    runtime = PermissionEngine(config, workspace_root=tmp_path)
    assert runtime.check_network_access("localhost").is_allowed
    assert runtime.check_file_accesses([(tmp_path / "private.pem", "read")]).is_denied
    old = NetGuardComponent()
    old.configure(config)
    assert (
        old.evaluate_url_policy("mcp_fetch_webpage", {"url": "http://localhost/"}).permission
        == PermissionLevel.DENY
    )
    assert "builtin" not in config and "urls" not in config["net_guard"]
    explicit = PermissionEngine(
        {**config, "net_guard": {"enabled": True, "urls": {"localhost": "deny"}}}
    )
    assert explicit.check_network_access("localhost").is_denied


@pytest.mark.skipif(os.name != "nt", reason="Windows runtime profile")
def test_windows_sensitive_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("APPDATA", str(tmp_path / "roaming"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    config = {"file_guard": {"enabled": True, "defaults": {"read": "allow"}}}
    engine = PermissionEngine(config)
    for path in [
        "roaming/Microsoft/Protect",
        "roaming/Microsoft/Protect/SID/key",
        "ROAMING/MICROSOFT/CREDENTIALS/file",
        "local/Microsoft/Credentials/entry",
        "local/Google/Chrome/User Data/Default/Login Data",
        "local/Microsoft/Edge/User Data/Profile 2/LOGIN DATA",
        "local/Microsoft/Edge/User Data/Local State",
        ".GIT-CREDENTIALS",
    ]:
        assert engine.check_file_accesses([(tmp_path / path, "read")]).is_denied, path
    for path in [
        ".PYPIRC",
        ".azure",
        ".azure/msal_token_cache.bin",
        "roaming/GitHub CLI/hosts.yml",
        ".config/gh/hosts.yml",
    ]:
        assert engine.check_file_accesses([(tmp_path / path, "read")]).needs_approval, path
    for path in [
        "roaming/Microsoft/ProtectOther/key",
        ".azure-docs/example",
        "local/MyApp/Local State",
    ]:
        assert engine.check_file_accesses([(tmp_path / path, "read")]).is_allowed, path
    for override in [{"package_builtin_rules": False}, {"builtin": {"sensitive_paths": []}}]:
        engine.update_config({**config, **override})
        assert engine.check_file_accesses([(tmp_path / ".git-credentials", "read")]).is_allowed

    # An exact spelling overlay still inherits the packaged rule's casing.
    config["file_guard"]["paths"] = [
        {"path": (tmp_path / ".git-credentials").as_posix(), "match": "glob", "read": "allow"}
    ]
    engine.update_config(config)
    assert engine.check_file_accesses([(tmp_path / ".GIT-CREDENTIALS", "read")]).is_denied


_METADATA_V4 = ".".join(("100", "100", "100", "200"))
_METADATA_V6 = ":".join(("fd00", "ec2:", "254"))
_NEIGHBOR_V4 = ".".join(("100", "100", "100", "201"))


@pytest.mark.parametrize("address", [_METADATA_V4, _METADATA_V6])
def test_runtime_metadata_default_covers_url_and_endpoint(address):
    authority = f"[{address}]" if ":" in address else address
    config = {"net_guard": {"enabled": True, "defaults": "allow", "urls": {address: "allow"}}}
    engine = PermissionEngine(config)
    for resource in [address, f"{authority}:8080", f"http://{authority}/latest"]:
        assert engine.check_network_access(resource).is_denied, resource
    assert engine.check_network_access(f"{_NEIGHBOR_V4}:8080").is_allowed
    engine.update_config({**config, "package_builtin_rules": False})
    assert engine.check_network_access(f"{authority}:8080").is_allowed


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "rule,allowed",
    [
        ("tools.bash", True),
        ("tools.bash|del_guard:batch_delete", True),
        ("file_guard:defaults|del_guard:batch_delete", False),
        ("host_review", False),
    ],
)
async def test_native_preapproval_respects_host_guard_result(tmp_path, rule, allowed):
    host = Mock()
    host.check_file_accesses.return_value = RuntimeResult(PermissionLevel.ALLOW)
    host.check_permission = AsyncMock(return_value=RuntimeResult(PermissionLevel.ASK, rule))
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "echo.exe"),
        "argv": [],
        "cwd": str(tmp_path),
    }
    result = await evaluate_resource(HostPolicyAdapter(host), subject, command_approved=True)
    assert result.is_allowed is allowed
    if not allowed:
        assert result.needs_approval and result.matched_rule == rule


@pytest.mark.parametrize(
    "permission,command_approved,allowed",
    [
        (PermissionLevel.ASK, False, False),
        (PermissionLevel.ASK, True, True),
        (PermissionLevel.DENY, True, False),
    ],
)
@pytest.mark.asyncio
async def test_host_batch_delete_decision(tmp_path, permission, command_approved, allowed):
    host = Mock()
    host.check_file_accesses.return_value = RuntimeResult(PermissionLevel.ALLOW)
    host.check_permission = AsyncMock(
        return_value=RuntimeResult(permission, "del_guard:batch_delete")
    )
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "rm.exe"),
        "argv": ["a", "b"],
        "cwd": str(tmp_path),
    }
    result = await evaluate_resource(
        HostPolicyAdapter(host),
        subject,
        command_approved=command_approved,
    )
    assert result.is_allowed is allowed


@pytest.mark.parametrize(
    "command",
    ["echo $(rm B)", "git status &", "git status # comment", 'cmd /c "git status && git diff"'],
)
def test_shared_grant_splitter_rejects_incomplete_input(command):
    assert shell_ast.split_shell_for_grants(command) == ()


def test_shared_grant_splitter_preserves_redirect_destinations():
    if getattr(shell_ast, "_get_tree_sitter_bash_parser")() is None:
        pytest.skip("optional tree-sitter backend not installed")
    assert shell_ast.split_shell_for_grants("printf hi > A && rm B && ls B 2>&1") == (
        "printf hi > A",
        "rm B",
        "ls B 2>&1",
    )
    assert shell_ast.split_shell_for_grants("cat < A | rm B") == ("cat < A", "rm B")


@pytest.mark.parametrize("command", ["git status", "git status &", "git status # comment"])
def test_grant_splitter_keeps_exact_only_without_syntax_backend(monkeypatch, command):
    monkeypatch.setattr(shell_ast, "_get_tree_sitter_bash_parser", lambda: None)
    assert shell_ast.split_shell_for_grants(command) == ()


@pytest.mark.asyncio
@pytest.mark.parametrize("defer", [False, True])
async def test_runtime_receipt_never_lifts_deletion_guard_ask(tmp_path, monkeypatch, defer):
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "tools": {"bash": "ask"},
        "defer_unmatched": defer,
        "file_guard": {"enabled": True, "defaults": {"read": "allow", "exec": "allow"}},
    }
    args = {"command": "echo hello", "workdir": str(tmp_path), "shell_type": "bash"}
    config["approval_overrides"] = [build_operation_grant("bash", args, config, tmp_path)]
    engine = PermissionEngine(config, workspace_root=tmp_path)
    assert (await engine.check_permission("bash", args)).is_allowed

    async def incomplete(*_args, **_kwargs):
        return PermissionResult(PermissionLevel.ASK, "del_guard:batch_delete")

    monkeypatch.setattr(DeletionGuardComponent, "evaluate", incomplete)
    result = await engine.check_permission(
        "bash", args, file_accesses=[(tmp_path / "echo.exe", "exec")]
    )
    assert result.needs_approval and "del_guard" in result.matched_rule


def test_failed_policy_update_keeps_previous_deny(tmp_path):
    engine = PermissionEngine({"net_guard": {"enabled": True, "urls": {"localhost": "deny"}}})
    before = engine.config
    with pytest.raises((TypeError, ValueError)):
        engine.update_config({"net_guard": {"enabled": True, "urls": {"localhost": "typo"}}})
    assert engine.config is before and engine.check_network_access("localhost").is_denied


@pytest.mark.parametrize(
    "kwargs",
    [
        {"approved": "false"},
        {"approved": True, "auto_confirm": "0"},
        {"approved": True, "persist_allow": "false"},
    ],
)
def test_approval_flags_reject_truthy_strings(kwargs):
    with pytest.raises(TypeError):
        PermissionConfirmResponse(**kwargs)


@pytest.mark.asyncio
async def test_malformed_reply_leaves_request_pending():
    from types import SimpleNamespace

    registry = RuntimeApprovalRequests()
    context = RuntimeGuardContext("session", "call", "v1")
    answer = PermissionConfirmResponse(approved=False)

    async def emit(event):
        for invalid in (
            None,
            SimpleNamespace(approved="false"),
            SimpleNamespace(approved=True, auto_confirm=1),
        ):
            assert not registry.resolve("session", event["request_id"], invalid)
        assert registry.resolve("session", event["request_id"], answer)

    assert await registry.request(context, {}, emit, 1) is answer


@pytest.mark.asyncio
async def test_host_permission_activation_applies_to_program_checks():
    engine = PermissionEngine({"enabled": True, "tools": {"bash": "deny"}})
    args = {"command": "echo hello", "shell_type": "bash"}
    assert (await engine.check_permission("bash", args)).is_denied
    engine.set_permission_checks_active(lambda: False)
    assert (await engine.check_permission("bash", args)).is_allowed
    engine.set_permission_checks_active(lambda: True)
    assert (await engine.check_permission("bash", args)).is_denied


@pytest.mark.asyncio
async def test_native_program_arguments_are_literal_but_tool_text_keeps_structure_checks(tmp_path):
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": "allow"},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        },
        workspace_root=tmp_path,
    )
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "bash.exe"),
        "argv": ["-c", "cd child && echo literal"],
        "cwd": str(tmp_path),
    }
    assert (await engine.check_permission("bash", program_policy_args(subject))).needs_approval
    assert (await evaluate_resource(engine, subject, source_tool="bash")).is_allowed


@pytest.mark.asyncio
@pytest.mark.parametrize("floor", ["file", "deletion", "command"])
async def test_legacy_command_receipt_does_not_bypass_native_guard_floors(
    tmp_path, monkeypatch, floor
):
    subject = {
        "kind": "program",
        "exe": str(tmp_path / ("git.exe" if os.name == "nt" else "git")),
        "argv": ["version"],
        "cwd": str(tmp_path),
    }
    args = program_policy_args(subject, "bash")
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "tools": {"bash": "ask"},
        "approval_overrides": [
            {
                "id": "old",
                "tools": ["bash"],
                "match_type": "command",
                "pattern": args["command"],
                "action": "allow",
            }
        ],
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
        },
    }
    if floor == "file":
        config["file_guard"]["paths"] = [{"path": subject["exe"], "exec": "deny"}]
    if floor == "command":
        config["rules"] = [
            {
                "id": "deny_git",
                "tools": ["bash"],
                "match_type": "command",
                "pattern": "git version",
                "action": "deny",
            }
        ]
    if floor == "deletion":

        async def incomplete(*_args, **_kwargs):
            return PermissionResult(PermissionLevel.ASK, "del_guard:batch_delete")

        monkeypatch.setattr(DeletionGuardComponent, "evaluate", incomplete)
    result = await evaluate_resource(
        PermissionEngine(config, workspace_root=tmp_path), subject, source_tool="bash"
    )
    assert result.needs_approval if floor == "deletion" else result.is_denied
