"""Resource scope and persistence do not broaden existing permission behavior."""

import importlib.util
import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    RuntimeApprovalRequests,
    WindowsGuardExecution,
)
from agent_shield.intercepts.native_call.dll_guard.policy import (
    SessionResourceGrants,
    evaluate_resource,
    program_tool_args,
    resource_grant,
    resource_grant_matches,
)
from agent_shield.intercepts.native_call.dll_guard.shell_launch import (
    _literal_programs,
    approved_programs,
)
from agent_shield.tool_permission.runtime.confirmation import normalize_confirmation_scope
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse


def bash_parser_ready():
    from agent_shield.tool_permission.toolguard import shell_ast

    return getattr(shell_ast, "_get_tree_sitter_bash_parser")() is not None


NEEDS_BASH_PARSER = pytest.mark.skipif(
    not bash_parser_ready(), reason="tree-sitter-bash is required"
)
NEEDS_TLD = pytest.mark.skipif(
    importlib.util.find_spec("tld") is None, reason="tld is required for domain scope"
)


def make_execution(tmp_path, emit, registry, *, read="ask", write="ask"):
    target = tmp_path / "target.txt"
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "file_guard": {
                "enabled": True,
                "paths": [{"path": str(target), "read": read, "write": write, "exec": "deny"}],
            },
        },
        workspace_root=tmp_path / "workspace",
    )
    execution = WindowsGuardExecution(
        session_id="s",
        tool_call_id="call",
        dll=tmp_path / "guard.dll",
        engine=lambda: engine,
        emit=emit,
        approvals=registry,
    )
    execution.job = SimpleNamespace(contains=lambda pid: pid == 123, close=lambda: None)
    return target, execution


@pytest.mark.parametrize("configured", [False, True])
def test_git_forwarding_uses_only_the_configured_sdk_installation(
    tmp_path, monkeypatch, configured
):
    import os

    from agent_shield.intercepts.native_call.dll_guard.shell_launch import (
        _with_configured_launcher_targets,
    )

    if os.name != "nt":
        pytest.skip("Windows Git launcher layout")
    launcher = tmp_path / "Git/cmd/git.exe"
    target = tmp_path / "Git/mingw64/bin/git.exe"
    unrelated = tmp_path / "other/git.exe"
    for path in (launcher, target, unrelated):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch()
    monkeypatch.delenv("AGENT_SHIELD_GIT_EXE", raising=False)
    if configured:
        monkeypatch.setenv("AGENT_SHIELD_GIT_EXE", str(launcher))
    programs = [
        {"kind": "program", "exe": str(path), "argv": ["status", "--short"], "cwd": str(tmp_path)}
        for path in (launcher, unrelated)
    ]
    result = _with_configured_launcher_targets(deepcopy(programs))
    expected = [*programs, {**programs[0], "exe": str(target)}] if configured else programs
    assert result == expected


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "bash,powershell", [("deny", "allow"), ("allow", "deny"), ("allow", "ask")]
)
async def test_actual_powershell_uses_powershell_rules(tmp_path, bash, powershell):
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": bash, "powershell": powershell},
        },
        workspace_root=tmp_path,
    )
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "powershell.exe"),
        "argv": ["-NoProfile", "-Command", "Write-Output OK"],
        "cwd": str(tmp_path),
    }
    original = await engine.check_permission(
        "powershell", {"command": "Write-Output OK", "shell_type": "powershell"}
    )
    assert (await evaluate_resource(engine, subject)).permission == original.permission


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "source,shell,executable",
    [
        ("powershell", "powershell", "powershell.exe"),
        ("core.powershell", "powershell", "powershell.exe"),
        ("mcp_exec_command", "bash", "bash.exe"),
        ("exec_command", "bash", "bash.exe"),
        ("mcp_exec_command", "powershell", "powershell.exe"),
    ],
)
async def test_trusted_shell_tool_identity_is_preserved(tmp_path, source, shell, executable):
    normalized = "mcp_exec_command" if source == "exec_command" else source
    tools = {
        "bash": "deny",
        "powershell": "deny",
        "core.powershell": "deny",
        "mcp_exec_command": "deny",
    }
    tools[normalized] = "allow"
    engine = PermissionEngine(
        {"enabled": True, "package_builtin_rules": False, "tools": tools}, workspace_root=tmp_path
    )
    subject = {
        "kind": "program",
        "exe": str(tmp_path / executable),
        "cwd": str(tmp_path),
        "argv": ["-lc", "echo OK"] if shell == "bash" else ["-Command", "Write-Output OK"],
    }
    result = await evaluate_resource(engine, subject, source_tool=source, source_shell=shell)
    assert result.is_allowed
    assert program_tool_args(subject, source, shell)["shell_type"] == shell


@pytest.mark.asyncio
@pytest.mark.parametrize("command_rule", ["ask", "allow"])
@pytest.mark.parametrize("approval", ["root", "child"])
async def test_child_batch_delete_keeps_existing_threshold(tmp_path, command_rule, approval):
    paths = [tmp_path / "a.txt", tmp_path / "b.txt"]
    for path in paths:
        path.write_text("test")
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": command_rule},
            "soft_delete": {"enabled": True, "batch_delete_threshold": 2},
        },
        workspace_root=tmp_path,
    )
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "rm.exe"),
        "argv": [str(p) for p in paths],
        "cwd": str(tmp_path),
    }
    if approval == "root":
        subject["root_command_approved"] = True
    result = await evaluate_resource(engine, subject)
    assert result.needs_approval and "del_guard:batch_delete" in result.matched_rule
    assert (await evaluate_resource(engine, subject, command_approved=True)).is_allowed

    cards, registry = [], RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve(
            "s", event["request_id"], PermissionConfirmResponse(approved=len(cards) == 1)
        )

    _, execution = make_execution(tmp_path, emit, registry)

    def current_engine():
        return engine

    execution.engine = current_engine
    if approval == "child":
        _, version = getattr(execution, "_policy")()
        execution.approved_programs, execution.approved_programs_version = [subject], version
    assert await execution.check_resource(123, subject)
    assert await execution.check_resource(123, subject)
    assert len(cards) == int(approval == "root")
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("handoff", [True, False])
@pytest.mark.parametrize("command_rule", ["allow", "ask"])
@NEEDS_BASH_PARSER
async def test_batch_delete_approval_follows_only_the_approved_command(
    tmp_path, handoff, command_rule
):
    registry, cards = RuntimeApprovalRequests(), []

    async def emit(event):
        cards.append(event)
        registry.resolve(
            "s",
            event["request_id"],
            PermissionConfirmResponse(approved=not handoff and len(cards) == 1),
        )

    _, execution = make_execution(tmp_path, emit, registry)
    for name in ("a.txt", "b.txt", "c.txt"):
        (tmp_path / name).touch()
    execution.engine().update_config(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": command_rule},
            "soft_delete": {"enabled": True, "batch_delete_threshold": 2},
        }
    )
    operation = {
        "kind": "command",
        "command": "rm a.txt b.txt",
        "shell_type": "bash",
        "cwd": str(tmp_path),
    }
    programs = approved_programs(operation)
    shell = programs[0]
    child = next(p for p in programs if Path(p["exe"]).stem == "rm")
    decision = await evaluate_resource(execution.engine(), shell)
    assert decision.needs_approval and set(map(Path, decision.external_paths)) == {
        tmp_path / "a.txt",
        tmp_path / "b.txt",
    }
    if handoff:
        execution.seed_approved_operation({"operation": operation})
    assert await execution.check_resource(123, shell)
    assert await execution.check_resource(123, child)
    assert len(cards) == int(not handoff)
    assert not await execution.check_resource(123, {**child, "argv": ["a.txt", "c.txt"]})
    assert await execution.check_resource(123, child)
    assert len(cards) == int(not handoff) + 1

    def updated_revision():
        return "updated"

    execution.policy_revision = updated_revision
    assert not await execution.check_resource(123, child)
    assert len(cards) == int(not handoff) + 2
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("receipt_scope", ["parent", "exact"])
@pytest.mark.parametrize("reply_format", ["object", "dict", "legacy"])
async def test_file_handoff_preserves_host_scope(tmp_path, receipt_scope, reply_format):
    registry, cards = RuntimeApprovalRequests(), []

    async def emit(event):
        cards.append(event)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(False))

    target, execution = make_execution(tmp_path, emit, registry)
    operation = {"kind": "file", "accesses": [(str(target), "read")]}
    answer = PermissionConfirmResponse(True, authorization_scope=receipt_scope)
    receipt = {"operation": operation, "grants": [resource_grant(operation, answer)]}
    if reply_format == "object":
        receipt["confirmation"] = answer
    elif reply_format == "dict":
        receipt["confirmation"] = {"approved": True, "authorization_scope": receipt_scope}
    execution.seed_approved_operation(receipt)
    assert await execution.check_access(123, str(target), 1)
    assert (await execution.check_access(123, str(tmp_path / "B.txt"), 1)) is (
        receipt_scope == "parent"
    )
    assert not await execution.check_access(123, str(target), 2)
    assert len(cards) == (1 if receipt_scope == "parent" else 2)
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"approved": True, "extra": 1},
        {"approved": "yes"},
        {"approved": True, "authorization_scope": "invalid"},
        {"approved": True, "authorization_scope": []},
        {"approved": False},
    ],
)
async def test_invalid_handoff_seeds_no_access(tmp_path, answer):
    registry = RuntimeApprovalRequests()

    async def reject(event):
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(False))

    target, execution = make_execution(tmp_path, reject, registry)
    accesses = [(str(target), "read")]
    execution.seed_approved_operation(
        {
            "operation": {"kind": "file", "accesses": accesses},
            "accesses": accesses,
            "confirmation": answer,
        }
    )
    assert not await execution.check_access(123, str(target), 1)
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [False, True])
async def test_runtime_keeps_existing_project_config_confirmation(tmp_path, enabled):
    cards, registry = [], RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=False))

    _target, obj = make_execution(tmp_path, emit, registry)
    engine = PermissionEngine(
        {"enabled": enabled, "package_builtin_rules": False}, workspace_root=tmp_path
    )

    def current_engine():
        return engine

    obj.engine = current_engine
    a = {"kind": "file", "accesses": [(str(tmp_path / "package.json"), "write")]}
    parent = resource_grant(
        a,
        PermissionConfirmResponse(
            approved=True, authorization_mode="allow_with_scope", authorization_scope="parent"
        ),
    )
    obj.seed_approved_operation({"operation": a, "accesses": a["accesses"], "grants": [parent]})
    assert await obj.check_access(123, str(tmp_path / "package.json"), 2)
    assert (await obj.check_access(123, str(tmp_path / "setup.py"), 2)) is (not enabled)
    assert len(cards) == int(enabled)
    await obj.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("action", ["read", "write", "exec"])
@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
async def test_runtime_control_directory_uses_configured_file_rules(tmp_path, action, decision):
    root = tmp_path / "skills"
    target = root / "script.py"
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
                "paths": [
                    {"path": str(root), "read": decision, "write": decision, "exec": decision}
                ],
            },
        },
        workspace_root=tmp_path,
    )
    result = await evaluate_resource(engine, {"kind": "file", "accesses": [(str(target), action)]})
    assert result.permission.value == decision


@pytest.mark.asyncio
@pytest.mark.parametrize("command_approved", [False, True])
@pytest.mark.parametrize("decision", ["allow", "deny"])
async def test_runtime_skill_program_preserves_sdk_control_plane_deny(
    tmp_path, command_approved, decision
):
    root, exe = tmp_path / "skills", tmp_path / "python.exe"
    subject = {
        "kind": "program",
        "exe": str(exe),
        "argv": [str(root / "session_state.py"), "init"],
        "cwd": str(tmp_path),
    }
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": decision},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        },
        workspace_root=tmp_path,
        immutable_control_roots=[root],
    )
    expected = await engine.check_permission(
        "bash", program_tool_args(subject), file_accesses=[(exe, "exec")]
    )
    assert expected.is_denied and expected.matched_rule == "immutable_control_plane"
    result = await evaluate_resource(engine, subject, command_approved=command_approved)
    assert result.permission == expected.permission
    assert result.matched_rule == expected.matched_rule


@pytest.mark.asyncio
@pytest.mark.parametrize("command_approved", [False, True])
@pytest.mark.parametrize("decision", ["allow", "ask", "deny"])
async def test_unprotected_runtime_script_keeps_command_rule_and_approval(
    tmp_path, command_approved, decision
):
    subject = {
        "kind": "program",
        "exe": str(tmp_path / "python.exe"),
        "argv": [str(tmp_path / "data" / "script.py")],
        "cwd": str(tmp_path),
    }
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": decision},
            "file_guard": {
                "enabled": True,
                "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
            },
        },
        workspace_root=tmp_path,
        immutable_control_roots=[tmp_path / "skills"],
    )
    result = await evaluate_resource(engine, subject, command_approved=command_approved)
    assert result.permission.value == (
        "allow" if command_approved and decision == "ask" else decision
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["missing", "missing_api", "missing_suffix_list"])
async def test_url_approval_without_tld_stays_exact(tmp_path, monkeypatch, failure):
    import sys
    from types import ModuleType

    from agent_shield.tool_permission.runtime_policy import grants

    if failure == "missing_suffix_list":
        pytest.importorskip("tld")
        from tld import base

        from agent_shield.tool_permission.runtime._public_suffix import BundledSuffixList

        monkeypatch.setattr(BundledSuffixList, "local_path", str(tmp_path / "missing.dat"))
        monkeypatch.setattr(base, "urlopen", lambda *_: pytest.fail("Unexpected suffix download"))
    else:
        monkeypatch.setitem(sys.modules, "tld", None if failure == "missing" else ModuleType("tld"))
    registry, urls = RuntimeApprovalRequests(), []

    async def emit(event):
        assert event["resource"]["can_remember"]
        assert [scope["value"] for scope in grants.scope_options(event["resource"])] == ["exact"]
        urls.append(event["resource"]["url"])
        # The second reply requests a scope unavailable for this resource.
        scope = "domain" if len(urls) == 2 else None
        assert registry.resolve(
            "s",
            event["request_id"],
            PermissionConfirmResponse(
                approved=len(urls) <= 2, auto_confirm=True, authorization_scope=scope
            ),
        )

    _, execution = make_execution(tmp_path, emit, registry)
    execution.persist = Mock(return_value=True)
    execution.engine().update_config(
        {"enabled": True, "net_guard": {"enabled": True, "defaults": "ask"}}
    )
    a = {"kind": "url", "url": "https://www.example.com/a"}
    b = {**a, "url": "https://www.example.com/b"}
    assert await execution.check_resource(123, a)
    assert await execution.check_resource(123, a)
    assert not await execution.check_resource(123, b)
    assert not await execution.check_resource(123, b)
    assert urls == [a["url"], b["url"], b["url"]]
    execution.persist.assert_called_once()
    assert json.loads(execution.persist.call_args.args[2]["pattern"])["scope"] == "exact"
    await execution.close()


@pytest.mark.parametrize("remember,expected", [(False, "exact"), (True, "subcommands")])
def test_compound_bash_default_scope_with_parser(tmp_path, remember, expected):
    from agent_shield.tool_permission.runtime import grants
    from agent_shield.tool_permission.toolguard import shell_ast

    if getattr(shell_ast, "_get_tree_sitter_bash_parser")() is None:
        pytest.skip("optional Bash parser unavailable")
    args = {"command": "git status && git diff", "shell_type": "bash", "workdir": str(tmp_path)}
    subject = grants.operation_subject("bash", args, {})
    answer = normalize_confirmation_scope(
        PermissionConfirmResponse(approved=True, auto_confirm=remember), subject
    )
    assert answer.authorization_scope == expected
    receipts = grants.build_operation_grants(
        "bash", args, {}, mode=answer.authorization_mode, scope=answer.authorization_scope
    )
    assert (
        any(grant["match_type"] == grants.SHELL_GRANT_MATCH_TYPE for grant in receipts) is remember
    )


@pytest.mark.parametrize("unavailable", ["tree_sitter", "tree_sitter_bash", "broken_grammar"])
def test_bash_approval_without_parser_stays_exact(tmp_path, monkeypatch, unavailable):
    import sys

    from agent_shield.tool_permission.runtime import command_identity, grants
    from agent_shield.tool_permission.toolguard import shell_ast

    monkeypatch.setattr(shell_ast, "_TREE_SITTER_BASH_READY", None)
    monkeypatch.setattr(shell_ast, "_TREE_SITTER_PARSER", None)
    if unavailable == "broken_grammar":

        def incompatible_language():
            raise ValueError("incompatible language ABI")

        monkeypatch.setitem(
            sys.modules, "tree_sitter_bash", SimpleNamespace(language=incompatible_language)
        )
    else:
        monkeypatch.setitem(sys.modules, unavailable, None)

    args = {"command": "git status && git diff", "shell_type": "bash", "workdir": str(tmp_path)}
    subject = grants.operation_subject("bash", args, {})
    assert [option["value"] for option in grants.scope_options(subject)] == ["exact"]
    normalized = normalize_confirmation_scope(
        PermissionConfirmResponse(approved=True, auto_confirm=True), subject
    )
    assert (normalized.authorization_mode, normalized.authorization_scope) == ("allow", "exact")
    receipt = grants.build_operation_grant("bash", args, {})
    assert grants.matches_subject(receipt, subject)
    assert not grants.matches_subject(receipt, {**subject, "command": "git diff"})
    with pytest.raises(ValueError, match="Invalid authorization scope"):
        grants.build_operation_grants(
            "bash", args, {}, mode="allow_with_scope", scope="subcommands"
        )
    assert command_identity.literal_shell_words("git status", "bash") is None
    assert _literal_programs(subject["command"], str(tmp_path)) == []


@pytest.mark.asyncio
@pytest.mark.parametrize("remember", [False, True])
@pytest.mark.parametrize("kind", ["file", "url"])
async def test_runtime_default_file_and_url_scopes(tmp_path, remember, kind):
    if kind == "url" and remember:
        pytest.importorskip("tld")  # This case exercises the available domain scope.
    cards, registry = [], RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve(
            "s",
            event["request_id"],
            PermissionConfirmResponse(
                approved=len(cards) == 1,
                auto_confirm=remember if len(cards) == 1 else False,
                persist_allow=False,
            ),
        )

    target, obj = make_execution(tmp_path, emit, registry)

    def persist_ok(*_args, **_kwargs):
        return True

    obj.persist = persist_ok
    if kind == "file":
        subject = {"kind": "file", "accesses": [(str(target), "read")]}
        sibling = {"kind": "file", "accesses": [(str(tmp_path / "B.txt"), "read")]}
        outside = {"kind": "file", "accesses": [(str(target), "write")]}
    else:
        obj.engine().update_config(
            {**obj.engine().config, "net_guard": {"enabled": True, "defaults": "ask"}}
        )
        subject = {"kind": "url", "url": "https://www.example.com/a"}
        sibling = {"kind": "url", "url": "https://api.example.com/b"}
        outside = {"kind": "url", "url": "https://example.org/a"}
    assert await obj.check_resource(123, subject)
    assert await obj.check_resource(123, subject)
    covers_sibling = kind == "file" or remember
    assert await obj.check_resource(123, sibling) is covers_sibling
    assert not await obj.check_resource(123, outside)
    assert len(cards) == (2 if covers_sibling else 3)
    await obj.close()


@pytest.mark.parametrize("action", ["read", "write", "exec", "delete"])
@pytest.mark.parametrize("at_root", [False, True])
@pytest.mark.parametrize("choice", ["default", "allow", "exact"])
def test_file_receipt_default_scope_and_action(tmp_path, action, at_root, choice):
    # Construct identities only. These checks do not access the drive root.
    parent = Path(tmp_path.anchor) if at_root else tmp_path
    target = str(parent / "original")
    subject = {"kind": "file", "accesses": [(target, action)]}
    answer = normalize_confirmation_scope(
        PermissionConfirmResponse(
            approved=True,
            authorization_mode="allow" if choice == "allow" else None,
            authorization_scope="exact" if choice == "exact" else None,
        ),
        subject,
    )
    use_parent = action != "delete" and choice == "default"
    assert answer.authorization_scope == ("parent" if use_parent else "exact")
    assert answer.authorization_mode == ("allow_with_scope" if use_parent else "allow")
    grant = resource_grant(subject, answer)
    assert resource_grant_matches(grant, subject)
    assert (
        resource_grant_matches(
            grant, {"kind": "file", "accesses": [(str(parent / "child" / "other"), action)]}
        )
        is use_parent
    )
    other_action = "write" if action == "read" else "read"
    assert not resource_grant_matches(grant, {"kind": "file", "accesses": [(target, other_action)]})


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scope",
    ["exact", pytest.param("subcommands", marks=NEEDS_BASH_PARSER)],
)
@pytest.mark.parametrize("has_accesses", [False, True])
async def test_command_handoff_keeps_only_runtime_file_grants(tmp_path, scope, has_accesses):
    from agent_shield.tool_permission.runtime.grants import (
        build_operation_grants,
        operation_subject,
    )

    target, execution = make_execution(
        tmp_path,
        AsyncMock(side_effect=AssertionError("Already approved")),
        RuntimeApprovalRequests(),
    )
    args = {
        "command": "echo approved && echo again",
        "shell_type": "bash",
        "workdir": str(tmp_path),
    }
    operation = operation_subject("bash", args, {})
    grants = build_operation_grants("bash", args, {}, mode="allow_with_scope", scope=scope)
    assert grants
    execution.seed_approved_operation(
        {
            "operation": operation,
            "grants": grants,
            "accesses": [(str(target), "read")] if has_accesses else [],
        }
    )
    assert len(getattr(execution.context, "_grants")) == int(has_accesses)
    assert execution.approved_programs
    assert execution.approved_programs_version == execution.context.policy_version
    if has_accesses:
        assert await execution.check_access(123, str(target), 1)
    await execution.close()


def test_unknown_preapproved_file_action_is_still_rejected(tmp_path):
    target, execution = make_execution(tmp_path, AsyncMock(), RuntimeApprovalRequests())
    with pytest.raises(ValueError, match="Invalid pre-approved file operation"):
        execution.seed_approved_accesses([(str(target), "unknown_action")])


@pytest.mark.asyncio
@NEEDS_BASH_PARSER
async def test_native_literal_argv_does_not_get_shell_path_rewriting(tmp_path):
    import shlex
    import sys

    from agent_shield.tool_permission.runtime.grants import build_operation_grants

    args = {
        "command": shlex.join([Path(sys.executable).as_posix(), "--data", r"C:\literal\data"]),
        "workdir": str(tmp_path),
        "shell_type": "bash",
    }
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "tools": {"bash": "ask"},
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "allow", "write": "allow", "exec": "allow"},
        },
    }
    config["approval_overrides"] = build_operation_grants("bash", args, config)
    engine = PermissionEngine(config)
    base = {"kind": "program", "exe": str(Path(sys.executable).resolve()), "cwd": str(tmp_path)}
    original = {**base, "argv": ["--data", "C:/literal/data"]}
    changed = {**base, "argv": ["--data", r"C:\literal\data"]}
    assert (
        await evaluate_resource(engine, original, source_tool="bash", source_shell="bash")
    ).is_allowed
    assert (
        await evaluate_resource(engine, changed, source_tool="bash", source_shell="bash")
    ).needs_approval


@pytest.mark.asyncio
@pytest.mark.parametrize("raises", [False, True])
async def test_host_callback_retains_native_binding_and_cleans_up(tmp_path, raises):
    import asyncio
    import sys

    from agent_shield.tool_permission.runtime.command_identity import bound_native_identity
    from agent_shield.tool_permission.runtime.grants import operation_subject
    from agent_shield.tool_permission.runtime.models import (
        PermissionLevel,
        PermissionResult,
    )

    _target, execution = make_execution(tmp_path, AsyncMock(), RuntimeApprovalRequests())
    execution.source_tool, execution.source_shell = "bash", "bash"
    subject = {
        "kind": "program",
        "exe": str(Path(sys.executable).resolve()),
        "cwd": str(tmp_path),
        "argv": ["--data", r"C:\literal\data"],
    }
    args = program_tool_args(subject, "bash", "bash")

    async def decision(_subject, _local):
        await asyncio.sleep(0)
        identity = operation_subject("bash", args, {})["command_identity"]
        assert identity["argv"][-1] == ["literal", r"C:\literal\data"]
        if raises:
            raise RuntimeError("host unavailable")
        return PermissionResult(PermissionLevel.ALLOW)

    execution.program_decision = decision
    if raises:
        with pytest.raises(RuntimeError, match="host unavailable"):
            await getattr(execution, "_host_program_decision")(
                subject, PermissionResult(PermissionLevel.UNDETERMINED)
            )
    else:
        assert (
            await getattr(execution, "_host_program_decision")(
                subject, PermissionResult(PermissionLevel.UNDETERMINED)
            )
        ).is_allowed
    assert bound_native_identity("bash", args) == (False, None)
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["file", "url"])
@pytest.mark.parametrize("source", ["config", "session"])
async def test_repeated_remembered_access_does_not_accumulate_grants(tmp_path, kind, source):
    target, execution = make_execution(
        tmp_path,
        AsyncMock(side_effect=AssertionError("Already remembered")),
        RuntimeApprovalRequests(),
    )
    subject = (
        {"kind": "file", "accesses": [(str(target), "read")]}
        if kind == "file"
        else {"kind": "url", "url": "https://site.test/a"}
    )
    grant = resource_grant(
        subject, PermissionConfirmResponse(approved=True, authorization_mode="allow")
    )
    config = deepcopy(execution.engine().config)
    config["net_guard"] = {"enabled": True, "defaults": "ask"}
    if source == "config":
        config["approval_overrides"] = [grant]
    execution.engine().update_config(config)
    if source == "session":
        execution.session_grants = SessionResourceGrants()
        _engine, version = getattr(execution, "_policy")()
        execution.session_grants.remember(grant, version)

    for _ in range(5):
        assert await execution.check_resource(123, subject)
    assert len(getattr(execution.context, "_grants")) == (2 if kind == "url" else 1)
    if kind == "url":
        assert await execution.check_resource(123, {"kind": "domain", "hostname": "site.test"})
    await execution.close()


@pytest.mark.asyncio
@NEEDS_TLD
async def test_remembered_domain_url_derives_only_current_host_dns(tmp_path):
    cards, registry = [], RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=False))

    _target, obj = make_execution(tmp_path, emit, registry)
    grant = resource_grant(
        {"kind": "url", "url": "https://www.example.com/a"},
        PermissionConfirmResponse(
            approved=True, authorization_mode="allow_with_scope", authorization_scope="domain"
        ),
    )
    obj.engine().update_config(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "approval_overrides": [grant],
            "net_guard": {"enabled": True, "defaults": "ask"},
        }
    )
    assert await obj.check_resource(123, {"kind": "url", "url": "https://api.example.com/b"})
    assert await obj.check_resource(123, {"kind": "domain", "hostname": "api.example.com"})
    assert not cards
    # Other DNS names still need an admitted URL in this execution.
    assert not await obj.check_resource(123, {"kind": "domain", "hostname": "unused.example.com"})
    assert not await obj.check_resource(
        123, {"kind": "endpoint", "address": "127.0.0.1", "port": 443, "protocol": "tcp"}
    )
    obj.engine().update_config(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "approval_overrides": [grant],
            "net_guard": {"enabled": True, "defaults": "ask", "urls": {"api.example.com": "deny"}},
        }
    )
    assert not await obj.check_resource(123, {"kind": "domain", "hostname": "api.example.com"})
    assert len(cards) == 2
    await obj.close()


@NEEDS_BASH_PARSER
def test_literal_commands_cover_user_rm_sequence(tmp_path):
    parsed = _literal_programs(
        'echo "temporary test file" > temp_test.txt && ls -la temp_test.txt && '
        'rm temp_test.txt && echo "---after rm---" && ls -la temp_test.txt 2>&1',
        str(tmp_path),
    )
    commands = []
    for argv, _cwd in parsed:
        commands.append(argv)
    assert commands == [
        ["echo", "temporary test file"],
        ["ls", "-la", "temp_test.txt"],
        ["rm", "temp_test.txt"],
        ["echo", "---after rm---"],
        ["ls", "-la", "temp_test.txt"],
    ]


@pytest.mark.parametrize(
    "command",
    [
        "rm $target",
        "rm *.txt",
        "rm $(cat file)",
        "rm `cat file`",
        "rm ~/*",
        "for f in a b; do rm $f; done",
        "f() { rm a; }; f",
        "PATH=/other rm a",
        "source runner.sh; rm a",
        "eval 'rm a'",
        "rm {a,b}",
        "echo test > $target",
        'cd "$target" && rm a',
        "cd && rm a",
        "cd - && rm a",
        "pushd sub; rm a; popd",
        "alias rm=other; rm a",
    ],
)
def test_dynamic_or_state_changing_commands_have_no_literal_child_grants(command, tmp_path):
    assert not _literal_programs(command, str(tmp_path))


@pytest.mark.parametrize(
    "command,expected",
    [
        ("cd sub && rm a", [("a", "sub")]),
        ("cd sub || rm a", [("a", ".")]),
        ("cd sub; rm a", [("a", "."), ("a", "sub")]),
        ("cd sub\nrm a", [("a", "."), ("a", "sub")]),
        ("cd sub && cd ../other && rm a", [("a", "other")]),
        ("cd sub || cd other; rm a", [("a", "."), ("a", "sub"), ("a", "other")]),
        ("(cd sub && rm a); rm b", [("a", "sub"), ("b", ".")]),
        ("{ cd sub && rm a; } && rm b", [("a", "sub"), ("b", "sub")]),
        ("cd sub | cat; rm a", [("a", ".")]),
        ("(cd sub && rm a) | cat; rm b", [("a", "sub"), ("b", ".")]),
        ("cd sub & rm a", [("a", ".")]),
        ("cd sub && rm a & rm b", [("a", "sub"), ("b", ".")]),
        ('cd -- "sub dir" && rm a', [("a", "sub dir")]),
        ("cd -P sub && rm a", [("a", "sub")]),
        ("cd sub && # next\nrm a # done", [("a", "sub")]),
        ("cd sub >out && rm a", [("a", "sub")]),
        ("cd sub && >a && rm a", [("a", "sub")]),
        (">a; rm a", [("a", ".")]),
    ],
)
@NEEDS_BASH_PARSER
def test_literal_program_directories_follow_shell_control_flow(tmp_path, command, expected):
    actual = {
        (argv[-1], str(Path(directory).relative_to(tmp_path)))
        for argv, directory in _literal_programs(command, str(tmp_path))
        if argv[0] == "rm"
    }
    assert actual == {(arg, str(Path(directory))) for arg, directory in expected}


@NEEDS_BASH_PARSER
def test_cd_binds_relative_executable_and_msys_drive_path(tmp_path):
    sub = tmp_path / "中文目录"
    sub.mkdir()
    (sub / "local-rm.exe").touch()  # Resolve only; this unit test never launches it.
    target = sub.as_posix()
    directories = [target]
    if len(target) > 1 and target[1] == ":":
        directories.append("/" + target[0].lower() + target[2:])
    for directory in directories:
        programs = approved_programs(
            {
                "kind": "command",
                "command": f'cd "{directory}" && ./local-rm.exe a',
                "cwd": str(tmp_path),
                "shell_type": "bash",
            }
        )
        assert {
            "kind": "program",
            "exe": str(sub / "local-rm.exe"),
            "argv": ["a"],
            "cwd": str(sub),
        } in programs


@NEEDS_BASH_PARSER
def test_literal_inline_shell_keeps_its_child_directory_local(tmp_path):
    command = """bash -c 'cd sub && rm a' && rm b"""
    programs = approved_programs(
        {"kind": "command", "command": command, "cwd": str(tmp_path), "shell_type": "bash"}
    )
    rm = {(tuple(item["argv"]), item["cwd"]) for item in programs if Path(item["exe"]).stem == "rm"}
    assert rm == {(("a",), str(tmp_path / "sub")), (("b",), str(tmp_path))}
    nested_forks = [
        item for item in programs if Path(item["exe"]).stem == "bash" and item["argv"][0] == "-c"
    ]
    assert {item["cwd"] for item in nested_forks} == {str(tmp_path), str(tmp_path / "sub")}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exec_decision,command_decision,expected",
    [
        ("allow", "ask", "allow"),
        ("allow", "deny", "deny"),
        ("ask", "ask", "ask"),
        ("deny", "ask", "deny"),
    ],
)
async def test_confirmed_command_preserves_exec_check_and_explicit_deny(
    tmp_path, exec_decision, command_decision, expected
):
    exe = tmp_path / "rm.exe"
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "tools": {"bash": command_decision},
            "file_guard": {"enabled": True, "paths": [{"path": str(exe), "exec": exec_decision}]},
        },
        workspace_root=tmp_path / "workspace",
    )
    subject = {"kind": "program", "exe": str(exe), "argv": ["a"], "cwd": str(tmp_path)}
    assert (
        await evaluate_resource(engine, subject, command_approved=True)
    ).permission.value == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("with_cd", [False, True])
@NEEDS_BASH_PARSER
async def test_seeded_program_binds_executable_args_cwd_and_policy(tmp_path, with_cd):
    command = "cd sub && rm a.txt" if with_cd else "rm a.txt"
    programs = approved_programs(
        {"kind": "command", "command": command, "cwd": str(tmp_path), "shell_type": "bash"}
    )
    rm = next(item for item in programs if Path(item["exe"]).stem == "rm")
    cards = []
    registry = RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=False))

    _target, execution = make_execution(tmp_path, emit, registry)
    config = {"enabled": True, "package_builtin_rules": False, "tools": {"bash": "ask"}}
    execution.engine().update_config(config)
    execution.seed_approved_operation(
        {
            "accesses": [],
            "operation": {
                "kind": "command",
                "command": command,
                "cwd": str(tmp_path),
                "shell_type": "bash",
            },
        }
    )
    assert await execution.check_resource(123, rm)
    for changed in [
        {**rm, "argv": ["b.txt"]},
        {**rm, "cwd": str(tmp_path / "other")},
        {**rm, "exe": str(tmp_path / "rm.exe")},
    ]:
        assert not await execution.check_resource(123, changed)
    assert len(cards) == 3
    execution.engine().update_config({**config, "tools": {"bash": "deny"}})
    assert not await execution.check_resource(123, rm)
    assert len(cards) == 3
    await execution.close()


@pytest.mark.asyncio
async def test_approved_url_reuses_exact_request_and_dns_but_not_path_ip_or_deny(tmp_path):
    cards = []
    registry = RuntimeApprovalRequests()

    async def emit(event):
        cards.append(event)
        registry.resolve("s", event["request_id"], PermissionConfirmResponse(approved=False))

    _target, execution = make_execution(tmp_path, emit, registry)
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "net_guard": {"enabled": True, "defaults": "ask"},
    }
    execution.engine().update_config(config)
    url = {"kind": "url", "url": "https://site.test/a"}
    execution.seed_approved_operation({"accesses": [], "operation": url})
    assert await execution.check_resource(123, url)
    assert await execution.check_resource(123, {"kind": "domain", "hostname": "site.test"})
    for subject in [
        {"kind": "url", "url": "https://site.test/b"},
        {"kind": "domain", "hostname": "other.test"},
        {"kind": "endpoint", "address": "127.0.0.1", "port": 443, "protocol": "tcp"},
    ]:
        assert not await execution.check_resource(123, subject)
    assert len(cards) == 3
    execution.engine().update_config(
        {**config, "net_guard": {"enabled": True, "defaults": "ask", "urls": {"site.test": "deny"}}}
    )
    assert not await execution.check_resource(123, url)
    assert not await execution.check_resource(123, {"kind": "domain", "hostname": "site.test"})
    assert len(cards) == 3
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "hostname,urls,default,expected",
    [
        ("WWW.TAOBAO.COM.", {"www.taobao.com": "deny"}, "allow", "deny"),
        ("api.taobao.com", {"*.taobao.com": "deny"}, "allow", "deny"),
        ("www.taobao.com", {"*.taobao.com": "allow", "www.taobao.com": "deny"}, "allow", "deny"),
        ("例子.测试", {"xn--fsqu00a.xn--0zwm56d": "deny"}, "allow", "deny"),
        ("site.test", {"https://site.test/private": "allow"}, "ask", "ask"),
        ("site.test", {"site.test:443": "allow"}, "deny", "deny"),
        ("site.test", {"site.test": "allow"}, "deny", "allow"),
        ("site.test", {"site.test": "ask"}, "deny", "ask"),
    ],
)
async def test_domain_uses_existing_netguard_without_url_or_ip_expansion(
    tmp_path, hostname, urls, default, expected
):
    config = {
        "enabled": True,
        "package_builtin_rules": False,
        "net_guard": {"enabled": True, "defaults": default, "urls": urls},
    }
    engine = PermissionEngine(config, workspace_root=tmp_path)
    before = deepcopy(engine.config)
    result = await evaluate_resource(engine, {"kind": "domain", "hostname": hostname})
    assert result.permission.value == expected
    assert engine.config == before


@pytest.mark.parametrize(
    "tools,expected",
    [
        (["source"], True),
        ([], False),
        ([None], False),
        (["one", "two"], False),
        ("source", False),
        (None, False),
    ],
)
def test_resource_matching_retains_source_format_validation(tools, expected):
    subject = {"kind": "domain", "hostname": "site.test"}
    grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
    grant["tools"] = tools
    assert resource_grant_matches(grant, subject) is expected


@pytest.mark.asyncio
async def test_domain_approval_does_not_authorize_other_resource_kinds_or_domains(tmp_path):
    subject = {"kind": "domain", "hostname": "site.test"}
    grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
    assert resource_grant_matches(grant, subject)
    for other in [
        {"kind": "domain", "hostname": "sub.site.test"},
        {"kind": "domain", "hostname": "other.test"},
        {"kind": "url", "url": "https://site.test/path"},
        {"kind": "endpoint", "address": "127.0.0.1", "port": 443, "protocol": "tcp"},
    ]:
        assert not resource_grant_matches(grant, other)


def test_empty_accesses_skip_snapshot_but_operation_still_refreshes(tmp_path):
    _, execution = make_execution(tmp_path, AsyncMock(), RuntimeApprovalRequests())
    policy = getattr(execution, "_policy")
    wrapped = Mock(wraps=policy)
    setattr(execution, "_policy", wrapped)
    execution.seed_approved_accesses([])
    wrapped.assert_not_called()
    operation = {"kind": "url", "url": "https://example.test/approved"}
    execution.seed_approved_operation({"operation": operation, "accesses": []})
    wrapped.assert_called_once()
    assert execution.context.matches(
        operation,
        execution_id=execution.context.execution_id,
        policy_version=execution.context.policy_version,
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("permanent", [False, True])
@pytest.mark.parametrize("outcome", ["failed", "not_visible", "visible"])
async def test_save_result_and_session_fallback(tmp_path, permanent, outcome):
    registry = RuntimeApprovalRequests()
    cards = []

    async def emit(event):
        cards.append(event)
        registry.resolve(
            "s",
            event["request_id"],
            PermissionConfirmResponse(approved=True, auto_confirm=True, persist_allow=permanent),
        )

    target, execution = make_execution(tmp_path, emit, registry)
    memory = SessionResourceGrants()
    execution.session_grants = memory

    def persist(_session, config, grant, **_kwargs):
        if outcome == "visible":
            updated = deepcopy(config)
            updated.setdefault("approval_overrides", []).append(grant)
            execution.engine().update_config(updated)
        return outcome != "failed"

    execution.persist = persist
    execution.notify = AsyncMock()
    assert await execution.check_access(123, str(target), 1)
    execution.notify.assert_awaited_once_with(
        {
            "session_id": "s",
            "execution_id": execution.context.execution_id,
            "tool_call_id": "call",
            "persisted": outcome != "failed",
            "scope": "permanent" if permanent else "session",
        }
    )
    assert memory.matches(
        {"kind": "file", "accesses": [(str(target), "read")]}, execution.context.policy_version
    ) is (outcome != "visible")
    # The execution-local grant never widens read to write.
    assert await execution.check_access(123, str(target), 2)
    assert len(cards) == 2
    await execution.close()

    # A subsequent execution must reuse either the refreshed snapshot or the
    # in-memory fallback; an explicit DENY still takes precedence over both.
    _, following = make_execution(tmp_path, emit, registry)
    following.engine = execution.engine
    following.session_grants = memory
    assert await following.check_access(123, str(target), 1)
    assert len(cards) == 2
    config = deepcopy(following.engine().config)
    config["file_guard"]["paths"][0]["read"] = "deny"
    following.engine().update_config(config)
    assert not await following.check_access(123, str(target), 1)
    assert len(cards) == 2
    await following.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("changed_during", ["persist", "notify"])
@pytest.mark.parametrize("change", ["deny", "unrelated"])
async def test_save_rechecks_policy_before_remembering(tmp_path, changed_during, change):
    registry = RuntimeApprovalRequests()

    async def emit(event):
        registry.resolve(
            "s", event["request_id"], PermissionConfirmResponse(approved=True, auto_confirm=True)
        )

    target, execution = make_execution(tmp_path, emit, registry)
    memory = SessionResourceGrants()
    execution.session_grants = memory

    def change_policy(grant=None):
        config = deepcopy(execution.engine().config)
        if change == "deny":
            config["file_guard"]["paths"][0]["read"] = "deny"
        else:
            config["file_guard"]["paths"].append({"path": str(tmp_path / "other"), "read": "deny"})
        if grant is not None:
            config.setdefault("approval_overrides", []).append(grant)
        execution.engine().update_config(config)

    def persist(_session, _config, grant, **_kwargs):
        if changed_during == "persist":
            change_policy(grant)
        return True

    async def notify(_event):
        if changed_during == "notify":
            change_policy()

    execution.persist, execution.notify = persist, notify
    assert not await execution.check_access(123, str(target), 1)
    assert not memory.grants
    assert not execution.context.matches(
        {"kind": "file", "accesses": [(str(target), "read")]},
        execution_id=execution.context.execution_id,
        policy_version=execution.context.policy_version,
    )
    await execution.close()


@pytest.mark.asyncio
async def test_preapproved_batch_subset_and_policy_revoke(tmp_path):
    registry = RuntimeApprovalRequests()
    target, execution = make_execution(
        tmp_path, AsyncMock(side_effect=AssertionError("No card expected")), registry
    )
    execution.seed_approved_accesses([(str(target), "read"), (str(tmp_path / "other"), "read")])
    assert await execution.check_access(123, str(target), 1)
    config = deepcopy(execution.engine().config)
    config["file_guard"]["paths"][0]["read"] = "deny"
    execution.engine().update_config(config)
    assert not await execution.check_access(123, str(target), 1)
    await execution.close()


@pytest.mark.asyncio
async def test_policy_change_during_save_notification_rejects(tmp_path):
    registry = RuntimeApprovalRequests()

    async def emit(event):
        registry.resolve(
            "s", event["request_id"], PermissionConfirmResponse(approved=True, auto_confirm=True)
        )

    target, execution = make_execution(tmp_path, emit, registry)

    def persist_rejected(*_args, **_kwargs):
        return False

    execution.persist = persist_rejected

    async def notify(_event):
        execution.context.finish()

    execution.notify = notify
    assert not await execution.check_access(123, str(target), 1)
    await execution.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("checks", [True, False])
async def test_full_access_and_url_does_not_authorize_endpoint(checks):
    engine = PermissionEngine(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "net_guard": {
                "enabled": True,
                "defaults": "ask",
                "urls": {"https://127.0.0.1/a": "allow"},
            },
        }
    )
    engine.set_permission_checks_active(lambda: checks)
    endpoint = {"kind": "endpoint", "address": "127.0.0.1", "port": 443, "protocol": "tcp"}
    assert (await evaluate_resource(engine, endpoint)).needs_approval is checks
    url = {"kind": "url", "url": "https://127.0.0.1/a"}
    grant = resource_grant(url, PermissionConfirmResponse(approved=True))
    assert not resource_grant_matches(grant, endpoint)


def test_parent_scope_preserves_action(tmp_path):
    subject = {"kind": "file", "accesses": [(str(tmp_path / "a"), "read")]}
    grant = resource_grant(
        subject,
        PermissionConfirmResponse(
            approved=True, authorization_mode="allow_with_scope", authorization_scope="parent"
        ),
    )
    assert resource_grant_matches(
        grant, {"kind": "file", "accesses": [(str(tmp_path / "b"), "read")]}
    )
    assert not resource_grant_matches(
        grant, {"kind": "file", "accesses": [(str(tmp_path / "b"), "write")]}
    )


@pytest.mark.asyncio
async def test_guard_control_files_follow_existing_file_policy(tmp_path):
    target, execution = make_execution(
        tmp_path, AsyncMock(side_effect=AssertionError("No ASK")), RuntimeApprovalRequests()
    )
    execution.engine().update_config({"enabled": False})
    assert await execution.check_access(123, str(execution.dll_source), 2)
    assert await execution.check_access(123, str(target), 2)
    execution.engine().update_config(
        {
            "enabled": True,
            "package_builtin_rules": False,
            "file_guard": {
                "enabled": True,
                "paths": [{"path": str(execution.dll_source), "write": "deny"}],
            },
        }
    )
    assert not await execution.check_access(123, str(execution.dll_source), 2)
    await execution.close()
