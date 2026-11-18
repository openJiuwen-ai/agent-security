# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""转发类 meta-tool 展开：外层信封按内层真实调用一并判定（issue jiuwenswarm#6499）。

未展开时的绕过链：``invoke_tool`` 不在 ``tools`` 配置 → ``defaults`` 放行 →
内层命令零评估执行。展开后：外层照常判定，命中注册转发器时对内层
``(tool_name, tool_args)`` 递归判定并合并取最严。
"""

from __future__ import annotations

import asyncio

import pytest

from agent_shield.tool_permission import (
    PermissionLevel as L,
)
from agent_shield.tool_permission import (
    register_meta_tool,
    registered_meta_tools,
    resolve_meta_tool_expansion,
    unregister_meta_tool,
)
from agent_shield.tool_permission.manager import new_permission_manager

INVOKE_TOOL = "invoke_tool"

# issue #6499 的四条 PowerShell 混淆载荷（原样取自复现步骤）。
ISSUE_PAYLOADS = [
    '[ScriptBlock]::Create("Get-Date")',
    "& (Get-Command notepad)",
    "powershell.exe -EncodedCommand aABlAGwAbABvAA==",
    'iex "Get-Process"',
]


def _forward(target: str, args: dict) -> dict:
    """构造 invoke_tool 外层参数（转发形态）。"""
    return {"tool_name": target, "arguments": args}


def _extract(tool_args):
    name = tool_args.get("tool_name")
    args = tool_args.get("arguments")
    if not isinstance(name, str) or not name.strip() or not isinstance(args, dict):
        return None
    return name, args


@pytest.fixture(autouse=True)
def _invoke_tool_registered():
    register_meta_tool(INVOKE_TOOL, _extract)
    yield
    unregister_meta_tool(INVOKE_TOOL)


def _check(config: dict, tool: str, args: dict):
    manager = new_permission_manager()
    return asyncio.run(manager.check_permission(tool, args, config=config))


def _base_config(**extra) -> dict:
    # defaults '*' allow 复现生产 config.yaml：invoke_tool 不在 tools 列表，
    # 外层默认放行——这正是绕过链的成因。
    return {
        "package_builtin_rules": False,
        "defaults": {"*": "allow"},
        **extra,
    }


# ---------------------------------------------------------------------------
# 注册表契约
# ---------------------------------------------------------------------------


def test_register_rejects_invalid_input():
    with pytest.raises(ValueError):
        register_meta_tool("", _extract)
    with pytest.raises(TypeError):
        register_meta_tool("bad_forwarder", None)


def test_extractor_garbage_raises_not_silently_abstains():
    register_meta_tool("bad_forwarder", lambda args: "garbage")
    try:
        with pytest.raises(TypeError):
            resolve_meta_tool_expansion("bad_forwarder", {})
    finally:
        unregister_meta_tool("bad_forwarder")


def test_register_is_idempotent():
    register_meta_tool(INVOKE_TOOL, _extract)
    register_meta_tool(INVOKE_TOOL, _extract)
    assert INVOKE_TOOL in registered_meta_tools()
    expansion = resolve_meta_tool_expansion(
        INVOKE_TOOL, _forward("bash", {"command": "dir"})
    )
    assert expansion == ("bash", {"command": "dir"})


def test_extractor_abstains_on_malformed_args():
    assert resolve_meta_tool_expansion(INVOKE_TOOL, {}) is None
    assert resolve_meta_tool_expansion(INVOKE_TOOL, {"tool_name": "bash"}) is None
    assert resolve_meta_tool_expansion(INVOKE_TOOL, {"arguments": {}}) is None
    assert resolve_meta_tool_expansion("bash", {"command": "dir"}) is None


# ---------------------------------------------------------------------------
# 判定展开（issue 场景）
# ---------------------------------------------------------------------------


def test_unregistered_forwarder_keeps_envelope_only_decision():
    # 回归基线：未注册时引擎行为与历史完全一致——外层走 defaults 放行。
    unregister_meta_tool(INVOKE_TOOL)
    config = _base_config(tools={"create_terminal": "ask"})
    result = _check(
        config, INVOKE_TOOL, _forward("create_terminal", {"command": ISSUE_PAYLOADS[2]})
    )
    assert result.permission is L.ALLOW


@pytest.mark.parametrize("command", ISSUE_PAYLOADS)
def test_forwarded_issue_payloads_are_not_allowed(command):
    # 先红后绿的“红”：展开缺失时本用例返回 ALLOW（绕过），展开后内层
    # create_terminal 按 ask/更严判定，合并结果不再是 ALLOW。
    config = _base_config(tools={"create_terminal": "ask"})
    result = _check(
        config, INVOKE_TOOL, _forward("create_terminal", {"command": command})
    )
    assert result.permission in (L.ASK, L.DENY)


def test_forwarded_benign_command_still_allowed():
    config = _base_config(tools={"bash": "allow"})
    result = _check(config, INVOKE_TOOL, _forward("bash", {"command": "dir"}))
    assert result.permission is L.ALLOW


def test_forwarded_malformed_args_abstain_to_envelope_decision():
    config = _base_config(tools={"create_terminal": "ask"})
    result = _check(config, INVOKE_TOOL, {"tool_name": "", "arguments": {}})
    assert result.permission is L.ALLOW


def test_outer_explicit_deny_still_wins():
    # 宿主对转发器本身的显式规则不被展开稀释。
    config = _base_config(tools={"invoke_tool": "deny", "bash": "allow"})
    result = _check(config, INVOKE_TOOL, _forward("bash", {"command": "echo hi"}))
    assert result.permission is L.DENY


def test_forwarded_call_matches_remembered_approval():
    # 直接调用批准过的命令，转发调用同样识别——展开让 remembered approval
    # 在直接/转发两条路径上判定一致，不会每转一次问一次。
    config = _base_config(
        tools={"bash": "ask"},
        approval_overrides=[
            {"id": "ok", "tools": ["bash"], "pattern": "echo audit", "action": "allow"}
        ],
    )
    result = _check(config, INVOKE_TOOL, _forward("bash", {"command": "echo audit"}))
    assert result.permission is L.ALLOW
    assert "approval_overrides" in (result.matched_rule or "")


def test_nested_forwarding_stops_at_depth_cap():
    # 三层转发：封顶处外层仍是注册转发器——不按信封静默放行（外层 defaults
    # 会重新打开本修复要堵的绕过），并入不可静默的 ASK 交用户裁决。生产宿主
    # 功能上只允许一层转发，此处钉住深层嵌套的 fail-closed 语义。
    config = _base_config(tools={"create_terminal": "ask"})
    innermost = _forward("create_terminal", {"command": ISSUE_PAYLOADS[0]})
    result = _check(
        config, INVOKE_TOOL, _forward(INVOKE_TOOL, _forward(INVOKE_TOOL, innermost))
    )
    assert result.permission is L.ASK
    assert result.matched_rule == "meta_tool_depth_cap"


def test_two_level_forwarding_judges_reached_target():
    # 两层转发：深度 0/1 两次展开到达 create_terminal；最内层非转发器，
    # 按完整判定（ask）——封顶只约束转发器嵌套，不影响普通内层工具。
    config = _base_config(tools={"create_terminal": "ask"})
    inner = _forward("create_terminal", {"command": ISSUE_PAYLOADS[0]})
    result = _check(config, INVOKE_TOOL, _forward(INVOKE_TOOL, inner))
    assert result.permission in (L.ASK, L.DENY)


def test_disabled_engine_keeps_allow_semantics():
    config = _base_config(enabled=False)
    result = _check(
        config, INVOKE_TOOL, _forward("create_terminal", {"command": ISSUE_PAYLOADS[2]})
    )
    assert result.permission is L.ALLOW
    assert "disabled" in (result.reason or "")
