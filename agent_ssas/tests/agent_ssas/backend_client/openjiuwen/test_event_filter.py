# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""事件过滤模块单元测试 (level1)。"""

from unittest.mock import MagicMock

import pytest
from openjiuwen.core.single_agent.rail.base import AgentCallbackEvent
from openjiuwen.harness.rails.security.base_security_rail import SecurityReject

from agent_ssas.backend_client.openjiuwen.event_filter import EventFilter


def _make_security_ctx(event, extra=None, tool_name="", tool_call_id=""):
    """构造测试用 mock security_ctx。"""
    security_ctx = MagicMock()
    security_ctx.callback_ctx = MagicMock()
    security_ctx.callback_ctx.extra = extra or {}
    security_ctx.event = event
    security_ctx.tool_name = tool_name
    security_ctx.tool_call_id = tool_call_id
    return security_ctx


class TestEventFilter:
    """验证事件过滤模块的过滤逻辑。"""

    @staticmethod
    @pytest.mark.level1
    def test_base_event_passes_through():
        """生命周期事件全通过(返回原始 dict,不修改)。"""
        security_ctx = _make_security_ctx(AgentCallbackEvent.BEFORE_INVOKE)
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "invoke_start", "event_class": "lifecycle"},
            "payload": {},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["common"]["event_type"] == "invoke_start"
        assert result["common"]["event_class"] == "lifecycle"

    @staticmethod
    @pytest.mark.level1
    def test_no_risk_when_skip_tool_false():
        """ctx.extra['_skip_tool'] 为 False 时,BEFORE_TOOL_CALL 作为生命周期事件通过。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={"_skip_tool": False},
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["common"]["event_type"] == "tool_input"
        assert result["common"]["event_class"] == "lifecycle"

    @staticmethod
    @pytest.mark.level1
    def test_risk_detected_when_skip_tool_true():
        """ctx.extra['_skip_tool'] 为 True 时,生成安全检测事件字段并修改 event_type 和 event_class。

        _interrupt_decision 缺失时保守回退:medium / unknown。
        """
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={"_skip_tool": True},
            tool_name="bash",
            tool_call_id="call-001",
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {"tool_name": "bash"},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["common"]["event_type"] == "permission_interrupt_tool"
        assert result["common"]["event_class"] == "security"
        assert result["payload"]["risk_source"] == "PermissionInterruptRail"
        assert result["payload"]["risk_type"] == "tool_permission_denied"
        # _interrupt_decision 缺失:保守回退 medium / unknown
        assert result["payload"]["risk_level"] == "medium"
        assert result["payload"]["deny_reason"] == "unknown"
        assert result["payload"]["decision"] == "reject"
        assert "evidence" in result["payload"]
        assert result["payload"]["evidence"]["tool_name"] == "bash"

    @staticmethod
    @pytest.mark.level1
    def test_policy_deny_scene_returns_medium():
        """策略 deny 场景:_interrupt_decision 的 tool_result 以 [PERMISSION_DENIED] 开头 → medium / policy_deny。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={
                "_skip_tool": True,
                "_interrupt_decision": SecurityReject(
                    result="[PERMISSION_DENIED] Operation not allowed"
                ),
            },
            tool_name="bash",
            tool_call_id="call-001",
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {"tool_name": "bash"},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["payload"]["risk_level"] == "medium"
        assert result["payload"]["deny_reason"] == "policy_deny"
        assert result["payload"]["risk_type"] == "tool_permission_denied"
        assert result["payload"]["decision"] == "reject"

    @staticmethod
    @pytest.mark.level1
    def test_user_reject_scene_returns_low():
        """ask 模式用户拒绝场景:tool_result 以 [PERMISSION_REJECTED] 开头 → low / user_reject。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={
                "_skip_tool": True,
                "_interrupt_decision": SecurityReject(
                    result="[PERMISSION_REJECTED] User rejected the request."
                ),
            },
            tool_name="read_file",
            tool_call_id="call-002",
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {"tool_name": "read_file"},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["payload"]["risk_level"] == "low"
        assert result["payload"]["deny_reason"] == "user_reject"

    @staticmethod
    @pytest.mark.level1
    def test_user_reject_scene_with_feedback_text_returns_low():
        """ask 模式用户拒绝场景:tool_result 为用户反馈文本(无固定前缀)→ low / user_reject。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={
                "_skip_tool": True,
                "_interrupt_decision": SecurityReject(result="不要删除这个文件"),
            },
            tool_name="bash",
            tool_call_id="call-003",
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {"tool_name": "bash"},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["payload"]["risk_level"] == "low"
        assert result["payload"]["deny_reason"] == "user_reject"

    @staticmethod
    @pytest.mark.level1
    def test_unreadable_decision_falls_back_to_medium():
        """_interrupt_decision 存在但无法读取 tool_result 时,保守回退 medium / unknown。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={"_skip_tool": True, "_interrupt_decision": object()},
            tool_name="bash",
            tool_call_id="call-004",
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {"tool_name": "bash"},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["payload"]["risk_level"] == "medium"
        assert result["payload"]["deny_reason"] == "unknown"

    @staticmethod
    @pytest.mark.level1
    def test_no_observation_for_non_tool_events():
        """非 BEFORE_TOOL_CALL 事件不检查 _skip_tool,直接通过。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_MODEL_CALL,
            extra={"_skip_tool": True},
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "llm_input", "event_class": "lifecycle"},
            "payload": {},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["common"]["event_type"] == "llm_input"
        assert result["common"]["event_class"] == "lifecycle"

    @staticmethod
    @pytest.mark.level1
    def test_no_skip_tool_key_defaults_false():
        """ctx.extra 中没有 _skip_tool 键时,默认为 False。"""
        security_ctx = _make_security_ctx(
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            extra={},
        )
        event_filter = EventFilter()

        original_dict = {
            "common": {"event_type": "tool_input", "event_class": "lifecycle"},
            "payload": {},
            "metadata": {},
        }
        result = event_filter.filter_event(original_dict, security_ctx)

        assert result is not None
        assert result["common"]["event_type"] == "tool_input"
        assert result["common"]["event_class"] == "lifecycle"
