# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""数据预处理模块单元测试。

验证 parse tool_input 事件、parse permission_interrupt_tool 安全检测事件、
解析后 UnifiedEvent 字段正确性、自动生成 session_start 节点。
"""

from __future__ import annotations

import pytest

from agent_ssas.core.framework.config.settings import AgentSSASConfig
from agent_ssas.core.framework.data_preprocessor import DataPreprocessor
from agent_ssas.core.framework.data_preprocessor.agent_preprocessor import (
    AgentSSASPreprocessor,
    _MAX_CACHED_TRACES,
)


class TestDataPreprocessor:
    """数据预处理模块。"""

    @staticmethod
    def _make_tool_input_raw_event() -> dict:
        """构造 tool_input 生命周期事件 raw_event。"""
        return {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "tool_input",
                "event_class": "lifecycle",
                "timestamp": 1715000000.0,
                "interaction_seq": 0,
                "session_id": "test-session",
                "conversation_id": "test-session",
                "agent_id": "test-agent",
                "trace_id": "test-trace",
                "context_id": "test-ctx",
                "llm_call_seq": -1,
                "tool_call_seq": 0,
                "subsession_id": "",
                "tool_call_id": "call-001",
            },
            "payload": {
                "tool_name": "bash",
                "tool_call_id": "call-001",
                "content": {"tool_args": {"command": "ls"}},
            },
            "metadata": {},
        }

    @staticmethod
    def _make_permission_interrupt_raw_event() -> dict:
        """构造 permission_interrupt_tool 安全检测事件 raw_event。"""
        return {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "permission_interrupt_tool",
                "event_class": "security",
                "timestamp": 1715000000.0,
                "interaction_seq": 0,
                "session_id": "test-session",
                "conversation_id": "test-session",
                "agent_id": "test-agent",
                "trace_id": "test-trace",
                "context_id": "test-ctx",
                "llm_call_seq": -1,
                "tool_call_seq": 0,
                "subsession_id": "",
                "tool_call_id": "call-001",
            },
            "payload": {
                "tool_name": "bash",
                "tool_call_id": "call-001",
                "risk_source": "PermissionInterruptRail",
                "risk_type": "tool_permission_denied",
                "risk_level": "medium",
                "deny_reason": "policy_deny",
                "decision": "reject",
                "evidence": {"reason": "denied"},
            },
            "metadata": {},
        }

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_parse_tool_input_event() -> None:
        """验证 tool_input 事件解析为 UnifiedEvent,字段正确。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        raw_event = TestDataPreprocessor._make_tool_input_raw_event()
        events = await preprocessor.parse(raw_event)
        # 最后一个是基础事件,前面是派生事件(session_start, user_input)
        unified = events[-1]
        node = unified.event_node
        assert node.event_type == "tool_input"
        assert node.event_class == "lifecycle"
        assert node.source == "AgentSSASSecurityRail"
        assert node.session_id == "test-session"
        assert node.interaction_seq == 0
        assert node.agent_id == "test-agent"
        assert node.action_name == "bash"
        assert node.is_risk_event is False
        assert node.node_type == "tool_call"
        assert node.tool_call_seq == 0
        assert node.tool_call_id == "call-001"
        assert unified.to_event_desc()["aux_ids"]["tool_call_id"] == "call-001"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_parse_permission_interrupt_event() -> None:
        """验证安全检测事件被正确标记为 is_risk_event=True。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        raw_event = TestDataPreprocessor._make_permission_interrupt_raw_event()
        events = await preprocessor.parse(raw_event)
        unified = events[-1]
        node = unified.event_node
        assert node.is_risk_event is True
        assert node.event_class == "security"
        assert node.risk_source == "PermissionInterruptRail"
        assert node.risk_type == "tool_permission_denied"
        assert node.risk_level == "medium"
        # deny_reason 顶层字段透传(与 risk_assessment 解耦)
        assert node.deny_reason == "policy_deny"
        assert unified.to_event_desc()["event_node"]["deny_reason"] == "policy_deny"
        # risk_assessment 包含 decision 和 evidence
        assert node.risk_assessment is not None
        assert node.risk_assessment["decision"] == "reject"
        assert node.risk_assessment["evidence"] == {"reason": "denied"}
        # 序列化输出携带 risk_assessment 与 tool_call_id(报告链路取值依据)
        desc = unified.to_event_desc()
        assert desc["event_node"]["risk_assessment"]["decision"] == "reject"
        assert desc["event_node"]["tool_call_id"] == "call-001"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_interaction_input_backfilled_from_invoke_start_cache() -> None:
        """验证同交互后续事件经会话级缓存回填 interaction_input。

        invoke_start 事件的 query 写入 (session_id, interaction_seq) 缓存,
        permission_interrupt_tool 事件回查缓存取回用户 query,
        使报告链路在仅携带当前事件节点时仍能取到交互输入。
        """
        preprocessor = DataPreprocessor(AgentSSASConfig())
        # 1. invoke_start:query 写入缓存
        invoke_event = {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "invoke_start",
                "event_class": "lifecycle",
                "timestamp": 1715000000.0,
                "interaction_seq": 0,
                "session_id": "test-session",
                "conversation_id": "test-session",
                "agent_id": "test-agent",
                "trace_id": "test-trace",
                "context_id": "test-ctx",
                "llm_call_seq": -1,
                "tool_call_seq": -1,
                "subsession_id": "",
                "tool_call_id": "",
            },
            "payload": {"content": {"query": "帮我删除日志文件"}},
            "metadata": {},
        }
        events = await preprocessor.parse(invoke_event)
        invoke_node = events[-1].event_node
        assert invoke_node.interaction_input == "帮我删除日志文件"

        # 2. 同交互 permission_interrupt_tool:回查缓存回填 query
        raw_event = TestDataPreprocessor._make_permission_interrupt_raw_event()
        events = await preprocessor.parse(raw_event)
        node = events[-1].event_node
        assert node.interaction_input == "帮我删除日志文件"
        # 序列化输出携带 interaction_input(ocsf 构建 interactions[0].input 依据)
        assert events[-1].to_event_desc()["event_node"]["interaction_input"] == (
            "帮我删除日志文件"
        )

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_interaction_input_empty_when_cache_miss() -> None:
        """验证缓存未命中(未先上报 invoke_start)时 interaction_input 为空串。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        raw_event = TestDataPreprocessor._make_permission_interrupt_raw_event()
        # 不先上报 invoke_start,缓存无记录
        events = await preprocessor.parse(raw_event)
        node = events[-1].event_node
        assert node.interaction_input == ""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_parse_fields_correctness() -> None:
        """验证解析后 UnifiedEvent 各字段正确性。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        raw_event = TestDataPreprocessor._make_tool_input_raw_event()
        events = await preprocessor.parse(raw_event)
        unified = events[-1]
        # event_id 已生成
        assert unified.event_id
        # trace 已构建
        assert unified.trace.trace_id == "test-trace"
        # event_node 已注册到 trace.all_nodes
        assert unified.event_node.node_id in unified.trace.all_nodes
        # input_content 来自 tool_args
        assert "command" in unified.event_node.input_content

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_auto_session_start_node() -> None:
        """验证无显式 session 事件时自动生成 session 节点。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        raw_event = TestDataPreprocessor._make_tool_input_raw_event()
        events = await preprocessor.parse(raw_event)
        unified = events[0]
        # 自动生成的 session 节点应存在于 trace.all_nodes
        session_node_id = "test-session_session"
        assert session_node_id in unified.trace.all_nodes
        start_node = unified.trace.all_nodes[session_node_id]
        assert start_node.node_type == "session"
        assert start_node.action_name == "session_start"
        assert start_node.interaction_seq == -1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_parse_invalid_raw_event_type() -> None:
        """验证传入非 dict 时抛出 ValueError。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        with pytest.raises(ValueError):
            await preprocessor.parse("not a dict")  # type: ignore[arg-type]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_parse_missing_common_layer() -> None:
        """验证缺少 common 层时抛出 ValueError。"""
        preprocessor = DataPreprocessor(AgentSSASConfig())
        with pytest.raises(ValueError):
            await preprocessor.parse({"payload": {}, "metadata": {}})


class TestTraceLRUEviction:
    """_traces 缓存 LRU 上限淘汰(P3 修复)。"""

    @staticmethod
    def _make_raw_event(
        trace_id: str,
        session_id: str,
        interaction_seq: int = 0,
    ) -> dict:
        """构造 tool_input raw_event,trace_id/session_id 可参数化。"""
        return {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "tool_input",
                "event_class": "lifecycle",
                "timestamp": 1715000000.0,
                "interaction_seq": interaction_seq,
                "session_id": session_id,
                "conversation_id": session_id,
                "agent_id": "test-agent",
                "trace_id": trace_id,
                "context_id": "test-ctx",
                "llm_call_seq": -1,
                "tool_call_seq": 0,
                "subsession_id": "",
                "tool_call_id": f"call-{trace_id}-{interaction_seq}",
            },
            "payload": {
                "tool_name": "bash",
                "tool_call_id": f"call-{trace_id}-{interaction_seq}",
                "content": {"tool_args": {"command": "ls"}},
            },
            "metadata": {},
        }

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_trace_cache_never_exceeds_max() -> None:
        """验证写入超过上限的 trace 后 dict 长度不超过上限,最旧的被淘汰。"""
        parser = AgentSSASPreprocessor(AgentSSASConfig())
        total = _MAX_CACHED_TRACES + 50

        for i in range(total):
            raw_event = TestTraceLRUEviction._make_raw_event(
                trace_id=f"trace-{i:04d}",
                session_id=f"session-{i:04d}",
            )
            await parser.parse(raw_event)

        # 缓存长度不超过上限
        assert len(parser._traces) <= _MAX_CACHED_TRACES  # pylint: disable=protected-access
        # 最旧的 trace(trace-0000 起)被淘汰
        traces = parser._traces  # pylint: disable=protected-access
        assert "trace-0000" not in traces
        assert "trace-0049" not in traces
        # 最近的 trace 保留(末尾 500 个)
        assert f"trace-{total - 1:04d}" in traces
        assert f"trace-{total - _MAX_CACHED_TRACES:04d}" in traces

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_active_trace_still_queryable_after_normal_flow() -> None:
        """验证正常事件序列处理后最近的 trace 仍可查且结构完整。"""
        parser = AgentSSASPreprocessor(AgentSSASConfig())
        # 同一 trace/session 的事件序列:tool_input → tool_output
        events = await parser.parse(
            TestTraceLRUEviction._make_raw_event(
                trace_id="active-trace", session_id="active-session"
            )
        )
        assert len(events) >= 1
        tool_output_event = TestTraceLRUEviction._make_raw_event(
            trace_id="active-trace",
            session_id="active-session",
        )
        tool_output_event["common"]["event_type"] = "tool_output"
        tool_output_event["payload"]["content"] = {"tool_result": "ok"}
        events = await parser.parse(tool_output_event)

        trace = parser._traces.get("active-trace")  # pylint: disable=protected-access
        assert trace is not None
        # 两类节点均注册到全局索引(session 节点 + tool_call 节点)
        assert "active-session_session" in trace.all_nodes
        assert "active-session_0_toolcall_0" in trace.all_nodes
        # session 与 trace 关联
        assert len(trace.sessions) == 1
        assert trace.sessions[0].session_id == "active-session"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_trace_lru_access_refresh_order() -> None:
        """验证 LRU 命中刷新顺序:再次访问的 trace 不会被优先淘汰。"""
        parser = AgentSSASPreprocessor(AgentSSASConfig())
        original_max = _MAX_CACHED_TRACES
        # 临时调小上限加速测试(直接改模块常量)
        import agent_ssas.core.framework.data_preprocessor.agent_preprocessor as ap

        ap._MAX_CACHED_TRACES = 3
        try:
            # 写入 3 个 trace
            for tid in ("t1", "t2", "t3"):
                await parser.parse(
                    TestTraceLRUEviction._make_raw_event(
                        trace_id=tid, session_id=f"s-{tid}"
                    )
                )
            assert len(parser._traces) == 3  # pylint: disable=protected-access

            # 访问 t1(刷新为最近使用)
            await parser.parse(
                TestTraceLRUEviction._make_raw_event(
                    trace_id="t1", session_id="s-t1"
                )
            )

            # 写入 t4:应淘汰最久未使用的 t2
            await parser.parse(
                TestTraceLRUEviction._make_raw_event(
                    trace_id="t4", session_id="s-t4"
                )
            )
            traces = parser._traces  # pylint: disable=protected-access
            assert len(traces) == 3
            assert "t2" not in traces
            assert "t1" in traces
            assert "t3" in traces
            assert "t4" in traces
        finally:
            ap._MAX_CACHED_TRACES = original_max

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_evicted_trace_does_not_break_active_session() -> None:
        """验证淘汰最旧 trace 不影响活跃 session 的继续处理。

        淘汰仅从 _traces 移除 Trace 引用;活跃 session 再次上报时
        若 trace 已被淘汰,会重建空 Trace 并重新关联 session 结构,
        事件解析不中断。
        """
        parser = AgentSSASPreprocessor(AgentSSASConfig())
        original_max = _MAX_CACHED_TRACES
        import agent_ssas.core.framework.data_preprocessor.agent_preprocessor as ap

        ap._MAX_CACHED_TRACES = 2
        try:
            # 写入 t1(将成最旧)
            await parser.parse(
                TestTraceLRUEviction._make_raw_event(
                    trace_id="t1", session_id="s1"
                )
            )
            # 写入 t2、t3:t1 被淘汰
            for tid in ("t2", "t3"):
                await parser.parse(
                    TestTraceLRUEviction._make_raw_event(
                        trace_id=tid, session_id=f"s-{tid}"
                    )
                )
            assert "t1" not in parser._traces  # pylint: disable=protected-access

            # t1 的 session(s1)再次上报:trace 重建,解析正常
            events = await parser.parse(
                TestTraceLRUEviction._make_raw_event(
                    trace_id="t1", session_id="s1"
                )
            )
            assert len(events) >= 1
            node = events[-1].event_node
            assert events[-1].trace.trace_id == "t1"
            # 重建的 trace 中节点正常注册
            assert node.node_id in events[-1].trace.all_nodes
        finally:
            ap._MAX_CACHED_TRACES = original_max
