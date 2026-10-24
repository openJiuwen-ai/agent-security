# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""ID 管理模块单元测试 (level1)。"""

from unittest.mock import MagicMock

import pytest
from openjiuwen.core.single_agent.rail.base import AgentCallbackEvent

from agent_ssas.backend_client.openjiuwen.id_manager import IDManager


class TestIDManager:
    """验证 interaction_seq、llm_call_seq、tool_call_seq 整数自增序号、
    tool_call 事件的 llm_call_seq 取值、subsession_id。
    三个计数器均存储当前序号,初始值为 -1,BEFORE_xxx 时先自增再使用。
    """

    @staticmethod
    @pytest.mark.level1
    def test_interaction_seq_incremental_sequence():
        """BEFORE_INVOKE 生成整数自增序号,从 0 开始递增。"""
        ctx = MagicMock()
        ctx.extra = {}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "test-session"
        idm = IDManager()

        # 第一次 BEFORE_INVOKE:-1 自增为 0
        seq0 = idm.ensure_interaction_seq(ctx, AgentCallbackEvent.BEFORE_INVOKE)  # pylint: disable=protected-access
        assert seq0 == 0
        assert isinstance(seq0, int)

        # 第二次 BEFORE_INVOKE:0 自增为 1
        seq1 = idm.ensure_interaction_seq(ctx, AgentCallbackEvent.BEFORE_INVOKE)  # pylint: disable=protected-access
        assert seq1 == 1
        assert isinstance(seq1, int)

    @staticmethod
    @pytest.mark.level1
    def test_interaction_seq_reused_within_invoke():
        """同一 invoke 内后续事件复用 interaction_seq(从 LRU 池读取当前值)。"""
        ctx = MagicMock()
        ctx.extra = {}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "test-session"
        idm = IDManager()

        # BEFORE_INVOKE 生成(-1 自增为 0)
        idm.ensure_interaction_seq(ctx, AgentCallbackEvent.BEFORE_INVOKE)  # pylint: disable=protected-access
        # 后续事件复用(非 BEFORE_INVOKE,从 LRU 池读取当前值)
        seq = idm.ensure_interaction_seq(ctx, AgentCallbackEvent.BEFORE_MODEL_CALL)  # pylint: disable=protected-access
        assert seq == 0

    @staticmethod
    @pytest.mark.level1
    def test_llm_call_seq_generated_on_before_model_call():
        """BEFORE_MODEL_CALL 生成整数自增序号(初始 -1,先自增再使用),AFTER_MODEL_CALL 复用。"""
        ctx = MagicMock()
        ctx.extra = {}
        idm = IDManager()

        # BEFORE_MODEL_CALL 生成(-1 自增为 0)
        llm_seq_1 = idm.ensure_llm_call_seq(ctx, AgentCallbackEvent.BEFORE_MODEL_CALL)  # pylint: disable=protected-access
        assert llm_seq_1 == 0
        assert isinstance(llm_seq_1, int)
        assert ctx.extra["llm_call_seq"] == 0

        # AFTER_MODEL_CALL 复用(读取当前值)
        llm_seq_2 = idm.ensure_llm_call_seq(ctx, AgentCallbackEvent.AFTER_MODEL_CALL)  # pylint: disable=protected-access
        assert llm_seq_2 == llm_seq_1 == 0

        # 第二次 BEFORE_MODEL_CALL(0 自增为 1)
        llm_seq_3 = idm.ensure_llm_call_seq(ctx, AgentCallbackEvent.BEFORE_MODEL_CALL)  # pylint: disable=protected-access
        assert llm_seq_3 == 1
        assert ctx.extra["llm_call_seq"] == 1

    @staticmethod
    @pytest.mark.level1
    def test_tool_call_seq_generated_on_before_tool_call():
        """BEFORE_TOOL_CALL 生成整数自增序号(初始 -1,先自增再使用),AFTER_TOOL_CALL 复用。"""
        ctx = MagicMock()
        ctx.extra = {}
        idm = IDManager()

        # 第一次 BEFORE_TOOL_CALL(-1 自增为 0)
        seq0 = idm.ensure_tool_call_seq(ctx, AgentCallbackEvent.BEFORE_TOOL_CALL)  # pylint: disable=protected-access
        assert seq0 == 0
        assert isinstance(seq0, int)
        assert ctx.extra["tool_call_seq"] == 0

        # AFTER_TOOL_CALL 复用(读取当前值)
        seq_after = idm.ensure_tool_call_seq(ctx, AgentCallbackEvent.AFTER_TOOL_CALL)  # pylint: disable=protected-access
        assert seq_after == seq0 == 0

        # 第二次 BEFORE_TOOL_CALL(0 自增为 1)
        seq1 = idm.ensure_tool_call_seq(ctx, AgentCallbackEvent.BEFORE_TOOL_CALL)  # pylint: disable=protected-access
        assert seq1 == 1
        assert ctx.extra["tool_call_seq"] == 1

    @staticmethod
    @pytest.mark.level1
    def test_llm_call_seq_for_tool_call_reads_from_pool():
        """tool_call 事件(分层 ctx 独立 extra)的 llm_call_seq 从 session 级池读取。

        模拟 agent-core 分层架构:BEFORE_MODEL_CALL 与 BEFORE_TOOL_CALL 分属
        不同 AgentCallbackContext(独立 extra 字典),tool 事件所在 ctx.extra
        无 llm_call_seq 键,序号经 session 级 LRU 池跨层共享。
        """
        ctx_model = MagicMock()
        ctx_model.extra = {}
        ctx_model.session = MagicMock()
        ctx_model.session.get_session_id.return_value = "test-session"
        idm = IDManager()

        # 同 session 先后 4 次 model call,池内计数到 3
        for i in range(4):
            seq = idm.ensure_llm_call_seq(ctx_model, AgentCallbackEvent.BEFORE_MODEL_CALL)
            assert seq == i

        # tool 事件:独立 extra 字典(分层 ctx),读池内当前值(最近一次 model call)
        ctx_tool = MagicMock()
        ctx_tool.extra = {}
        ctx_tool.session = MagicMock()
        ctx_tool.session.get_session_id.return_value = "test-session"
        llm_seq = idm.ensure_llm_call_seq(ctx_tool, AgentCallbackEvent.BEFORE_TOOL_CALL)
        assert llm_seq == 3
        assert isinstance(llm_seq, int)
        # 序号镜像写回 ctx.extra,便于同 ctx 内其他组件读取
        assert ctx_tool.extra["llm_call_seq"] == 3

    @staticmethod
    @pytest.mark.level1
    def test_llm_call_seq_default_when_not_set():
        """session 无 model call 记录时返回 -1(未知哨兵)。"""
        ctx = MagicMock()
        ctx.extra = {}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "no-model-session"
        idm = IDManager()

        llm_seq = idm.ensure_llm_call_seq(ctx, AgentCallbackEvent.AFTER_MODEL_CALL)  # pylint: disable=protected-access
        assert llm_seq == -1

    @staticmethod
    @pytest.mark.level1
    def test_llm_call_seq_prefers_valid_extra_value():
        """ctx.extra 已有有效序号时优先返回该值(不自增、不覆盖)。"""
        ctx = MagicMock()
        ctx.extra = {"llm_call_seq": 2}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "extra-session"
        idm = IDManager()

        # 池内无记录,但 ctx.extra 有有效值:优先复用 ctx.extra
        llm_seq = idm.ensure_llm_call_seq(ctx, AgentCallbackEvent.AFTER_MODEL_CALL)
        assert llm_seq == 2
        assert ctx.extra["llm_call_seq"] == 2

    @staticmethod
    @pytest.mark.level1
    def test_llm_call_seq_increment_floors_at_extra_value():
        """自增以 max(池内值, ctx.extra 已有值) 为基准,不回退到更小序号。

        模拟池 LRU 淘汰后 session 又被访问:池内值被淘汰重置,
        但同 ctx 的 extra 仍保留较大序号,下一次自增从 extra 值续接。
        """
        ctx = MagicMock()
        ctx.extra = {}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "floor-session"
        idm = IDManager()

        # 第一次 model call:池计数到 0
        assert idm.ensure_llm_call_seq(
            ctx, AgentCallbackEvent.BEFORE_MODEL_CALL
        ) == 0
        # 模拟池 LRU 淘汰:直接清空池,ctx.extra 仍保留 0
        idm._session_llm_call_seqs.clear()  # pylint: disable=protected-access
        # 第二次 model call:以 extra 值 0 为基准自增,得到 1(不回退到 0)
        assert idm.ensure_llm_call_seq(
            ctx, AgentCallbackEvent.BEFORE_MODEL_CALL
        ) == 1
        assert ctx.extra["llm_call_seq"] == 1
        # 池内计数同步续接到 1
        assert idm._session_llm_call_seqs["floor-session"] == 1  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_tool_call_seq_prefers_valid_extra_value():
        """tool_call_seq 同样优先复用 ctx.extra 已有有效序号。"""
        ctx = MagicMock()
        ctx.extra = {"tool_call_seq": 5}
        ctx.session = MagicMock()
        ctx.session.get_session_id.return_value = "tool-extra-session"
        idm = IDManager()

        # AFTER_TOOL_CALL(非自增事件):优先返回 extra 中的 5
        tool_seq = idm.ensure_tool_call_seq(ctx, AgentCallbackEvent.AFTER_TOOL_CALL)
        assert tool_seq == 5
        assert ctx.extra["tool_call_seq"] == 5

    @staticmethod
    @pytest.mark.level1
    def test_subsession_id_empty_for_non_subagent():
        """非子 Agent 场景 subsession_id 为空字符串。"""
        ctx = MagicMock()
        ctx.inputs = MagicMock()
        ctx.inputs.parent_session_id = None
        idm = IDManager()

        assert idm.resolve_subsession_id(ctx) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_subsession_id_filled_for_subagent():
        """子 Agent 场景 subsession_id 为 parent_session_id。"""
        ctx = MagicMock()
        ctx.inputs = MagicMock()
        ctx.inputs.parent_session_id = "parent-session-001"
        idm = IDManager()

        assert idm.resolve_subsession_id(ctx) == "parent-session-001"  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_session_id_empty_when_no_session():
        """无 session 时返回空字符串。"""
        ctx = MagicMock()
        ctx.session = None
        idm = IDManager()
        assert idm.resolve_session_id(ctx) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_agent_id_empty_when_no_agent():
        """无 agent 时返回空字符串。"""
        ctx = MagicMock()
        ctx.agent = None
        idm = IDManager()
        assert idm.resolve_agent_id(ctx) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_trace_id_empty_when_no_session():
        """无 session 时 trace_id 返回空字符串。"""
        ctx = MagicMock()
        ctx.session = None
        idm = IDManager()
        assert idm.resolve_trace_id(ctx) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_context_id_empty_when_no_context():
        """无 context 时返回空字符串。"""
        ctx = MagicMock()
        ctx.context = None
        idm = IDManager()
        assert idm.resolve_context_id(ctx) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_tool_name_for_non_tool_event():
        """非 TOOL 事件 tool_name 为空字符串。"""
        ctx = MagicMock()
        idm = IDManager()
        assert idm.resolve_tool_name(ctx, AgentCallbackEvent.BEFORE_MODEL_CALL) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_resolve_tool_call_id_empty_for_none():
        """tool_call 为 None 时返回空字符串。"""
        idm = IDManager()
        assert idm.resolve_tool_call_id(None) == ""  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_event_class_for_lifecycle():
        """生命周期事件 event_class 为 lifecycle。"""
        idm = IDManager()
        assert idm.event_class_for(AgentCallbackEvent.BEFORE_INVOKE, "invoke_start") == "lifecycle"  # pylint: disable=protected-access
        assert idm.event_class_for(AgentCallbackEvent.BEFORE_MODEL_CALL, "llm_input") == "lifecycle"  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.level1
    def test_event_class_for_security():
        """安全检测事件 event_class 为 security。"""
        idm = IDManager()
        assert idm.event_class_for(  # pylint: disable=protected-access
            AgentCallbackEvent.BEFORE_TOOL_CALL, "permission_interrupt_tool"
        ) == "security"
