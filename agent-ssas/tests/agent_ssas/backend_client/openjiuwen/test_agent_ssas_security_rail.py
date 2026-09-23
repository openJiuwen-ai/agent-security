# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""AgentSSASSecurityRail 采集逻辑单元测试 (level1)。"""

import asyncio
from unittest.mock import MagicMock

import pytest
from openjiuwen.core.single_agent.rail.base import AgentCallbackEvent, AgentRail
from openjiuwen.harness.rails.security.base_security_rail import SecurityAllow

from agent_ssas.backend_client.openjiuwen.agent_ssas_security_rail import (
    _MODEL_EVENTS,
    _PIPELINE_EVENTS,
    AgentSSASSecurityRail,
)
from agent_ssas.core.framework.core_types.assessment import (
    RiskAssessment,
    RiskLevel,
)


class TestAgentSSASSecurityRailCollection:
    """验证 AgentSSASSecurityRail 的事件采集逻辑。"""

    @staticmethod
    @pytest.mark.level1
    def test_priority_is_80():
        """验证 priority=80。"""
        assert AgentSSASSecurityRail.priority == 80

    @staticmethod
    @pytest.mark.level1
    def test_supported_events_declared():
        """验证 supported_events 声明了 6 个管线事件。"""
        assert AgentSSASSecurityRail.supported_events == _PIPELINE_EVENTS
        assert len(_PIPELINE_EVENTS) == 6
        assert len(_MODEL_EVENTS) == 2

    @staticmethod
    @pytest.mark.level1
    def test_pipeline_events_contains_correct_events():
        """验证 _PIPELINE_EVENTS 包含正确的 6 个事件。"""
        expected = {
            AgentCallbackEvent.BEFORE_INVOKE,
            AgentCallbackEvent.AFTER_INVOKE,
            AgentCallbackEvent.BEFORE_MODEL_CALL,
            AgentCallbackEvent.AFTER_MODEL_CALL,
            AgentCallbackEvent.BEFORE_TOOL_CALL,
            AgentCallbackEvent.AFTER_TOOL_CALL,
        }
        assert _PIPELINE_EVENTS == expected

    @staticmethod
    @pytest.mark.level1
    def test_model_events_contains_correct_events():
        """验证 _MODEL_EVENTS 包含 BEFORE/AFTER_MODEL_CALL。"""
        expected = {
            AgentCallbackEvent.BEFORE_MODEL_CALL,
            AgentCallbackEvent.AFTER_MODEL_CALL,
        }
        assert _MODEL_EVENTS == expected

    @staticmethod
    @pytest.mark.level1
    def test_init_creates_modules():
        """验证 __init__ 创建了各模块实例。"""
        backend = MagicMock()
        rail = AgentSSASSecurityRail(backend=backend)

        assert rail._backend is backend  # pylint: disable=protected-access
        assert rail._id_manager is not None  # pylint: disable=protected-access
        assert rail._event_builder is not None  # pylint: disable=protected-access
        assert rail._event_filter is not None  # pylint: disable=protected-access
        assert rail._event_reporter is not None  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_run_security_check_returns_allow_on_filter_none():
        """过滤返回 None 时返回 SecurityAllow。"""
        backend = MagicMock()
        rail = AgentSSASSecurityRail(backend=backend)

        # 构造 mock security_ctx,让 event_filter 返回 None
        sec_ctx = MagicMock()
        sec_ctx.event = AgentCallbackEvent.BEFORE_INVOKE
        sec_ctx.callback_ctx = MagicMock()
        sec_ctx.callback_ctx.extra = {}

        # Mock event_builder 返回一个 dict
        rail._event_builder.build_event_dict = MagicMock(  # pylint: disable=protected-access
            return_value={"common": {}, "payload": {}, "metadata": {}}
        )
        # Mock event_filter 返回 None
        rail._event_filter.filter_event = MagicMock(return_value=None)  # pylint: disable=protected-access

        result = await rail.run_security_check(sec_ctx)
        assert isinstance(result, SecurityAllow)

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_run_security_check_reports_filtered_event():
        """验证 run_security_check 正确串联 builder→filter→reporter。"""
        backend = MagicMock()

        async def _report(raw_event):
            return RiskAssessment(risk_level=RiskLevel.SAFE)

        backend.report_event = _report
        rail = AgentSSASSecurityRail(backend=backend)

        # 构造 mock security_ctx
        sec_ctx = MagicMock()
        sec_ctx.event = AgentCallbackEvent.BEFORE_INVOKE
        sec_ctx.callback_ctx = MagicMock()
        sec_ctx.callback_ctx.extra = {}
        sec_ctx.callback_ctx.inputs = MagicMock()
        sec_ctx.callback_ctx.exception = None

        # 不 mock event_builder/filter,用真实实现
        result = await rail.run_security_check(sec_ctx)
        # 应返回 SecurityAllow(因为 backend 返回 SAFE)
        assert isinstance(result, SecurityAllow)


class TestAgentSSASSecurityRailClose:
    """验证 AgentSSASSecurityRail 的后端关闭语义。

    agent-core 的 AgentRail 定义同步销毁钩子 uninit(agent),由
    BaseAgent.unregister_rail() 调用,rail 覆写后在钩子内调度异步
    close;close() 亦为宿主可显式 await 的释放入口。
    """

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_close_calls_backend_close():
        """调用 rail.close() 后 backend.close 被调用(spy 计数)。"""
        backend = MagicMock()
        close_calls = []

        async def _close_spy():
            close_calls.append(1)

        backend.close = _close_spy
        rail = AgentSSASSecurityRail(backend=backend)

        await rail.close()
        assert len(close_calls) == 1

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_close_remote_backend_no_error():
        """remote backend(AgentSSASRemoteBackend)场景调用不报错。

        AgentSSASRemoteBackend 有 close(关闭 httpx 客户端),rail.close
        委托调用;此处用等价桩验证协议语义。
        """
        from agent_ssas.core.framework.config.settings import AgentSSASConfig

        from agent_ssas.core.framework.access_adapter.agent_remote_backend import (  # pylint: disable=wrong-import-position
            AgentSSASRemoteBackend,
        )

        backend = AgentSSASRemoteBackend(
            AgentSSASConfig(http_endpoint="http://localhost:8443")
        )
        rail = AgentSSASSecurityRail(backend=backend)
        # 不应抛错
        await rail.close()

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_close_backend_without_close_method_skips():
        """backend 无 close 方法时静默跳过,不报错。"""

        class _NoCloseBackend:
            """无 close 方法的桩后端(协议最小实现)。"""

            async def report_event(self, raw_event):
                return RiskAssessment(risk_level=RiskLevel.SAFE)

        rail = AgentSSASSecurityRail(backend=_NoCloseBackend())
        # 不应抛 AttributeError
        await rail.close()

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_close_is_idempotent():
        """重复调用 rail.close() 安全(spy 计数累加不报错)。

        backend.close() 幂等(AgentSSASBackend.close 可重复调用),
        rail.close 每次都委托 backend.close,不额外维护状态。
        """
        backend = MagicMock()
        close_calls = []

        async def _close_spy():
            close_calls.append(1)

        backend.close = _close_spy
        rail = AgentSSASSecurityRail(backend=backend)

        await rail.close()
        await rail.close()
        assert len(close_calls) == 2

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_close_backend_close_exception_swallowed():
        """backend.close() 抛异常时 rail.close 不抛出(仅记日志)。"""
        backend = MagicMock()

        async def _close_fail():
            raise RuntimeError("simulated backend close failure")

        backend.close = _close_fail
        rail = AgentSSASSecurityRail(backend=backend)

        # 不应向外抛出
        await rail.close()

    @staticmethod
    @pytest.mark.asyncio
    @pytest.mark.level1
    async def test_uninit_schedules_backend_close():
        """uninit 钩子在事件循环内调用时调度 backend.close 执行。"""
        backend = MagicMock()
        close_calls = []

        async def _close_spy():
            close_calls.append(1)

        backend.close = _close_spy
        rail = AgentSSASSecurityRail(backend=backend)

        # 模拟 unregister_rail() 的同步上下文:运行中事件循环内调用 uninit
        rail.uninit(agent=None)
        # ensure_future 已调度,await 一次让出控制权使任务执行
        await asyncio.sleep(0)
        assert len(close_calls) == 1

    @staticmethod
    @pytest.mark.level1
    def test_uninit_without_running_loop_skips_gracefully():
        """无运行中事件循环时 uninit 跳过调度,不抛错(宿主 close() 兜底)。"""
        backend = MagicMock()
        close_calls = []

        async def _close_spy():
            close_calls.append(1)

        backend.close = _close_spy
        rail = AgentSSASSecurityRail(backend=backend)

        # 同步测试上下文无运行中事件循环,ensure_future 抛 RuntimeError
        # 被 uninit 捕获跳过
        rail.uninit(agent=None)
        assert close_calls == []

    @staticmethod
    @pytest.mark.level1
    def test_uninit_calls_super(monkeypatch):
        """uninit 覆写透传 super().uninit(agent)(保持基类钩子语义)。"""
        backend = MagicMock()
        rail = AgentSSASSecurityRail(backend=backend)

        called_with = []

        def _super_uninit_spy(self, agent):
            called_with.append(agent)

        # 替换 AgentRail.uninit 为 spy,验证 super().uninit 被透传调用
        monkeypatch.setattr(AgentRail, "uninit", _super_uninit_spy)
        rail.uninit(agent="fake-agent")
        # 无事件循环时跳过调度,但 super().uninit 仍被调用
        assert called_with == ["fake-agent"]
