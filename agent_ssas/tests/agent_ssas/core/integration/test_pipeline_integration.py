# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""流水线集成测试。

验证完整流水线:raw_event -> parse -> pipeline -> RiskAssessment,
生命周期事件处理,安全检测事件处理。
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
# 确保能导入测试 fixtures
from tests.fixtures.event_factory import (
    CallInfo,
    EventIds,
    RiskInfo,
    create_raw_event,
    generate_permission_interrupt_event,
)

from agent_ssas.core.framework.access_adapter.agent_backend import AgentSSASBackend
from agent_ssas.core.framework.config.settings import AgentSSASConfig
from agent_ssas.core.framework.core_types.assessment import RiskAssessment, RiskLevel


class TestPipelineIntegration:
    """流水线集成测试:raw_event -> parse -> pipeline -> RiskAssessment。"""

    @staticmethod
    @pytest.mark.integration
    @pytest.mark.level1
    async def test_full_pipeline_lifecycle_event(ssas_home: Path) -> None:
        """测试完整流水线处理生命周期事件。

        raw_event(tool_input) -> DataPreprocessor.parse ->
        ThreatAnalysisPipeline.run -> RiskAssessment(无风险)。
        """
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        raw_event = create_raw_event(
            "tool_input",
            ids=EventIds(
                session_id="int-session",
                agent_id="int-agent",
                trace_id="int-trace",
            ),
            interaction_seq=0,
            call=CallInfo(tool_call_seq=0, tool_call_id="call-001"),
        )
        assessment = await backend.report_event(raw_event)
        assert isinstance(assessment, RiskAssessment)
        # tool_input 事件:test_detection 通配订阅返回无风险
        assert assessment.risk_level == RiskLevel.SAFE

    @staticmethod
    @pytest.mark.integration
    @pytest.mark.level1
    async def test_full_pipeline_lifecycle_sequence(ssas_home: Path) -> None:
        """测试生命周期事件序列处理。

        依次上报 invoke_start -> llm_input -> tool_input -> tool_output ->
        llm_output -> invoke_end,验证每个事件都返回 RiskAssessment。
        """
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        events = [
            create_raw_event(
                "invoke_start",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
            ),
            create_raw_event(
                "llm_input",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
                call=CallInfo(llm_call_seq=0),
            ),
            create_raw_event(
                "tool_input",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
                call=CallInfo(tool_call_seq=0, tool_call_id="call-001"),
            ),
            create_raw_event(
                "tool_output",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
                call=CallInfo(tool_call_seq=0, tool_call_id="call-001"),
            ),
            create_raw_event(
                "llm_output",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
                call=CallInfo(llm_call_seq=0),
            ),
            create_raw_event(
                "invoke_end",
                ids=EventIds(
                    session_id="seq-session",
                    agent_id="seq-agent",
                    trace_id="seq-trace",
                ),
                interaction_seq=0,
            ),
        ]
        for raw_event in events:
            assessment = await backend.report_event(raw_event)
            assert isinstance(assessment, RiskAssessment)
        # 全部为生命周期事件,最终聚合应为无风险
        # (BlankThreatAnalyzer 和 AgentMossAnalyzer 都返回 safe)

    @staticmethod
    @pytest.mark.integration
    @pytest.mark.level1
    async def test_full_pipeline_security_event(ssas_home: Path) -> None:
        """测试安全检测事件处理。

        permission_interrupt_tool 事件经流水线后,
        security_rail_detection 为 notify 模式,report_event 不等待后台
        检测,直接返回无风险 RiskAssessment。
        """
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        raw_event = generate_permission_interrupt_event(
            ids=EventIds(
                session_id="sec-session",
                agent_id="sec-agent",
                trace_id="sec-trace",
            ),
            interaction_seq=0,
            tool_call_seq=0,
            risk=RiskInfo(
                risk_level="medium",
                risk_type="tool_permission_denied",
                deny_reason="policy_deny",
            ),
        )
        assessment = await backend.report_event(raw_event)
        assert isinstance(assessment, RiskAssessment)
        # security_rail_detection 模块订阅 permission_interrupt_tool,
        # notify 模式:report_event 不等待后台检测,直接返回无风险
        assert assessment.has_risk is False
        assert assessment.risk_level == RiskLevel.SAFE

    @staticmethod
    @pytest.mark.integration
    @pytest.mark.level1
    async def test_pipeline_persists_raw_events(ssas_home: Path) -> None:
        """验证 raw_event 被持久化到 SQLite 数据库。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        raw_event = create_raw_event(
            "tool_input",
            ids=EventIds(
                session_id="persist-session",
                trace_id="persist-trace",
            ),
        )
        await backend.report_event(raw_event)
        # 从存储查询 raw_events
        events = await backend._storage.get_events_by_trace_id("persist-trace")  # pylint: disable=protected-access
        # 至少应有 raw_event 记录
        assert len(events) >= 1

    @staticmethod
    @pytest.mark.integration
    @pytest.mark.level0
    async def test_result_store_report_survives_ttl_cleanup(
        ssas_home: Path,
    ) -> None:
        """验证真实模块流水线报告落 result_store 后不被 TTL 清理误删(P1)。

        修复前:分析器报告顶层无 timestamp,落库回退 0.0,
        每次 cleanup_expired 全删(90 天结果保留实为 0 天);
        修复后:pipeline 注入事件时刻,90 天清理后报告仍在。
        (原用 agent_moss 模块验证,该模块未随本仓库分发,
        改用 security_rail_detection + permission_interrupt_tool 事件。)
        """
        import time

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        # 事件时刻取 1 天前(90 天 TTL 内,极小 TTL 外)
        event_ts = time.time() - 1 * 86400
        raw_event = generate_permission_interrupt_event(
            ids=EventIds(
                session_id="p1-session",
                agent_id="p1-agent",
                trace_id="p1-trace",
            ),
            interaction_seq=0,
            tool_call_seq=0,
            timestamp=event_ts,
            risk=RiskInfo(
                risk_level="medium",
                risk_type="tool_permission_denied",
                deny_reason="policy_deny",
            ),
        )

        assessment = await backend.report_event(raw_event)
        assert assessment.risk_level == RiskLevel.SAFE  # notify 模式不阻塞
        await asyncio.sleep(0.05)
        background_tasks = backend._pipeline._background_tasks  # pylint: disable=protected-access
        if background_tasks:
            await asyncio.gather(*background_tasks, return_exceptions=True)

        module = backend._module_manager.get_module("security_rail_detection")  # pylint: disable=protected-access
        assert module is not None
        reports = await module.storage.result_store.get_events(limit=20)
        sec_reports = [
            r
            for r in reports
            if r.get("module_name") == "security_rail_detection" and r.get("risk_score", 0) >= 1
        ]
        assert sec_reports, "security_rail_detection 告警报告应已落 result_store"
        report = sec_reports[0]
        # 报告顶层 timestamp 为事件时刻(非 0)
        assert report["timestamp"] == pytest.approx(event_ts, abs=1.0)

        # 落库行 timestamp 列为事件时刻(> 0,不会被 cutoff 立即命中)
        row = module.storage.result_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp FROM events WHERE event_id = ?",
            (report["event_id"],),
        ).fetchone()
        assert row is not None
        assert row[0] > 0.0
        assert row[0] == pytest.approx(event_ts, abs=1.0)

        # 90 天 TTL 清理后报告仍在(不再被立即误删)
        deleted = await module.storage.result_store.cleanup_expired("events", 90)
        assert deleted == 0
        remaining = await module.storage.result_store.get_events(limit=20)
        assert any(r.get("event_id") == report["event_id"] for r in remaining)
