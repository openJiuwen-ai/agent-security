# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""接入适配模块单元测试。

验证 report_event 返回 RiskAssessment、fail-open 异常时返回无风险、
initialize 加载检测模块。
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from agent_ssas.core.framework.access_adapter.agent_backend import AgentSSASBackend
from agent_ssas.core.framework.config.settings import AgentSSASConfig
from agent_ssas.core.framework.core_types.assessment import RiskAssessment, RiskLevel


def _make_raw_event() -> dict:
    """构造测试用 raw_event。"""
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


class TestAgentSSASBackend:
    """AgentSSASBackend 进程内模式。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_report_event_returns_assessment(ssas_home: Path) -> None:
        """验证 report_event 返回 RiskAssessment。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        assessment = await backend.report_event(_make_raw_event())
        assert assessment is not None
        assert isinstance(assessment, RiskAssessment)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_report_event_returns_assessment_with_mock(
        ssas_home: Path,
    ) -> None:
        """验证 report_event 返回 RiskAssessment(mock 内部模块)。

        使用 mock 的 preprocessor 和 pipeline,隔离检测模块依赖。
        """
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        # mock preprocessor.parse 返回事件列表
        backend._preprocessor = MagicMock()  # pylint: disable=protected-access
        backend._preprocessor.parse = AsyncMock(return_value=[MagicMock()])  # pylint: disable=protected-access
        # mock pipeline.run 返回无风险 RiskAssessment
        backend._pipeline = MagicMock()  # pylint: disable=protected-access
        backend._pipeline.run = AsyncMock(  # pylint: disable=protected-access
            return_value=RiskAssessment(has_risk=False, risk_level=RiskLevel.SAFE)
        )
        assessment = await backend.report_event({"common": {}, "payload": {}, "metadata": {}})
        assert assessment is not None
        assert isinstance(assessment, RiskAssessment)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_fail_open_on_exception(ssas_home: Path) -> None:
        """验证引擎异常时 fail-open 返回无风险 RiskAssessment。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        # mock preprocessor.parse 抛出异常
        backend._preprocessor = MagicMock()  # pylint: disable=protected-access
        backend._preprocessor.parse = AsyncMock(  # pylint: disable=protected-access
            side_effect=RuntimeError("engine failed")
        )
        backend._pipeline = MagicMock()  # pylint: disable=protected-access
        backend._pipeline.run = AsyncMock(  # pylint: disable=protected-access
            return_value=RiskAssessment(has_risk=False, risk_level=RiskLevel.SAFE)
        )
        assessment = await backend.report_event({"common": {}, "payload": {}, "metadata": {}})
        assert isinstance(assessment, RiskAssessment)
        assert assessment.risk_level == RiskLevel.SAFE

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_initialize_loads_detection_modules(
        ssas_home: Path,
    ) -> None:
        """验证 initialize 加载检测模块。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        # initialize 后检测模块管理器应已加载内置模块
        # test_detection 默认 disabled,security_rail_detection 默认 enabled
        module = backend._module_manager.get_module("security_rail_detection")  # pylint: disable=protected-access
        assert module is not None

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_initialize_is_idempotent(ssas_home: Path) -> None:
        """验证 initialize 幂等:连续两次调用无异常,模块只加载一次。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()
        await backend.initialize()  # 重复调用应安全返回
        assert backend._initialized is True  # pylint: disable=protected-access
        module = backend._module_manager.get_module("security_rail_detection")  # pylint: disable=protected-access
        assert module is not None

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_report_event_auto_waits_for_initialization(
        ssas_home: Path,
    ) -> None:
        """验证未先 initialize 时 report_event 自动等待初始化(fire-and-forget 竞态修复)。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        # 模拟 patch 的 fire-and-forget:不 await initialize 直接 report_event
        assessment = await backend.report_event(_make_raw_event())
        assert isinstance(assessment, RiskAssessment)
        # 初始化已被自动触发并完成,检测模块可用
        assert backend._initialized is True  # pylint: disable=protected-access
        module = backend._module_manager.get_module("security_rail_detection")  # pylint: disable=protected-access
        assert module is not None

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_report_event_waits_inflight_init_task(
        ssas_home: Path,
    ) -> None:
        """验证在途 fire-and-forget 初始化任务被等待完成而非重复执行。"""
        import asyncio

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        # 模拟 patch 的 ensure_future(backend.initialize())
        init_task = asyncio.ensure_future(backend.initialize())
        backend._init_task = init_task  # pylint: disable=protected-access
        # 未等待初始化完成直接上报事件
        assessment = await backend.report_event(_make_raw_event())
        assert isinstance(assessment, RiskAssessment)
        # 在途任务完成后初始化标志置位
        await init_task
        assert backend._initialized is True  # pylint: disable=protected-access

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_security_event_writes_alert_via_notify(
        ssas_home: Path,
    ) -> None:
        """验证 permission_interrupt_tool 事件经 notify 路径写入 alerts 表。

        该用例复现并验证告警丢失根因修复:全 notify 订阅下同步返回无风险,
        但有风险的报告由流水线后台任务写入主库 alerts 表。
        """
        import asyncio

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()

        raw_event = _make_raw_event()
        # 改写为安全检测事件(PermissionInterruptRail 策略 deny 场景)
        raw_event["common"]["event_type"] = "permission_interrupt_tool"
        raw_event["common"]["event_class"] = "security"
        raw_event["payload"]["risk_source"] = "PermissionInterruptRail"
        raw_event["payload"]["risk_type"] = "tool_permission_denied"
        raw_event["payload"]["risk_level"] = "medium"
        raw_event["payload"]["deny_reason"] = "policy_deny"
        raw_event["payload"]["decision"] = "reject"

        assessment = await backend.report_event(raw_event)
        # observe 默认策略(全 notify)同步返回无风险
        assert assessment.risk_level == RiskLevel.SAFE
        # 等待 notify 后台任务完成(含告警落库)
        await backend.wait_background_tasks()
        alerts = await backend._storage.get_alerts()  # pylint: disable=protected-access
        assert len(alerts) == 1
        alert = alerts[0]
        # alert_id 含 module_name,可追溯产生告警的检测模块
        assert alert["alert_id"].endswith("_security_rail_detection")
        assert alert["module_name"] == "security_rail_detection"
        # medium(策略 deny 场景)事件仍写入 alerts 表
        assert alert["risk_level"] == "medium"
        assert alert["risk_type"] == "tool_permission_denied"
        # timestamp_text 列为本地时区可读格式(直接查表列验证)
        row = backend._storage._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM alerts WHERE alert_id = ?",
            (alert["alert_id"],),
        ).fetchone()
        assert row is not None and len(row[0]) > 0

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_low_risk_user_reject_event_writes_alert(
        ssas_home: Path,
    ) -> None:
        """验证 low(user_reject)事件同样写入 alerts 表并生成威胁报告。

        medium/low 均高于 safe,满足 _write_alerts 的入表条件
        (risk_level 高于 safe 即入表),确保场景化降级不丢告警。
        """
        import asyncio

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()

        raw_event = _make_raw_event()
        # 改写为安全检测事件(ask 模式用户拒绝场景:low / user_reject)
        raw_event["common"]["event_type"] = "permission_interrupt_tool"
        raw_event["common"]["event_class"] = "security"
        raw_event["payload"]["risk_source"] = "PermissionInterruptRail"
        raw_event["payload"]["risk_type"] = "tool_permission_denied"
        raw_event["payload"]["risk_level"] = "low"
        raw_event["payload"]["deny_reason"] = "user_reject"
        raw_event["payload"]["decision"] = "reject"

        await backend.report_event(raw_event)
        # 等待 notify 后台任务完成(含告警落库)
        await backend.wait_background_tasks()
        alerts = await backend._storage.get_alerts()  # pylint: disable=protected-access
        assert len(alerts) == 1
        assert alerts[0]["risk_level"] == "low"

        # 威胁报告同步生成,OCSF severity_id 按 low -> 2 映射
        import json

        threat_log_dir = Path(config.storage_path) / "reports" / "threat_log"
        files = list(threat_log_dir.glob("*.json"))
        assert len(files) == 1
        with open(files[0], "r", encoding="utf-8") as f:
            ocsf = json.load(f)
        assert ocsf["severity_id"] == 2  # low -> 2
        assert ocsf["finding_info"]["analytic"]["name"] == "Tool Permission Rejected"
        assert ocsf["finding_info"]["desc"] == "User rejected the tool call to bash"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_initialize_triggers_ttl_cleanup(ssas_home: Path) -> None:
        """验证 initialize 启动时执行 TTL 清理(预置过期数据被清除)。"""
        import time

        from agent_ssas.core.framework.storage.sqlite_store import SQLiteStore

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        # 预置过期数据到主库(先以同一路径打开写入;AgentSSASBackend 构造时
        # 才会创建 ssas 目录,此处需先建目录)
        db_path = ssas_home / "ssas" / "ssas_core.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        pre_store = SQLiteStore(db_path)
        old_ts = time.time() - 31 * 86400  # 31 天前,超过 event_ttl=30
        await pre_store.record_event(
            {
                "event_id": "stale_event",
                "event_type": "invoke_start",
                "timestamp": old_ts,
            }
        )
        await pre_store.record_raw_event(
            {
                "common": {
                    "event_type": "invoke_start",
                    "event_class": "lifecycle",
                    "timestamp": old_ts,
                    "session_id": "s1",
                }
            }
        )
        pre_store._conn.close()  # pylint: disable=protected-access

        backend = AgentSSASBackend(config)
        await backend.initialize()  # 启动清理应删除过期事件

        events = await backend._storage.get_events()  # pylint: disable=protected-access
        raw_events = backend._storage._conn.execute(  # pylint: disable=protected-access
            "SELECT data FROM raw_events"
        ).fetchall()
        assert all(e["event_id"] != "stale_event" for e in events)
        assert len(raw_events) == 0

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_storages_removes_expired_threat_reports(
        ssas_home: Path,
    ) -> None:
        """验证 _cleanup_storages 链路清理过期威胁报告 JSON 文件。

        预置一个文件名时间戳过期的报告文件,经 initialize 触发的
        启动清理后应被删除(数据生命周期 P2 修复)。
        """
        import time
        from datetime import datetime, timedelta

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        threat_log_dir = Path(config.storage_path) / "reports" / "threat_log"
        threat_log_dir.mkdir(parents=True, exist_ok=True)

        # 预置过期报告文件(文件名时间戳 91 天前,超过 report_file_ttl=90)
        expired_dt = datetime.fromtimestamp(time.time()) - timedelta(  # noqa: DTZ006
            days=91
        )
        expired_name = (
            f"threat_trace-old_mod_{expired_dt.strftime('%Y%m%d_%H%M%S')}_001.json"
        )
        expired_path = threat_log_dir / expired_name
        expired_path.write_text("{}", encoding="utf-8")
        # 预置未过期报告文件(文件名时间戳 1 天前,应保留)
        fresh_dt = datetime.fromtimestamp(time.time()) - timedelta(days=1)  # noqa: DTZ006
        fresh_name = (
            f"threat_trace-new_mod_{fresh_dt.strftime('%Y%m%d_%H%M%S')}_002.json"
        )
        fresh_path = threat_log_dir / fresh_name
        fresh_path.write_text("{}", encoding="utf-8")

        backend = AgentSSASBackend(config)
        await backend.initialize()  # 启动清理应删除过期报告文件

        assert not expired_path.exists()
        assert fresh_path.exists()


class TestPeriodicTTLCleanup:
    """周期性 TTL 后台清理任务(数据生命周期 P5 修复)。

    低流量进程下"启动清理 + 每 100 次上报触发清理"不足以保证过期
    数据的保留期上界;修复后 initialize() 启动周期性后台清理任务,
    close() 时取消。测试用 mock asyncio.sleep 验证定时触发语义,
    不真实等待 24 小时。
    """

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_initialize_starts_and_close_cancels_cleanup_task(
        ssas_home: Path,
    ) -> None:
        """验证 initialize 后存在周期清理任务,close 后任务被取消。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        await backend.initialize()

        task = backend._cleanup_task  # pylint: disable=protected-access
        assert task is not None
        assert not task.done()

        await backend.close()
        # close 后任务已结束并清空引用
        assert backend._cleanup_task is None  # pylint: disable=protected-access
        assert task.cancelled() or task.done()

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_periodic_cleanup_loop_triggers_cleanup(
        ssas_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """验证定时循环到点后调用清理(间隔语义经 mock sleep 验证)。

        fake_sleep 记录收到的间隔秒数(24h -> 86400),并在第 3 次调用时
        抛出 CancelledError 终止循环;断言清理被调用 2 次且间隔正确。
        """
        import asyncio

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        cleanup_mock = AsyncMock()
        monkeypatch.setattr(
            backend, "_cleanup_storages_safe", cleanup_mock
        )

        sleep_intervals: list[float] = []

        async def fake_sleep(interval: float) -> None:
            sleep_intervals.append(interval)
            if len(sleep_intervals) >= 3:
                raise asyncio.CancelledError

        monkeypatch.setattr(
            "agent_ssas.core.framework.access_adapter.agent_backend.asyncio.sleep",
            fake_sleep,
        )

        with pytest.raises(asyncio.CancelledError):
            await backend._periodic_cleanup_loop(24)  # pylint: disable=protected-access

        assert cleanup_mock.await_count == 2
        # 间隔按小时换算为秒:24 小时 = 86400 秒
        assert sleep_intervals == [86400.0, 86400.0, 86400.0]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_periodic_cleanup_loop_survives_cleanup_failure(
        ssas_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """验证单次清理失败不中断循环(_cleanup_storages_safe 记日志后继续)。"""
        import asyncio

        config = AgentSSASConfig(ssas_home=str(ssas_home))
        backend = AgentSSASBackend(config)
        # mock 真正的清理逻辑抛异常,由 _cleanup_storages_safe 捕获
        calls = {"count": 0}

        async def failing_cleanup() -> None:
            calls["count"] += 1
            if calls["count"] == 1:
                raise RuntimeError("cleanup failed")

        async def fake_sleep(interval: float) -> None:
            if calls["count"] >= 2:
                raise asyncio.CancelledError

        monkeypatch.setattr(
            "agent_ssas.core.framework.access_adapter.agent_backend.asyncio.sleep",
            fake_sleep,
        )
        monkeypatch.setattr(
            backend, "_cleanup_storages", failing_cleanup
        )

        # 第一次清理抛 RuntimeError,经 _cleanup_storages_safe 捕获后
        # 循环继续执行第二次清理(最终由 fake_sleep 抛 CancelledError 终止)
        with pytest.raises(asyncio.CancelledError):
            await backend._periodic_cleanup_loop(24)  # pylint: disable=protected-access
        assert calls["count"] == 2

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_task_not_started_when_disabled(
        ssas_home: Path,
    ) -> None:
        """验证 cleanup_interval_hours <= 0 时禁用周期清理任务。"""
        config = AgentSSASConfig(ssas_home=str(ssas_home), cleanup_interval_hours=0)
        backend = AgentSSASBackend(config)
        backend._start_cleanup_task()  # pylint: disable=protected-access
        assert backend._cleanup_task is None  # pylint: disable=protected-access
        # close 幂等:无在途任务时安全返回
        await backend.close()
