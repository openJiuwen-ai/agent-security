# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""呈现模块单元测试。

验证 render 生成 OCSF Detection Finding 格式文件、
risk_level_to_severity 映射、build_ocsf_report 构建。
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_ssas.core.framework.config.settings import AgentSSASConfig
from agent_ssas.core.framework.presentation.ocsf import (
    build_ocsf_report,
    risk_level_to_severity,
)
from agent_ssas.core.framework.presentation.threat_log import AgentSSASThreatLog


class TestAgentSSASThreatLog:
    """威胁日志呈现插件。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_render_generates_ocsf_file(ssas_config: AgentSSASConfig) -> None:
        """验证 render 生成 OCSF Detection Finding 格式 JSON 文件。"""
        presentation = AgentSSASThreatLog(ssas_config)
        report = {
            "has_risk": True,
            "risk_level": "high",
            "risk_type": "tool_misuse",
            "risk_score": 75.0,
            "confidence": 0.9,
            "detected_threats": ["tool_misuse"],
            "analytic_name": "Tool Permission Denied",
            "analytic_type_id": 1,
            "description": "PermissionInterruptRail denied the tool call to rm",
            "evidence": {"risk_source": "PermissionInterruptRail", "decision": "reject"},
            "recommended_actions": ["log", "alert"],
            "module_name": "security_rail_detection",
            "aux_ids": {
                "trace_id": "trace-1",
                "session_id": "s1",
                "interaction_seq": 0,
                "agent_id": "a1",
                "llm_call_seq": 0,
                "tool_call_seq": 1,
            },
            "event_node": {
                "event_type": "permission_interrupt_tool",
                "action_name": "rm",
                "input_content": '{"command": "rm -rf /"}',
                "output_content": "",
                "source": "AgentSSASSecurityRail",
                # 事件真实时刻(秒),与渲染时刻明显不同,验证 time 语义
                "timestamp": 1715000000.0,
            },
            "timestamp": 1715000000.0,
        }
        await presentation.render(report)
        # 验证文件已生成
        output_dir = Path(ssas_config.storage_path) / "reports" / "threat_log"
        files = list(output_dir.glob("threat_trace-1_*.json"))
        assert len(files) == 1
        # 验证文件名为可读时间格式(YYYYMMDD_HHMMSS_mmm)
        import re

        file_name = files[0].name
        assert re.search(r"_\d{8}_\d{6}_\d{3}\.json$", file_name), f"威胁日志文件名时间格式不符: {file_name!r}"
        # 验证文件内容为 OCSF Detection Finding 格式
        with open(files[0], "r", encoding="utf-8") as f:
            ocsf = json.load(f)
        # 框架固定字段
        assert ocsf["activity_id"] == 1
        assert ocsf["activity_name"] == "Create"
        assert ocsf["category_uid"] == 2
        assert ocsf["category_name"] == "Findings"
        assert ocsf["class_uid"] == 2004
        assert ocsf["class_name"] == "Detection Finding"
        assert ocsf["severity_id"] == 4  # high -> 4
        assert ocsf["status"] == "New"
        assert ocsf["status_id"] == 1
        assert ocsf["trace_id"] == "trace-1"
        # metadata
        assert ocsf["metadata"]["product"]["name"] == "AgentSSAS"
        assert ocsf["metadata"]["product"]["vendor_name"] == "AgentSSAS"
        # metadata.product.feature.name 承载第二级发现者(检测模块名)
        assert ocsf["metadata"]["product"]["feature"]["name"] == "security_rail_detection"
        # metadata.profiles 声明 ai_operation profile
        assert ocsf["metadata"]["profiles"] == ["ai_operation"]
        # actor
        assert ocsf["actor"]["name"] == "a1"
        assert ocsf["actor"]["type"] == "Application"
        assert ocsf["actor"]["type_id"] == 4
        # ai_agent
        assert ocsf["ai_agent"]["uid"] == "a1"
        assert ocsf["ai_agent"]["type"] == "Native"
        # ai_agent.instance_uid 承载 session_id
        assert ocsf["ai_agent"]["instance_uid"] == "s1"
        # 无 resources 字段
        assert "resources" not in ocsf
        # finding_info 只保留 OCSF 标准字段
        assert "evidence" not in ocsf["finding_info"]
        assert "product" not in ocsf["finding_info"]
        # analytic 对象(第三级发现者,检测策略名)
        assert ocsf["finding_info"]["analytic"]["type_id"] == 1
        assert ocsf["finding_info"]["analytic"]["type"] == "Rule"
        assert ocsf["finding_info"]["analytic"]["name"] == "Tool Permission Denied"
        # finding_info.uid 为 UUID 字符串
        assert isinstance(ocsf["finding_info"]["uid"], str)
        assert len(ocsf["finding_info"]["uid"]) > 0
        assert ocsf["finding_info"]["desc"] == ("PermissionInterruptRail denied the tool call to rm")
        # confidence 映射为 confidence_id (int) + confidence (str)
        assert ocsf["finding_info"]["confidence_id"] == 3  # 0.9 -> High -> 3
        assert ocsf["finding_info"]["confidence"] == "High"
        # confidence_score 按 OCSF 语义填置信度分值(0-100,与 confidence 0-1 同源)
        assert ocsf["finding_info"]["confidence_score"] == 90
        # types(OCSF 标准字段,原 risk_types)
        assert ocsf["finding_info"]["types"] == ["tool_misuse"]
        # created_time 是毫秒级时间戳
        assert isinstance(ocsf["finding_info"]["created_time"], int)
        assert ocsf["finding_info"]["created_time"] > 1715000000000
        # 顶层 evidences 数组(OCSF 标准 Evidence Artifacts)
        assert isinstance(ocsf["evidences"], list)
        assert len(ocsf["evidences"]) == 1
        evidence_item = ocsf["evidences"][0]
        assert isinstance(evidence_item["uid"], str)
        assert len(evidence_item["uid"]) > 0
        assert evidence_item["name"] == "detection_evidence"
        # evidences[0].data 包含 detected_threats 和 recommended_actions
        assert evidence_item["data"]["detected_threats"] == ["tool_misuse"]
        assert evidence_item["data"]["recommended_actions"] == ["log", "alert"]
        # 检测模块自定义 evidence 字段也合并到 data
        assert evidence_item["data"]["risk_source"] == "PermissionInterruptRail"
        assert evidence_item["data"]["decision"] == "reject"
        # time 为事件真实时刻(秒级 timestamp 转 OCSF 毫秒),非渲染时刻
        assert ocsf["time"] == 1715000000000
        # message_context:工具事件的 prompt_text/response_text 为空(工具输入输出在 ai_operation 中)
        assert ocsf["message_context"]["ai_role_id"] == 3  # tool -> 3
        assert ocsf["message_context"]["ai_role"] == "Tool"
        assert ocsf["message_context"]["prompt_text"] == ""
        assert ocsf["message_context"]["response_text"] == ""
        assert ocsf["message_context"]["application"]["name"] == "JiuwenSwarm"
        # risk_source 从 evidence 中提取
        assert ocsf["message_context"]["service"]["name"] == "PermissionInterruptRail"
        # ai_operation
        interactions = ocsf["ai_operation"]["interactions"]
        assert len(interactions) == 1
        llm_calls = interactions[0]["llm_calls"]
        assert len(llm_calls) == 1
        tool_calls = llm_calls[0]["tool_calls"]
        assert len(tool_calls) == 1
        assert tool_calls[0]["name"] == "rm"
        assert tool_calls[0]["input"] == '{"command": "rm -rf /"}'

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_build_ai_operation_interaction_input_and_seq_omitted() -> None:
        """验证 input 缓存 miss 时为空串,seq 未知时省略(-1 不落 JSON)。

        permission_interrupt_tool 事件未先上报同交互 invoke_start 时
        (会话级 query 缓存 miss),interactions[0].input 允许为空串;
        llm_call_seq=-1 时 llm_call 层省略 seq 键(tool_call 层仍挂载),
        保证 OCSF JSON 中不出现 -1 哨兵值。
        """
        report = {
            "has_risk": True,
            "risk_level": "medium",
            "risk_type": "tool_permission_denied",
            "module_name": "security_rail_detection",
            "aux_ids": {
                "trace_id": "trace-miss",
                "session_id": "s1",
                "interaction_seq": 0,
                "agent_id": "a1",
                "llm_call_seq": -1,
                "tool_call_seq": 0,
            },
            "event_node": {
                "event_type": "permission_interrupt_tool",
                "action_name": "bash",
                # 未回填 interaction_input(缓存 miss),字段缺省
                "input_content": '{"command": "ls"}',
                "interaction_input": "",
                "timestamp": 1715000000.0,
            },
        }
        ocsf = build_ocsf_report(report)
        interactions = ocsf["ai_operation"]["interactions"]
        assert len(interactions) == 1
        # 缓存 miss:interaction_input 为空串,不报错
        assert interactions[0]["input"] == ""
        # llm_call_seq 未知:llm_call 层省略 seq 键(不输出 -1),
        # 但仍创建 llm_call 空壳承载 tool_calls
        llm_calls = interactions[0]["llm_calls"]
        assert len(llm_calls) == 1
        assert "seq" not in llm_calls[0]
        # tool_call 层 seq 正常挂载(tool_call_seq 有效)
        assert llm_calls[0]["tool_calls"][0]["seq"] == 0
        # llm_input/llm_output 保持为空(llm_call_seq 未知)
        assert llm_calls[0]["input"] == ""
        assert llm_calls[0]["output"] == ""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_risk_level_to_severity_mapping(ssas_config: AgentSSASConfig) -> None:
        """验证 risk_level_to_severity 映射。"""
        # safe -> 1, low -> 2, medium -> 3, high -> 4, critical -> 5
        assert risk_level_to_severity("safe") == 1
        assert risk_level_to_severity("low") == 2
        assert risk_level_to_severity("medium") == 3
        assert risk_level_to_severity("high") == 4
        assert risk_level_to_severity("critical") == 5
        # 未知风险等级回退为 1 (Info)
        assert risk_level_to_severity("unknown") == 1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_render_medium_and_low_severity(ssas_config: AgentSSASConfig) -> None:
        """验证 medium→severity_id=3、low→severity_id=2 的 OCSF 渲染。

        permission_interrupt_tool 事件场景化分级后,策略 deny 产生 medium
        报告、ask 模式用户拒绝产生 low 报告,两者均应正常渲染为
        OCSF Detection Finding,severity_id 按等级自动映射。
        """
        presentation = AgentSSASThreatLog(ssas_config)
        for risk_level, expected_severity_id in (("medium", 3), ("low", 2)):
            report = {
                "has_risk": True,
                "risk_level": risk_level,
                "risk_type": "tool_permission_denied",
                "risk_score": 50.0 if risk_level == "medium" else 25.0,
                "confidence": 1.0,
                "detected_threats": ["tool_permission_denied"],
                "analytic_name": "Tool Permission Denied",
                "analytic_type_id": 1,
                "description": "PermissionInterruptRail denied the tool call to bash",
                "evidence": {"risk_source": "PermissionInterruptRail", "decision": "reject"},
                "module_name": "security_rail_detection",
                "aux_ids": {
                    "trace_id": f"trace-{risk_level}",
                    "session_id": "s1",
                    "interaction_seq": 0,
                    "agent_id": "a1",
                    "llm_call_seq": 0,
                    "tool_call_seq": 0,
                },
                "event_node": {
                    "event_type": "permission_interrupt_tool",
                    "action_name": "bash",
                    "deny_reason": "policy_deny" if risk_level == "medium" else "user_reject",
                },
                "timestamp": 1715000000.0,
            }
            await presentation.render(report)
            output_dir = Path(ssas_config.storage_path) / "reports" / "threat_log"
            files = list(output_dir.glob(f"threat_trace-{risk_level}_*.json"))
            assert len(files) == 1
            with open(files[0], "r", encoding="utf-8") as f:
                ocsf = json.load(f)
            assert ocsf["severity_id"] == expected_severity_id
            assert ocsf["finding_info"]["analytic"]["name"] == "Tool Permission Denied"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_build_ocsf_report_no_risk(ssas_config: AgentSSASConfig) -> None:
        """验证 build_ocsf_report 构建无风险报告。"""
        report = {
            "has_risk": False,
            "risk_level": "safe",
            "module_name": "test_detection",
            "analytic_name": "Pass Through Scan",
            "analytic_type_id": 1,
            "description": "No risk detected",
            "aux_ids": {"trace_id": "trace-safe", "agent_id": "a1"},
            "event_node": {"event_type": "tool_input"},
            "timestamp": 1715000000.0,
        }
        ocsf = build_ocsf_report(report)
        # status 固定为 OCSF 标准 finding 生命周期状态 New (1)
        assert ocsf["status"] == "New"
        assert ocsf["status_id"] == 1
        assert ocsf["severity_id"] == 1  # safe -> 1
        assert ocsf["class_uid"] == 2004
        # 无 risk_type 时 types 为空列表
        assert ocsf["finding_info"]["types"] == []
        # 顶层 evidences 数组存在(即使无风险也有 data)
        assert isinstance(ocsf["evidences"], list)
        assert len(ocsf["evidences"]) == 1
        # 无 detected_threats 和 recommended_actions 时 data 不含这两个字段
        assert "detected_threats" not in ocsf["evidences"][0]["data"]
        assert "recommended_actions" not in ocsf["evidences"][0]["data"]
        # analytic 对象
        assert ocsf["finding_info"]["analytic"]["name"] == "Pass Through Scan"
        assert ocsf["finding_info"]["analytic"]["type_id"] == 1
        # 无 resources 字段
        assert "resources" not in ocsf

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_build_ocsf_report_sanitizes_non_dict_evidence() -> None:
        """验证非 dict 类型 evidence 被忽略(不影响 evidences 数组结构)。"""
        report = {
            "has_risk": False,
            "risk_level": "safe",
            "module_name": "test_detection",
            "aux_ids": {"trace_id": "trace-x"},
            "event_node": {},
            "evidence": "not a dict",
        }
        ocsf = build_ocsf_report(report)
        # 非 dict evidence 被忽略,evidences 数组仍正常构造
        assert isinstance(ocsf["evidences"], list)
        assert len(ocsf["evidences"]) == 1
        # 无 detected_threats 和 recommended_actions 时 data 不含这两个字段
        assert "detected_threats" not in ocsf["evidences"][0]["data"]
        assert "recommended_actions" not in ocsf["evidences"][0]["data"]
        # finding_info 不再有 evidence 字段
        assert "evidence" not in ocsf["finding_info"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_render_no_risk_status_info(ssas_config: AgentSSASConfig) -> None:
        """验证无风险报告 status 固定为 New(OCSF finding 生命周期状态)。"""
        presentation = AgentSSASThreatLog(ssas_config)
        report = {
            "has_risk": False,
            "risk_level": "safe",
            "module_name": "test_detection",
            "analytic_name": "Pass Through Scan",
            "analytic_type_id": 1,
            "aux_ids": {"trace_id": "trace-2"},
            "event_node": {"event_type": "tool_input"},
            "timestamp": 0.0,
        }
        await presentation.render(report)
        output_dir = Path(ssas_config.storage_path) / "reports" / "threat_log"
        files = list(output_dir.glob("threat_trace-2_*.json"))
        assert len(files) == 1
        with open(files[0], "r", encoding="utf-8") as f:
            ocsf = json.load(f)
        # status 固定为 OCSF 标准 finding 生命周期状态 New (1)
        assert ocsf["status"] == "New"
        assert ocsf["severity_id"] == 1  # safe -> 1
        assert ocsf["status_id"] == 1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_render_invalid_report_type(ssas_config: AgentSSASConfig) -> None:
        """验证传入非 dict 时抛出 TypeError。"""
        presentation = AgentSSASThreatLog(ssas_config)
        with pytest.raises(TypeError):
            await presentation.render("not a dict")  # type: ignore[arg-type]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_render_empty_report(ssas_config: AgentSSASConfig) -> None:
        """验证传入空 dict 时抛出 ValueError。"""
        presentation = AgentSSASThreatLog(ssas_config)
        with pytest.raises(ValueError):
            await presentation.render({})


class TestThreatLogCleanup:
    """威胁报告文件 TTL 清理(P2 修复)。"""

    @staticmethod
    def _make_log_with_files(
        ssas_config: AgentSSASConfig,
    ) -> tuple[AgentSSASThreatLog, Path]:
        """构造威胁日志实例,并预置 3 个测试文件。

        文件命名与 threat_log.py 渲染生成的格式一致
        (threat_{trace}_{module}_{YYYYMMDD_HHMMSS}_{mmm}.json):
        - expired_*: 时间戳为 91 天前(过期)
        - fresh_*: 时间戳为 1 天前(未过期)
        - legacy.json: 文件名无时间戳(回退 mtime,当前时间)
        """
        import time
        from datetime import datetime, timedelta

        presentation = AgentSSASThreatLog(ssas_config)
        output_dir = Path(ssas_config.storage_path) / "reports" / "threat_log"

        now = time.time()
        expired_dt = datetime.fromtimestamp(now) - timedelta(days=91)  # noqa: DTZ006
        fresh_dt = datetime.fromtimestamp(now) - timedelta(days=1)  # noqa: DTZ006
        expired_name = (
            f"threat_trace-x_mod_{expired_dt.strftime('%Y%m%d_%H%M%S')}_001.json"
        )
        fresh_name = (
            f"threat_trace-y_mod_{fresh_dt.strftime('%Y%m%d_%H%M%S')}_002.json"
        )
        (output_dir / expired_name).write_text("{}", encoding="utf-8")
        (output_dir / fresh_name).write_text("{}", encoding="utf-8")
        # 非标准命名(无时间戳):回退 mtime 判定
        (output_dir / "legacy.json").write_text("{}", encoding="utf-8")
        return presentation, output_dir

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_deletes_only_expired_files(
        ssas_config: AgentSSASConfig,
    ) -> None:
        """验证清理仅删除过期文件,未过期与 mtime 回退的文件保留。"""
        presentation, output_dir = TestThreatLogCleanup._make_log_with_files(
            ssas_config
        )
        expired_files = list(output_dir.glob("threat_trace-x_mod_*.json"))
        fresh_files = list(output_dir.glob("threat_trace-y_mod_*.json"))
        assert len(expired_files) == 1
        assert len(fresh_files) == 1

        deleted = await presentation.cleanup_expired(90)
        # 仅过期文件被删,返回删除数 1
        assert deleted == 1
        assert not expired_files[0].exists()
        # 未过期文件与 mtime 回退文件保留
        assert fresh_files[0].exists()
        assert (output_dir / "legacy.json").exists()

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_ttl_zero_disabled(
        ssas_config: AgentSSASConfig,
    ) -> None:
        """验证 ttl<=0 时禁用清理(不删除任何文件)。"""
        presentation, output_dir = TestThreatLogCleanup._make_log_with_files(
            ssas_config
        )
        before = {p.name for p in output_dir.glob("*.json")}
        assert len(before) == 3

        deleted = await presentation.cleanup_expired(0)
        assert deleted == 0
        deleted = await presentation.cleanup_expired(-1)
        assert deleted == 0
        after = {p.name for p in output_dir.glob("*.json")}
        assert after == before

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_legacy_file_by_mtime(
        ssas_config: AgentSSASConfig,
    ) -> None:
        """验证文件名无时间戳的文件按 mtime 判定过期。"""
        import os
        import time

        presentation = AgentSSASThreatLog(ssas_config)
        output_dir = Path(ssas_config.storage_path) / "reports" / "threat_log"
        legacy_path = output_dir / "legacy.json"
        legacy_path.write_text("{}", encoding="utf-8")
        # 将 mtime 置为 91 天前(Windows 下 utime 支持设置过去时间)
        old_ts = time.time() - 91 * 86400
        os.utime(legacy_path, (old_ts, old_ts))

        deleted = await presentation.cleanup_expired(90)
        assert deleted == 1
        assert not legacy_path.exists()

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_delete_failure_skipped_no_raise(
        ssas_config: AgentSSASConfig,
    ) -> None:
        """验证单个文件删除失败时记日志跳过,不抛异常。"""
        from unittest.mock import patch

        presentation, output_dir = TestThreatLogCleanup._make_log_with_files(
            ssas_config
        )
        expired_files = list(output_dir.glob("threat_trace-x_mod_*.json"))
        assert len(expired_files) == 1

        # 模拟删除失败(Windows 句柄占用等场景抛 PermissionError,属 OSError)
        with patch.object(
            Path,
            "unlink",
            side_effect=PermissionError("file in use"),
        ):
            deleted = await presentation.cleanup_expired(90)
        # 删除失败:返回 0,不抛异常(记日志跳过)
        assert deleted == 0
        # 文件仍在(清理被跳过)
        assert expired_files[0].exists()
