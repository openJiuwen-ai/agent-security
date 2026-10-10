# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""安全护栏检测模块单元测试。

验证 SecurityRailAnalyzer 处理安全检测事件、跳过非安全检测事件。
"""

from __future__ import annotations

import pytest

from agent_ssas.core.detection_modules.security_rail_detection.security_rail_analyzer import (
    SecurityRailAnalyzer,
)


class TestSecurityRailDetection:
    """安全护栏检测模块。"""

    @staticmethod
    def _make_security_event_desc(
        risk_type: str = "tool_permission_denied",
        risk_level: str = "medium",
        risk_source: str = "PermissionInterruptRail",
        evidence: dict | None = None,
        deny_reason: str = "policy_deny",
    ) -> dict:
        """构造安全检测事件的事件描述 json。

        event_node 中包含 event_class="security" 及风险字段,
        结构与 _node_to_dict 输出对齐(tool_call_id 等溯源字段齐全)。
        默认值对应策略 deny 场景(medium / policy_deny)。
        """
        if evidence is None:
            evidence = {
                "tool_name": "bash",
                "tool_call_id": "call-001",
                "reason": "denied",
            }
        return {
            "event_node": {
                "event_type": "permission_interrupt_tool",
                "event_class": "security",
                "action_name": "bash",
                "tool_call_id": "call-001",
                "risk_source": risk_source,
                "risk_type": risk_type,
                "risk_level": risk_level,
                "deny_reason": deny_reason,
                "risk_assessment": {
                    "decision": "reject",
                    "evidence": evidence,
                },
            },
            "aux_ids": {
                "trace_id": "t1",
                "session_id": "s1",
                "interaction_seq": 0,
                "tool_call_id": "call-001",
            },
        }

    @staticmethod
    def _make_lifecycle_event_desc() -> dict:
        """构造生命周期事件的事件描述 json。"""
        return {
            "event_node": {
                "event_type": "tool_input",
                "event_class": "lifecycle",
                "action_name": "bash",
            },
            "aux_ids": {"trace_id": "t1"},
        }

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_handles_security_event() -> None:
        """验证 SecurityRailAnalyzer 处理安全检测事件(策略 deny 场景),输出风险报告。"""
        analyzer = SecurityRailAnalyzer()
        event_desc = TestSecurityRailDetection._make_security_event_desc()
        report = await analyzer.analyze(event_desc)
        assert report["has_risk"] is True
        assert report["risk_level"] == "medium"
        assert report["risk_type"] == "tool_permission_denied"
        assert report["risk_score"] == 50.0  # medium -> 50
        assert report["detected_threats"] == ["tool_permission_denied"]
        assert report["module_name"] == "security_rail_detection"
        assert report["analytic_name"] == "Tool Permission Denied"
        assert report["description"] == (
            "PermissionInterruptRail denied the tool call to bash (policy deny)"
        )
        # evidence 为自定义字段,包含 risk_source 和 decision(见 9.4.2 节)
        assert report["evidence"]["risk_source"] == "PermissionInterruptRail"
        assert report["evidence"]["decision"] == "reject"
        # 证据明细(tool_name/tool_call_id/reason)来自 risk_assessment.evidence
        assert report["evidence"]["tool_name"] == "bash"
        assert report["evidence"]["tool_call_id"] == "call-001"
        assert report["evidence"]["reason"] == "denied"
        # 风险报告按场景产出推荐处置动作(策略 deny:记录并告警)
        assert report["recommended_actions"] == ["log", "alert"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_user_reject_scene() -> None:
        """验证 ask 用户拒绝场景(low / user_reject)的文案与分数。"""
        analyzer = SecurityRailAnalyzer()
        event_desc = TestSecurityRailDetection._make_security_event_desc(
            risk_level="low",
            deny_reason="user_reject",
        )
        report = await analyzer.analyze(event_desc)
        assert report["has_risk"] is True
        assert report["risk_level"] == "low"
        assert report["risk_score"] == 25.0  # low -> 25
        assert report["analytic_name"] == "Tool Permission Rejected"
        assert report["description"] == "User rejected the tool call to bash"
        # 用户主动拒绝:仅记录,不告警
        assert report["recommended_actions"] == ["log"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_unknown_scene_keeps_default_text() -> None:
        """验证 deny_reason 缺省(unknown)时保持现有文案。"""
        analyzer = SecurityRailAnalyzer()
        event_desc = TestSecurityRailDetection._make_security_event_desc(
            risk_level="medium",
            deny_reason="unknown",
        )
        report = await analyzer.analyze(event_desc)
        assert report["has_risk"] is True
        assert report["risk_level"] == "medium"
        assert report["risk_score"] == 50.0  # medium -> 50
        assert report["analytic_name"] == "Tool Permission Denied"
        assert report["description"] == "PermissionInterruptRail denied the tool call to bash"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_skips_lifecycle_event() -> None:
        """验证 SecurityRailAnalyzer 跳过非安全检测事件(lifecycle)。"""
        analyzer = SecurityRailAnalyzer()
        event_desc = TestSecurityRailDetection._make_lifecycle_event_desc()
        report = await analyzer.analyze(event_desc)
        assert report["has_risk"] is False
        assert report["risk_level"] == "safe"
        # 跳过报告保持 recommended_actions 为空列表
        assert report["recommended_actions"] == []

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_handles_non_dict_input() -> None:
        """验证传入非 dict 时返回无风险报告。"""
        analyzer = SecurityRailAnalyzer()
        report = await analyzer.analyze("not a dict")  # type: ignore[arg-type]
        assert report["has_risk"] is False

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_analyzer_evidence_from_risk_assessment() -> None:
        """验证 evidence 包含 risk_source 和 decision(来自 risk_assessment)。"""
        analyzer = SecurityRailAnalyzer()
        event_desc = TestSecurityRailDetection._make_security_event_desc(
            evidence={"detail": "tool not allowed"}
        )
        report = await analyzer.analyze(event_desc)
        # evidence 为自定义字段,包含 risk_source 和 decision(见 9.4.2 节)
        # decision 优先从 risk_assessment 中获取
        assert report["evidence"]["risk_source"] == "PermissionInterruptRail"
        assert report["evidence"]["decision"] == "reject"
        # 明细缺失字段回退 event_node(tool_name 取 action_name)
        assert report["evidence"]["tool_name"] == "bash"
        # 明细不含 tool_call_id/reason 时不出空值字段
        assert "reason" not in report["evidence"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_level_to_score_mapping() -> None:
        """验证 _level_to_score 风险等级到分数的映射。"""
        assert SecurityRailAnalyzer._level_to_score("safe") == 0.0  # pylint: disable=protected-access
        assert SecurityRailAnalyzer._level_to_score("low") == 25.0  # pylint: disable=protected-access
        assert SecurityRailAnalyzer._level_to_score("medium") == 50.0  # pylint: disable=protected-access
        assert SecurityRailAnalyzer._level_to_score("high") == 75.0  # pylint: disable=protected-access
        assert SecurityRailAnalyzer._level_to_score("critical") == 100.0  # pylint: disable=protected-access
        # 未知等级回退 50.0
        assert SecurityRailAnalyzer._level_to_score("unknown") == 50.0  # pylint: disable=protected-access
