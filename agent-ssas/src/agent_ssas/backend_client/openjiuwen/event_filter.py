# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""EventFilter - 事件过滤模块,针对事件类型和不同策略进行过滤。"""

from __future__ import annotations

from typing import Any

from openjiuwen.core.single_agent.rail.base import AgentCallbackEvent

from agent_ssas.backend_client.openjiuwen.extended_context import (
    ExtendedSecurityCheckContext,
)


class EventFilter:
    """事件过滤模块。

    输入:构建模块产出的 raw_event(三层结构 dict)
    输出:过滤后的 raw_event(可能被修改了 event_type 和 payload)或 None(被过滤掉)

    过滤策略:
    1. 生命周期事件:全通过(上报给 AgentSSAS)
    2. SafetyPromptRail 相关:不产生安全检测事件(始终返回 Allow,无安全检测输出)
    3. PermissionInterruptRail:当 ctx.extra["_skip_tool"] 为 True 时才生成安全检测事件
    4. 未来扩展...
    """

    def filter_event(
        self, event_dict: dict[str, Any], security_ctx: ExtendedSecurityCheckContext
    ) -> dict[str, Any] | None:
        """事件过滤模块:针对事件类型和不同策略进行过滤。"""
        ctx = security_ctx.callback_ctx
        event = security_ctx.event

        # PermissionInterruptRail deny 检测:仅 BEFORE_TOOL_CALL 事件
        if event == AgentCallbackEvent.BEFORE_TOOL_CALL:
            skip_tool = ctx.extra.get("_skip_tool", False)
            if skip_tool:
                # PermissionInterruptRail deny → 生成安全检测事件字段
                risk_event = self._build_risk_fields(security_ctx)
                event_dict["payload"].update(risk_event)
                event_dict["common"]["event_type"] = "permission_interrupt_tool"
                event_dict["common"]["event_class"] = "security"
                return event_dict

        # 生命周期事件:全通过
        # SafetyPromptRail 相关(BEFORE_MODEL_CALL):
        #   始终返回 Allow 且无安全检测输出,不产生安全检测事件,
        #   但 BEFORE_MODEL_CALL 本身作为生命周期事件仍然通过。
        return event_dict

    @staticmethod
    def _build_risk_fields(security_ctx: ExtendedSecurityCheckContext) -> dict[str, Any]:
        """生成 PermissionInterruptRail deny 的安全检测事件字段(场景化风险等级)。

        通过 ctx.extra["_interrupt_decision"] 中 PermissionInterruptRail 写入的
        原始 RejectResult 区分拒绝场景(AgentSSASSecurityRail 覆写该键发生在
        EventFilter 执行之后,此处读到的仍是原始决策):
        - 策略 deny(tool_result 以 "[PERMISSION_DENIED]" 开头)→ medium / policy_deny
        - 用户在 ask 模式下拒绝(其他 RejectResult)→ low / user_reject
        - 决策缺失或无法读取(保守回退)→ medium / unknown
        """
        deny_reason, risk_level = EventFilter._classify_deny_scene(security_ctx)
        return {
            "risk_source": "PermissionInterruptRail",
            "risk_type": "tool_permission_denied",
            "risk_level": risk_level,
            "deny_reason": deny_reason,
            "decision": "reject",
            "evidence": {
                "tool_name": security_ctx.tool_name,
                "tool_call_id": security_ctx.tool_call_id,
                "reason": "PermissionInterruptRail denied the tool call",
            },
        }

    @staticmethod
    def _classify_deny_scene(
        security_ctx: ExtendedSecurityCheckContext,
    ) -> tuple[str, str]:
        """根据原始 RejectResult 判定拒绝场景,返回 (deny_reason, risk_level)。"""
        decision = security_ctx.callback_ctx.extra.get("_interrupt_decision")
        tool_result = getattr(decision, "result", None)
        if tool_result is None:
            # 决策缺失或 RejectResult 无 result:保守回退 medium
            return "unknown", "medium"
        tool_result_text = tool_result if isinstance(tool_result, str) else str(tool_result)
        if tool_result_text.startswith("[PERMISSION_DENIED]"):
            # PermissionInterruptRail 策略 deny 路径的固定前缀
            return "policy_deny", "medium"
        # 存在 RejectResult 但非策略 deny 前缀:ask 模式下用户拒绝
        return "user_reject", "low"
