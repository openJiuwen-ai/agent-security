# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""IDManager - 生成和管理 interaction_seq、llm_call_seq、tool_call_seq 等标识字段。"""

from __future__ import annotations

import logging
from collections import OrderedDict
from threading import Lock

from openjiuwen.core.single_agent.rail.base import (
    AgentCallbackContext,
    AgentCallbackEvent,
)

logger = logging.getLogger(__name__)


class IDManager:
    """ID 管理模块。

    生成和管理交互标识(int 类型自增序号)及各类会话/Agent/Trace 标识。

    interaction_seq、llm_call_seq、tool_call_seq:均使用 session 级 LRU 池
    存储(跨层共享),因为 agent-core 中 DeepAgent 外层与 ReActAgent 内层
    各自创建独立的 AgentCallbackContext 实例,ctx.extra 不跨层共享。
    - interaction_seq:BEFORE_INVOKE 时自增,其余事件复用当前值。
    - llm_call_seq:BEFORE_MODEL_CALL 时自增,其余事件(含 tool_call)读取
      当前值(session 内最近一次 model call 的序号),session 无记录时 -1。
    - tool_call_seq:BEFORE_TOOL_CALL 时自增,其余事件读取当前值,
      session 无记录时 -1。

    同时将序号镜像写回 ctx.extra(便于同 ctx 内其他组件读取,并保持
    兼容旧断言);分配与读取的权威来源始终是 LRU 池,并保证与
    ctx.extra 已有有效值的一致性:
    - 读取(非自增事件)时,若 ctx.extra 已有有效序号(>= 0)则优先
      返回该值(兼容同 ctx 内其他组件已写入的场景),否则读池;
    - 自增时以 max(池内当前值, ctx.extra 已有有效值)为基准递增,
      避免 ctx.extra 已有更大序号时被池内旧值覆盖(如池 LRU 淘汰后
      session 又被访问的场景)。

    LRU 池防止 session 无限增长导致内存泄漏。
    后续版本将基于 session_end 事件实现精确生命周期管理。
    """

    # LRU 池最大 session 数
    _MAX_SESSIONS = 100

    # session 无记录时的未知序号哨兵值
    _SEQ_UNKNOWN = -1

    def __init__(self):
        # session_id → interaction_seq 的 LRU 池
        # OrderedDict 实现 LRU:最近访问的在末尾,满了从头部淘汰
        self._session_interaction_seqs: OrderedDict[str, int] = OrderedDict()
        # session_id → llm_call_seq 的 LRU 池(语义:session 内第几次 LLM 调用)
        self._session_llm_call_seqs: OrderedDict[str, int] = OrderedDict()
        # session_id → tool_call_seq 的 LRU 池(语义:session 内第几次工具调用)
        self._session_tool_call_seqs: OrderedDict[str, int] = OrderedDict()
        self._lock = Lock()

    # ------------------------------------------------------------------
    # 通用 LRU 序号池操作(读 / 自增),三个序号池共用同一套逻辑
    # ------------------------------------------------------------------

    def _get_seq_from_pool(self, pool: OrderedDict[str, int], session_id: str) -> int:
        """从 LRU 池读取当前序号(只读,更新 LRU 顺序,不创建条目)。

        session 无记录时返回 -1(未知),不向池内写入,避免把"未知"
        固化为初始计数。
        """
        key = session_id if session_id else "__no_session__"
        with self._lock:
            if key in pool:
                # 已存在,移到末尾(LRU 最近使用)
                seq = pool.pop(key)
                pool[key] = seq
                return seq
            return self._SEQ_UNKNOWN

    # ------------------------------------------------------------------
    # interaction_seq(session 级,LRU 池)
    # ------------------------------------------------------------------

    def _get_interaction_seq_from_pool(self, session_id: str) -> int:
        """从 LRU 池获取 interaction_seq(只读,更新 LRU 顺序)。

        与 interaction 池的既有语义不同:session 首次出现即视为 0 号
        交互进行中(自动节点生成依赖此行为),因此无记录时创建并返回 -1
        供调用方(ensure_interaction_seq 的非自增分支)兼容旧语义。
        """
        key = session_id if session_id else "__no_session__"
        with self._lock:
            if key in self._session_interaction_seqs:
                # 已存在,移到末尾(LRU 最近使用)
                seq = self._session_interaction_seqs.pop(key)
                self._session_interaction_seqs[key] = seq
                return seq
            # 新 session,检查池是否已满
            if len(self._session_interaction_seqs) >= self._MAX_SESSIONS:
                # LRU 淘汰:弹出最久未使用的(头部)
                evicted_key, _ = self._session_interaction_seqs.popitem(last=False)
                logger.info("LRU 淘汰 session: %s", evicted_key)
            # 创建新 session 的 interaction_seq,初始值 -1
            self._session_interaction_seqs[key] = -1
            return -1

    def _increment_interaction_seq_in_pool(self, session_id: str) -> int:
        """在 LRU 池中自增 interaction_seq 并返回新值(原子操作)。

        单次加锁完成读-改-写,避免并发竞态。
        """
        key = session_id if session_id else "__no_session__"
        with self._lock:
            if key in self._session_interaction_seqs:
                # 已存在,移到末尾(LRU 最近使用)并自增
                seq = self._session_interaction_seqs.pop(key)
                seq += 1
                self._session_interaction_seqs[key] = seq
                return seq
            # 新 session,检查池是否已满
            if len(self._session_interaction_seqs) >= self._MAX_SESSIONS:
                evicted_key, _ = self._session_interaction_seqs.popitem(last=False)
                logger.info("LRU 淘汰 session: %s", evicted_key)
            # 创建新 session,初始值 -1,自增后为 0
            self._session_interaction_seqs[key] = 0
            return 0

    def ensure_interaction_seq(self, ctx: AgentCallbackContext, event: AgentCallbackEvent = None) -> int:
        """获取或生成 interaction_seq(session 级,BEFORE_INVOKE 时自增)。

        使用 session 级 LRU 池存储,跨 DeepAgent/ReActAgent 层共享。
        初始值为 -1,BEFORE_INVOKE 时先自增再使用。
        后续事件复用同一序号(从 LRU 池读取当前值)。
        """
        session_id = self.resolve_session_id(ctx)
        if event is not None and event != AgentCallbackEvent.BEFORE_INVOKE:
            # 非 BEFORE_INVOKE:从 LRU 池复用当前值
            return self._get_interaction_seq_from_pool(session_id)
        # BEFORE_INVOKE 或未指定事件:原子自增
        return self._increment_interaction_seq_in_pool(session_id)

    # ------------------------------------------------------------------
    # llm_call_seq / tool_call_seq(session 级,LRU 池)
    # ------------------------------------------------------------------

    @staticmethod
    def _extra_seq(ctx: AgentCallbackContext, key: str) -> int:
        """读取 ctx.extra 中已缓存的序号,无效或缺键时返回 -1。"""
        value = ctx.extra.get(key, -1)
        if isinstance(value, int) and value >= 0:
            return value
        return -1

    def _bump_seq_in_pool(
        self, pool: OrderedDict[str, int], session_id: str, floor: int
    ) -> int:
        """以 max(池内当前值, floor) 为基准在池中自增并返回新值。

        floor 取自 ctx.extra 已有有效序号,保证与 ctx.extra 值的一致性
        (如池 LRU 淘汰后 session 又被访问时,不回退到更小的序号)。
        """
        key = session_id if session_id else "__no_session__"
        with self._lock:
            current = pool.pop(key, -1)
            seq = max(current, floor) + 1
            if len(pool) >= self._MAX_SESSIONS:
                # LRU 淘汰:弹出最久未使用的(头部)
                evicted_key, _ = pool.popitem(last=False)
                logger.info("LRU 淘汰 session: %s", evicted_key)
            pool[key] = seq
            return seq

    def _ensure_llm_call_seq_from_pool(
        self, ctx: AgentCallbackContext, event: AgentCallbackEvent
    ) -> int:
        """llm_call_seq 的池化分配(权威来源为 session 级 LRU 池)。

        语义:session 内第几次 LLM 调用。分层 ctx(BEFORE_MODEL_CALL 事件
        与 tool 事件分属不同 AgentCallbackContext,ctx.extra 不跨层共享)
        下,池按 session_id 跨层共享计数:
        - BEFORE_MODEL_CALL:以 max(池内当前值, ctx.extra 已有有效值)
          为基准自增并返回新值;
        - 其他事件(含 BEFORE/AFTER_TOOL_CALL):优先返回 ctx.extra 已有
          有效序号,否则读池内当前计数(最近一次 model call 的序号),
          不自增;
        - 均无记录:返回 -1(未知)。

        分配出的序号同步镜像写回 ctx.extra,便于同 ctx 内其他组件读取。
        """
        session_id = self.resolve_session_id(ctx)
        extra_seq = self._extra_seq(ctx, "llm_call_seq")
        if event == AgentCallbackEvent.BEFORE_MODEL_CALL:
            seq = self._bump_seq_in_pool(
                self._session_llm_call_seqs, session_id, extra_seq
            )
        elif extra_seq != self._SEQ_UNKNOWN:
            # ctx.extra 已有有效序号(如同 ctx 内其他组件写入),优先复用
            seq = extra_seq
        else:
            seq = self._get_seq_from_pool(self._session_llm_call_seqs, session_id)
        if seq != self._SEQ_UNKNOWN:
            ctx.extra["llm_call_seq"] = seq
        return seq

    def _ensure_tool_call_seq_from_pool(
        self, ctx: AgentCallbackContext, event: AgentCallbackEvent
    ) -> int:
        """tool_call_seq 的池化分配(权威来源为 session 级 LRU 池)。

        语义:session 内第几次工具调用。与 llm_call_seq 同理,分层 ctx 下
        tool 事件所在 ctx 缺键时旧实现会从 -1 自增为 0(序号恒为 0,
        多次工具调用无法区分),改为 session 级池:
        - BEFORE_TOOL_CALL:以 max(池内当前值, ctx.extra 已有有效值)
          为基准自增并返回新值;
        - 其他事件(AFTER_TOOL_CALL 等):优先返回 ctx.extra 已有有效
          序号,否则读池内当前计数,不自增;
        - 均无记录:返回 -1(未知)。

        分配出的序号同步镜像写回 ctx.extra,便于同 ctx 内其他组件读取。
        """
        session_id = self.resolve_session_id(ctx)
        extra_seq = self._extra_seq(ctx, "tool_call_seq")
        if event == AgentCallbackEvent.BEFORE_TOOL_CALL:
            seq = self._bump_seq_in_pool(
                self._session_tool_call_seqs, session_id, extra_seq
            )
        elif extra_seq != self._SEQ_UNKNOWN:
            # ctx.extra 已有有效序号(如同一工具调用的 BEFORE 事件写入),优先复用
            seq = extra_seq
        else:
            seq = self._get_seq_from_pool(self._session_tool_call_seqs, session_id)
        if seq != self._SEQ_UNKNOWN:
            ctx.extra["tool_call_seq"] = seq
        return seq

    def ensure_llm_call_seq(self, ctx: AgentCallbackContext, event: AgentCallbackEvent) -> int:
        """获取或生成 llm_call_seq(session 级 LRU 池分配)。

        保持既有签名,内部委托 _ensure_llm_call_seq_from_pool:
        BEFORE_MODEL_CALL 自增,其余事件读池(session 无记录为 -1)。
        """
        return self._ensure_llm_call_seq_from_pool(ctx, event)

    def ensure_tool_call_seq(self, ctx: AgentCallbackContext, event: AgentCallbackEvent) -> int:
        """获取或生成 tool_call_seq(session 级 LRU 池分配)。

        保持既有签名,内部委托 _ensure_tool_call_seq_from_pool:
        BEFORE_TOOL_CALL 自增,其余事件读池(session 无记录为 -1)。
        """
        return self._ensure_tool_call_seq_from_pool(ctx, event)

    @staticmethod
    def resolve_subsession_id(ctx: AgentCallbackContext) -> str:
        """获取 subsession_id(子 Agent 场景的父会话 ID)。

        子 Agent 场景下,子 Agent 的 parent_session_id 写入 subsession_id,
        session_id 用子 Agent 自己的 session_id。非子 Agent 场景为空字符串。
        """
        try:
            return getattr(ctx.inputs, "parent_session_id", "") or ""
        except Exception:
            logger.debug("解析 subsession_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_conversation_id(ctx: AgentCallbackContext, event: AgentCallbackEvent) -> str:
        """获取 conversation_id,优先从 inputs 取,回退到 extra 缓存。"""
        cid = getattr(ctx.inputs, "conversation_id", None)
        if cid:
            ctx.extra["conversation_id"] = cid
            return cid
        return ctx.extra.get("conversation_id", "")

    @staticmethod
    def resolve_session_id(ctx: AgentCallbackContext) -> str:
        """获取 session_id,无 session 时返回空字符串。"""
        try:
            return ctx.session.get_session_id() if ctx.session else ""
        except Exception:
            logger.debug("解析 session_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_agent_id(ctx: AgentCallbackContext) -> str:
        """获取 agent_id,无 agent 时返回空字符串。"""
        try:
            return ctx.agent.card.id if ctx.agent and ctx.agent.card else ""
        except Exception:
            logger.debug("解析 agent_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_trace_id(ctx: AgentCallbackContext) -> str:
        """获取 trace_id,无 session 时返回空字符串。"""
        try:
            # 访问 openjiuwen Session 内部链路获取 trace_id,外部库无公开 API,
            # 异常时 fail-open 返回空字符串,故豁免受保护成员检查
            return (
                ctx.session._inner._tracer._trace_id  # pylint: disable=protected-access
                if ctx.session
                else ""
            )
        except Exception:
            logger.debug("解析 trace_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_context_id(ctx: AgentCallbackContext) -> str:
        """获取 context_id,无 context 时返回空字符串。"""
        try:
            return ctx.context.context_id() if ctx.context else ""
        except Exception:
            logger.debug("解析 context_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_tool_name(ctx: AgentCallbackContext, event: AgentCallbackEvent) -> str:
        """获取 tool_name,仅 TOOL 事件有值。"""
        try:
            if event in (AgentCallbackEvent.BEFORE_TOOL_CALL,
                         AgentCallbackEvent.AFTER_TOOL_CALL):
                return getattr(ctx.inputs, "tool_name", "")
            return ""
        except Exception:
            logger.debug("解析 tool_name 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def resolve_tool_call_id(tool_call) -> str:
        """获取 tool_call_id。

        基类 BaseSecurityRail 中已存在此方法(用于 _resolve_subject_id),
        此处保持一致签名与行为,供 _run_and_apply 显式调用填充 security_ctx。
        """
        try:
            return tool_call.id if tool_call else ""
        except Exception:
            logger.debug("解析 tool_call_id 失败, 返回空字符串", exc_info=True)
            return ""

    @staticmethod
    def event_class_for(event: AgentCallbackEvent, event_type: str) -> str:
        """根据 event_type 判断事件类别。

        安全检测事件(如 permission_interrupt_tool)返回 "security",
        生命周期事件返回 "lifecycle"。
        """
        if event_type == "permission_interrupt_tool":
            return "security"
        return "lifecycle"
