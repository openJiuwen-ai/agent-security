# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""AgentSSAS 内存存储(测试用)。

MemoryStore 实现 StoragePlugin 接口的所有方法,数据存储在内存中。
主要用于单元测试和开发调试,避免磁盘 I/O 和数据库依赖。
"""

from __future__ import annotations

import asyncio
import time
from collections import deque

from agent_ssas.core.framework.utils.id_utils import new_uuid

# 允许执行 TTL 清理的表名白名单(与 SQLiteStore._CLEANUP_TABLES 对齐)
_CLEANUP_TABLES: frozenset[str] = frozenset({"events", "alerts", "raw_events"})


def _ts_of(record: dict) -> float:
    """取记录顶层 timestamp 字段,无效/缺失时返回 0.0。"""
    ts = record.get("timestamp", 0.0)
    return ts if isinstance(ts, (int, float)) else 0.0


def _raw_event_ts(record: dict) -> float:
    """取 raw_event 的 common.timestamp,无效/缺失时返回 0.0。"""
    common = record.get("common")
    if not isinstance(common, dict):
        return 0.0
    ts = common.get("timestamp", 0.0)
    return ts if isinstance(ts, (int, float)) else 0.0


class MemoryStore:
    """内存存储,实现 StoragePlugin 接口。

    数据存储在内存列表中,进程结束后数据丢失。
    所有方法均为异步,通过 asyncio.Lock 保证线程安全。
    适用于单元测试、开发调试等不要求持久化的场景。

    实现的方法与 SQLiteStore 对齐,包括 record_event、create_alert、
    get_events、get_alerts、cleanup_expired、close、record_raw_event、
    get_events_by_trace_id。
    """

    def __init__(self) -> None:
        """初始化内存存储。

        创建事件列表、告警列表和异步锁。
        """
        self._events: deque[dict] = deque()
        self._alerts: deque[dict] = deque()
        self._raw_events: deque[dict] = deque()
        self._lock = asyncio.Lock()

    async def record_event(self, event: dict) -> str:
        """异步写入一条事件记录,返回 event_id。

        Args:
            event: 事件 dict,应包含 event_id 等字段。

        Returns:
            事件唯一标识 event_id。

        Raises:
            TypeError: event 不是 dict 类型时。
            ValueError: event 为空 dict 时。
        """
        if not isinstance(event, dict):
            raise TypeError(f"event 必须为 dict,实际类型: {type(event).__name__}")
        if not event:
            raise ValueError("event 不能为空 dict")

        record = dict(event)
        event_id = record.get("event_id")
        if not event_id:
            event_id = new_uuid()
            record["event_id"] = event_id

        async with self._lock:
            self._events.append(record)
        return event_id

    async def record_raw_event(self, raw_event: dict) -> str:
        """异步持久化 raw_event(原始事件),返回 raw_event_id。

        Args:
            raw_event: 原始事件 dict,包含 common、payload、metadata 三层。

        Returns:
            原始事件唯一标识 raw_event_id。

        Raises:
            TypeError: raw_event 不是 dict 类型时。
            ValueError: raw_event 为空 dict 时。
        """
        if not isinstance(raw_event, dict):
            raise TypeError(
                f"raw_event 必须为 dict,实际类型: {type(raw_event).__name__}"
            )
        if not raw_event:
            raise ValueError("raw_event 不能为空 dict")

        record = dict(raw_event)
        raw_event_id = record.get("raw_event_id")
        if not raw_event_id:
            common = record.get("common")
            if isinstance(common, dict):
                raw_event_id = common.get("raw_event_id")
        if not raw_event_id:
            raw_event_id = new_uuid()
            record["raw_event_id"] = raw_event_id

        async with self._lock:
            self._raw_events.append(record)
        return raw_event_id

    async def create_alert(self, alert: dict) -> str:
        """异步写入一条告警记录,返回 alert_id。

        Args:
            alert: 告警 dict,应包含 alert_id 等字段。

        Returns:
            告警唯一标识 alert_id。

        Raises:
            TypeError: alert 不是 dict 类型时。
            ValueError: alert 为空 dict 时。
        """
        if not isinstance(alert, dict):
            raise TypeError(f"alert 必须为 dict,实际类型: {type(alert).__name__}")
        if not alert:
            raise ValueError("alert 不能为空 dict")

        record = dict(alert)
        alert_id = record.get("alert_id")
        if not alert_id:
            alert_id = new_uuid()
            record["alert_id"] = alert_id

        async with self._lock:
            self._alerts.append(record)
        return alert_id

    async def get_events(self, session_id: str = "", limit: int = 100) -> list[dict]:
        """查询事件记录,支持按 session_id 过滤。

        Args:
            session_id: 会话 ID,为空字符串时不过滤。
            limit: 返回记录数上限,必须为正整数。

        Returns:
            事件 dict 列表,按写入时间倒序(最新优先)排列。

        Raises:
            ValueError: limit 不是正整数时。
        """
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError(f"limit 必须为正整数,实际值: {limit!r}")

        async with self._lock:
            if session_id:
                matched = [
                    e for e in self._events if e.get("session_id") == session_id
                ]
            else:
                matched = list(self._events)
            # 倒序(最新优先),取前 limit 条
            matched.reverse()
            return matched[:limit]

    async def get_events_by_trace_id(self, trace_id: str) -> list[dict]:
        """按 trace_id 查询事件记录,用于呈现模块关联查询。

        合并统一事件和原始事件,按写入时间升序返回。

        Args:
            trace_id: 追踪 ID,不能为空字符串。

        Returns:
            事件 dict 列表,按写入时间升序排列。
            每条记录带有 "_source" 字段标识来源。

        Raises:
            ValueError: trace_id 为空字符串时。
        """
        if not trace_id:
            raise ValueError("trace_id 不能为空字符串")

        async with self._lock:
            results: list[dict] = []
            for e in self._events:
                if e.get("trace_id") == trace_id:
                    record = dict(e)
                    record["_source"] = "event"
                    results.append(record)
            for e in self._raw_events:
                common = e.get("common")
                if isinstance(common, dict) and common.get("trace_id") == trace_id:
                    record = dict(e)
                    record["_source"] = "raw_event"
                    results.append(record)
            return results

    async def get_alerts(
        self, acknowledged: bool | None = None, limit: int = 50
    ) -> list[dict]:
        """查询告警记录,支持按确认状态过滤。

        Args:
            acknowledged: 确认状态过滤。None 表示不过滤,True 表示已确认,
                False 表示未确认。
            limit: 返回记录数上限,必须为正整数。

        Returns:
            告警 dict 列表,按写入时间倒序(最新优先)排列。

        Raises:
            ValueError: limit 不是正整数时。
        """
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError(f"limit 必须为正整数,实际值: {limit!r}")

        async with self._lock:
            if acknowledged is None:
                matched = list(self._alerts)
            else:
                matched = [
                    a for a in self._alerts if bool(a.get("acknowledged")) == acknowledged
                ]
            matched.reverse()
            return matched[:limit]

    async def cleanup_expired(
        self, table: str, ttl_days: int, now: float | None = None
    ) -> int:
        """清理内存中超过 TTL 的过期数据,返回删除的条数。

        与 SQLiteStore.cleanup_expired 语义对齐:按 timestamp 字段
        (Unix 秒)与 cutoff = now - ttl_days * 86400 比较,仅删除
        timestamp 有效(> 0)且小于 cutoff 的条目;timestamp 为 0/
        缺失的条目不删(无效时间戳的记录保留待人工处置,避免被
        静默清除)。table 限定白名单(events/alerts/raw_events);
        ttl_days <= 0 视为禁用清理(返回 0)。

        raw_events 表的 timestamp 取 common.timestamp(与
        record_raw_event 落库语义一致)。deque 不支持按 timestamp
        索引,采用线性扫描重建(测试场景数据量小,性能可接受)。

        Args:
            table: 表名,必须为 events / alerts / raw_events 之一。
            ttl_days: 保留天数。<= 0 时不执行清理(禁用语义)。
            now: 当前时间戳(Unix 秒)。None 时取 time.time()。

        Returns:
            删除的条数。TTL 禁用时返回 0。

        Raises:
            ValueError: table 不在白名单中时。
        """
        if table not in _CLEANUP_TABLES:
            raise ValueError(
                f"table 必须为 events/alerts/raw_events 之一,实际值: {table!r}"
            )
        if ttl_days <= 0:
            return 0

        current = now if now is not None else time.time()
        cutoff = current - ttl_days * 86400

        async with self._lock:
            if table == "raw_events":
                data = self._raw_events
                ts_of = _raw_event_ts
            elif table == "alerts":
                data = self._alerts
                ts_of = _ts_of
            else:
                data = self._events
                ts_of = _ts_of
            remaining = deque(r for r in data if not (0 < ts_of(r) < cutoff))
            deleted = len(data) - len(remaining)
            data.clear()
            data.extend(remaining)
            return deleted

    async def close(self) -> None:
        """关闭存储,清空全部内存数据。

        内存存储无持久化,关闭即数据生命周期的终点(P10:原实现为
        空操作且不清数据,与 SQLiteStore.close 释放连接的资源语义
        不对齐;现改为清空 events/alerts/raw_events,释放内存占用,
        并与 StoragePlugin 契约中"关闭后不应再访问数据"的语义一致)。
        """
        async with self._lock:
            self._events.clear()
            self._alerts.clear()
            self._raw_events.clear()
