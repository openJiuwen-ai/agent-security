# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""AgentSSAS 存储插件协议接口定义。

定义 StoragePlugin 协议,作为存储后端的统一接口契约。
具体实现包括 SQLiteStore(生产环境)和 MemoryStore(测试环境)。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class StoragePlugin(Protocol):
    """存储插件协议,定义存储后端的统一接口。

    所有存储后端(SQLiteStore、MemoryStore 等)需实现此协议。
    接口方法均为异步,保证存储操作不阻塞事件循环。
    """

    async def record_event(self, event: dict) -> str:
        """异步写入一条事件记录,返回 event_id。

        Args:
            event: 事件 dict,包含 event_id、event_type、event_class、
                interaction_seq、session_id、agent_id、trace_id、timestamp 等字段。

        Returns:
            事件唯一标识 event_id。
        """
        ...

    async def create_alert(self, alert: dict) -> str:
        """异步写入一条告警记录,返回 alert_id。

        Args:
            alert: 告警 dict,包含 alert_id、interaction_seq、session_id、
                trace_id、risk_level、risk_type、timestamp 等字段。

        Returns:
            告警唯一标识 alert_id。
        """
        ...

    async def get_events(self, session_id: str = "", limit: int = 100) -> list[dict]:
        """查询事件记录,支持按 session_id 过滤。

        Args:
            session_id: 会话 ID,为空字符串时不过滤,返回所有事件。
            limit: 返回记录数上限。

        Returns:
            事件 dict 列表,按写入时间倒序排列。
        """
        ...

    async def get_alerts(self, acknowledged: bool | None = None, limit: int = 50) -> list[dict]:
        """查询告警记录,支持按确认状态过滤。

        Args:
            acknowledged: 确认状态过滤。None 表示不过滤,True 表示已确认,
                False 表示未确认。
            limit: 返回记录数上限。

        Returns:
            告警 dict 列表,按写入时间倒序排列。
        """
        ...

    async def cleanup_expired(
        self, table: str, ttl_days: int, now: float | None = None
    ) -> int:
        """清理指定表中超过 TTL 的过期数据,返回删除的行数。

        与 SQLiteStore.cleanup_expired 语义对齐:按 timestamp(Unix 秒)
        与 cutoff = now - ttl_days * 86400 比较,仅删除 timestamp 有效
        (> 0)且小于 cutoff 的行;timestamp 为 0/NULL/缺失的行不删
        (无效时间戳的行保留待人工处置,避免被静默清除)。
        table 限定白名单(events/alerts/raw_events);ttl_days <= 0 视为
        禁用清理(返回 0)。

        Args:
            table: 表名,必须为 events / alerts / raw_events 之一。
            ttl_days: 保留天数。<= 0 时不执行清理(禁用语义)。
            now: 当前时间戳(Unix 秒)。None 时取 time.time()。

        Returns:
            删除的行数。TTL 禁用时返回 0。

        Raises:
            ValueError: table 不在白名单中时。
        """
        ...

    async def close(self) -> None:
        """关闭存储,释放连接/资源。

        供调用方在优雅关闭时调用。关闭即存储生命周期的终点:
        持久化实现(如 SQLiteStore)关闭数据库连接;内存实现(如
        MemoryStore)清空全部数据。关闭后不应再调用其他方法。
        """
        ...
