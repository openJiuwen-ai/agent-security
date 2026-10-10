# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""存储模块单元测试。

验证 SQLiteStore 的 record_event/get_events/create_alert/get_alerts/
record_raw_event/get_events_by_trace_id,ModuleStorageManager 目录结构,
MemoryStore 基本功能。
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import NamedTuple

import pytest

from agent_ssas.core.framework.storage.interfaces import StoragePlugin
from agent_ssas.core.framework.storage.memory_store import MemoryStore
from agent_ssas.core.framework.storage.module_store import ModuleStorageManager
from agent_ssas.core.framework.storage.sqlite_store import SQLiteStore


class EventIds(NamedTuple):
    """事件关联标识(agent/trace),打包以减少函数参数个数。"""

    agent_id: str = "a1"
    trace_id: str = "t1"


_DEFAULT_IDS = EventIds()


def _make_event(
    event_id: str = "test1",
    event_type: str = "invoke_start",
    event_class: str = "lifecycle",
    interaction_seq: int = 0,
    session_id: str = "s1",
    *,
    ids: EventIds = _DEFAULT_IDS,
    timestamp: float = 0.0,
    **extra,
) -> dict:
    """构造事件 dict,便于测试复用。"""
    event = {
        "event_id": event_id,
        "event_type": event_type,
        "event_class": event_class,
        "interaction_seq": interaction_seq,
        "session_id": session_id,
        "agent_id": ids.agent_id,
        "trace_id": ids.trace_id,
        "timestamp": timestamp,
    }
    event.update(extra)
    return event


class TestSQLiteStore:
    """SQLiteStore 读写。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_and_get_events(sqlite_store: SQLiteStore) -> None:
        """验证 record_event + get_events 基本读写。"""
        await sqlite_store.record_event(_make_event())
        events = await sqlite_store.get_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_id"] == "test1"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_filter_by_session_id(sqlite_store: SQLiteStore) -> None:
        """验证按 session_id 过滤事件。"""
        await sqlite_store.record_event(_make_event(session_id="s1"))
        await sqlite_store.record_event(
            _make_event(
                event_id="test2",
                event_type="invoke_end",
                session_id="s2",
                trace_id="t2",
            )
        )
        events = await sqlite_store.get_events(session_id="s1")
        assert len(events) == 1
        assert events[0]["session_id"] == "s1"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_event_auto_id(sqlite_store: SQLiteStore) -> None:
        """验证 event 缺少 event_id 时自动生成 UUID。"""
        event = _make_event()
        del event["event_id"]
        returned_id = await sqlite_store.record_event(event)
        assert returned_id  # 非空字符串
        events = await sqlite_store.get_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_id"] == returned_id

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_record_event_invalid_type(sqlite_store: SQLiteStore) -> None:
        """验证传入非 dict 时抛出 TypeError。"""
        with pytest.raises(TypeError):
            await sqlite_store.record_event("not a dict")  # type: ignore[arg-type]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_record_event_empty_dict(sqlite_store: SQLiteStore) -> None:
        """验证传入空 dict 时抛出 ValueError。"""
        with pytest.raises(ValueError):
            await sqlite_store.record_event({})

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_create_and_get_alerts(sqlite_store: SQLiteStore) -> None:
        """验证 create_alert + get_alerts 基本读写。"""
        await sqlite_store.create_alert(
            {
                "alert_id": "alert-1",
                "interaction_seq": 0,
                "session_id": "s1",
                "trace_id": "t1",
                "risk_level": "high",
                "risk_type": "tool_misuse",
                "timestamp": 1715000000.0,
            }
        )
        alerts = await sqlite_store.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "alert-1"
        assert alerts[0]["risk_level"] == "high"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_get_alerts_filter_acknowledged(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证 get_alerts 按 acknowledged 过滤。"""
        await sqlite_store.create_alert({"alert_id": "a1", "risk_level": "low", "acknowledged": False})
        await sqlite_store.create_alert({"alert_id": "a2", "risk_level": "high", "acknowledged": True})
        unack = await sqlite_store.get_alerts(acknowledged=False)
        assert len(unack) == 1
        assert unack[0]["alert_id"] == "a1"
        ack = await sqlite_store.get_alerts(acknowledged=True)
        assert len(ack) == 1
        assert ack[0]["alert_id"] == "a2"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_raw_event(sqlite_store: SQLiteStore) -> None:
        """验证 record_raw_event 持久化原始事件。"""
        raw_event = {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "tool_input",
                "event_class": "lifecycle",
                "interaction_seq": 0,
                "session_id": "s1",
                "agent_id": "a1",
                "trace_id": "t1",
                "timestamp": 1715000000.0,
            },
            "payload": {"tool_name": "bash"},
            "metadata": {},
        }
        raw_id = await sqlite_store.record_raw_event(raw_event)
        assert raw_id  # 自动生成的 raw_event_id

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_get_events_by_trace_id(sqlite_store: SQLiteStore) -> None:
        """验证按 trace_id 关联查询统一事件和原始事件。"""
        # 写入统一事件
        await sqlite_store.record_event(_make_event(event_id="e1", ids=EventIds(trace_id="trace-1")))
        # 写入原始事件
        await sqlite_store.record_raw_event(
            {
                "common": {
                    "event_type": "tool_input",
                    "event_class": "lifecycle",
                    "interaction_seq": 0,
                    "session_id": "s1",
                    "agent_id": "a1",
                    "trace_id": "trace-1",
                    "timestamp": 0.0,
                },
                "payload": {},
                "metadata": {},
            }
        )
        results = await sqlite_store.get_events_by_trace_id("trace-1")
        assert len(results) == 2
        sources = {r.get("_source") for r in results}
        assert sources == {"event", "raw_event"}

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_get_events_by_trace_id_empty_trace(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证空 trace_id 抛出 ValueError。"""
        with pytest.raises(ValueError):
            await sqlite_store.get_events_by_trace_id("")

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_get_events_invalid_limit(sqlite_store: SQLiteStore) -> None:
        """验证非正整数 limit 抛出 ValueError。"""
        with pytest.raises(ValueError):
            await sqlite_store.get_events(limit=0)
        with pytest.raises(ValueError):
            await sqlite_store.get_events(limit=-1)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_event_without_timestamp_falls_back_to_now(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证缺失 timestamp 的事件落库回退当前时间(非 0)。

        数据生命周期 P1 修复:回退 0.0 会导致行被 TTL 清理立即误删,
        修复后缺失 timestamp 的记录(如模块报告)落库时间为当前时间。
        """
        import time

        before = time.time()
        # 构造缺失 timestamp 的记录(模拟分析器返回的报告 dict)
        event = _make_event(event_id="no_ts")
        del event["timestamp"]
        await sqlite_store.record_event(event)
        # 直接查表列(而非 data JSON),验证 timestamp 列为当前时间附近
        row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp, timestamp_text FROM events WHERE event_id = 'no_ts'"
        ).fetchone()
        assert row is not None
        assert row[0] > 0.0
        assert row[0] >= before - 1.0
        assert row[0] <= time.time() + 1.0
        # timestamp_text 同步写入(可读格式非空)
        assert row[1] is not None and len(row[1]) > 0
        # TTL 清理(30 天)后行仍在(不再被立即误删)
        deleted = await sqlite_store.cleanup_expired("events", 30)
        assert deleted == 0
        events = await sqlite_store.get_events(limit=10)
        assert len(events) == 1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_event_explicit_timestamp_not_overwritten(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证显式 timestamp 正常落库(不被回退逻辑覆盖)。"""
        await sqlite_store.record_event(
            _make_event(event_id="with_ts", timestamp=1715000000.0)
        )
        row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp FROM events WHERE event_id = 'with_ts'"
        ).fetchone()
        assert row is not None
        assert row[0] == 1715000000.0


class TestTimestampTextColumn:
    """timestamp_text 可读时间列(本地时区 YYYY-MM-DD HH:MM:SS.mmm)。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_event_timestamp_text_format(sqlite_store: SQLiteStore) -> None:
        """验证 events 表 timestamp_text 写入为可读格式。"""
        import re
        import time

        now = time.time()
        await sqlite_store.record_event(_make_event(event_id="t1", timestamp=now))
        row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM events WHERE event_id = 't1'"
        ).fetchone()
        assert row is not None
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}", row[0]), (
            f"timestamp_text 格式不符: {row[0]!r}"
        )

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_raw_event_and_alert_timestamp_text(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证 raw_events 与 alerts 表 timestamp_text 写入。"""
        import re

        await sqlite_store.record_raw_event(
            {
                "common": {
                    "event_type": "tool_input",
                    "event_class": "lifecycle",
                    "timestamp": 1715000000.123,
                    "session_id": "s1",
                    "trace_id": "t1",
                }
            }
        )
        await sqlite_store.create_alert({"alert_id": "a1", "timestamp": 1715000000.456, "risk_level": "high"})
        raw_row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM raw_events LIMIT 1"
        ).fetchone()
        alert_row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM alerts WHERE alert_id = 'a1'"
        ).fetchone()
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}", raw_row[0])
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}", alert_row[0])

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_legacy_db_migration_backfills(ssas_home: Path) -> None:
        """验证旧库(无 timestamp_text 列)自动迁移并回填历史数据。"""
        import sqlite3

        db_path = ssas_home / "ssas" / "legacy_test.db"
        db_path.parent.mkdir(parents=True, exist_ok=True)
        # 手工构造旧表结构(无 timestamp_text 列)
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE,
                event_type TEXT,
                event_class TEXT,
                interaction_seq INTEGER,
                session_id TEXT,
                agent_id TEXT,
                trace_id TEXT,
                timestamp REAL,
                data TEXT
            )
            """
        )
        conn.execute(
            "INSERT INTO events (event_id, timestamp, data) VALUES (?, ?, ?)",
            ("old1", 1715000000.0, "{}"),
        )
        conn.execute(
            "INSERT INTO events (event_id, timestamp, data) VALUES (?, ?, ?)",
            ("old_invalid", 0.0, "{}"),
        )
        conn.commit()
        conn.close()

        # 打开 SQLiteStore 触发迁移
        store = SQLiteStore(db_path)
        columns = {
            row[1]
            for row in store._conn.execute("PRAGMA table_info(events)").fetchall()  # pylint: disable=protected-access
        }
        assert "timestamp_text" in columns
        # 有效 timestamp 回填,无效(<=0)保持 NULL
        row1 = store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM events WHERE event_id = 'old1'"
        ).fetchone()
        row2 = store._conn.execute(  # pylint: disable=protected-access
            "SELECT timestamp_text FROM events WHERE event_id = 'old_invalid'"
        ).fetchone()
        assert row1[0] is not None and len(row1[0]) > 0
        assert row2[0] is None
        store._conn.close()  # pylint: disable=protected-access


class TestCleanupExpired:
    """TTL 过期数据清理(cleanup_expired)。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_events_by_ttl(sqlite_store: SQLiteStore) -> None:
        """验证 events 表按 TTL 清理过期数据,未过期数据保留。"""
        import time

        now = time.time()
        # 一条 31 天前(过期,event_ttl=30),一条 1 天前(未过期)
        await sqlite_store.record_event(_make_event(event_id="old", timestamp=now - 31 * 86400))
        await sqlite_store.record_event(_make_event(event_id="new", timestamp=now - 1 * 86400))
        deleted = await sqlite_store.cleanup_expired("events", 30, now=now)
        assert deleted == 1
        remaining = await sqlite_store.get_events(limit=10)
        assert len(remaining) == 1
        assert remaining[0]["event_id"] == "new"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_alerts_by_ttl(sqlite_store: SQLiteStore) -> None:
        """验证 alerts 表按 90 天 TTL 清理。"""
        import time

        now = time.time()
        await sqlite_store.create_alert({"alert_id": "old_alert", "timestamp": now - 91 * 86400})
        await sqlite_store.create_alert({"alert_id": "new_alert", "timestamp": now - 89 * 86400})
        deleted = await sqlite_store.cleanup_expired("alerts", 90, now=now)
        assert deleted == 1
        alerts = await sqlite_store.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "new_alert"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_ttl_zero_disabled(sqlite_store: SQLiteStore) -> None:
        """验证 ttl_days <= 0 时禁用清理(不删除任何数据)。"""
        import time

        now = time.time()
        await sqlite_store.record_event(_make_event(event_id="old", timestamp=now - 365 * 86400))
        deleted = await sqlite_store.cleanup_expired("events", 0, now=now)
        assert deleted == 0
        events = await sqlite_store.get_events()
        assert len(events) == 1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_invalid_table_raises(sqlite_store: SQLiteStore) -> None:
        """验证非法表名抛出 ValueError(白名单防注入)。"""
        with pytest.raises(ValueError):
            await sqlite_store.cleanup_expired("sessions; DROP TABLE events", 30)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_preserves_zero_timestamp_rows(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证 timestamp=0.0 的行执行 cleanup_expired 后仍存在。

        数据生命周期 P8 修复:0/NULL 的时间戳恒小于 cutoff,不加上界
        会被立即误删;修复后无效时间戳的历史遗留行保留待人工处置,
        正常过期行仍被删除。
        """
        import time

        now = time.time()
        # 显式写入 timestamp=0.0 的行(record_event 落库显式 0 值)
        await sqlite_store.record_event(
            _make_event(event_id="zero_ts", timestamp=0.0)
        )
        # 正常过期行(31 天前,超过 event_ttl=30,应被删除)
        await sqlite_store.record_event(
            _make_event(event_id="old", timestamp=now - 31 * 86400)
        )
        deleted = await sqlite_store.cleanup_expired("events", 30, now=now)
        assert deleted == 1
        remaining = await sqlite_store.get_events(limit=10)
        remaining_ids = {e["event_id"] for e in remaining}
        assert "old" not in remaining_ids
        # timestamp=0.0 的行保留,不被误删
        assert "zero_ts" in remaining_ids

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_preserves_null_timestamp_rows(
        sqlite_store: SQLiteStore,
    ) -> None:
        """验证 timestamp 为 NULL 的行(绕过落库回退直插)清理后仍存在。"""
        import time

        now = time.time()
        # 绕过 record_event 的回退逻辑,直插 timestamp 为 NULL 的行
        sqlite_store._conn.execute(  # pylint: disable=protected-access
            "INSERT INTO events (event_id, event_type, timestamp, data) "
            "VALUES ('null_ts', 'invoke_start', NULL, '{}')"
        )
        sqlite_store._conn.commit()  # pylint: disable=protected-access

        deleted = await sqlite_store.cleanup_expired("events", 30, now=now)
        assert deleted == 0
        row = sqlite_store._conn.execute(  # pylint: disable=protected-access
            "SELECT event_id FROM events WHERE event_id = 'null_ts'"
        ).fetchone()
        assert row is not None

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_module_storage_cleanup(
        ssas_home: Path,
    ) -> None:
        """验证 ModuleStorageManager.cleanup 按 TTL 清理过程/结果库。"""
        import time

        now = time.time()
        manager = ModuleStorageManager("ttl_test_module", ssas_home)
        # process.db 写入 31 天前数据(超过 event_ttl=30 应清理)
        await manager.process_store.record_event({"event_id": "p_old", "timestamp": now - 31 * 86400})
        # result.db 写入 91 天前数据(超过 alert_ttl=90 应清理)
        await manager.result_store.record_event({"event_id": "r_old", "timestamp": now - 91 * 86400})
        # result.db 写入 1 天前数据(应保留)
        await manager.result_store.record_event({"event_id": "r_new", "timestamp": now - 86400})

        # cleanup 内部使用 time.time(),预置数据足够旧,无需 mock
        await manager.cleanup(30, 90)

        process_events = await manager.process_store.get_events(limit=10)
        result_events = await manager.result_store.get_events(limit=10)
        assert process_events == []
        assert len(result_events) == 1
        assert result_events[0]["event_id"] == "r_new"
        await manager.close()


class TestModuleStorageManager:
    """ModuleStorageManager 创建和目录结构。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_creates_directory_structure(ssas_home: Path) -> None:
        """验证创建模块目录结构和 result.db/config 目录。

        process.db 懒创建:初始化后不存在,首次访问 process_store 后创建。
        """
        manager = ModuleStorageManager("test_module", ssas_home)
        module_dir = ssas_home / "ssas" / "modules" / "test_module"
        assert module_dir.exists()
        # process.db 懒创建,初始化后不存在
        assert not (module_dir / "process.db").exists()
        assert (module_dir / "result.db").exists()
        assert (module_dir / "config").is_dir()
        assert manager.config_dir == module_dir / "config"
        # 首次访问 process_store 后创建
        assert manager.process_store is not None
        assert (module_dir / "process.db").exists()
        assert manager.result_store is not None

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_process_db_lazy_creation(ssas_home: Path) -> None:
        """验证 process.db 懒创建:初始化不建库,显式访问后才创建。"""
        manager = ModuleStorageManager("lazy_module", ssas_home)
        module_dir = ssas_home / "ssas" / "modules" / "lazy_module"
        # 初始化后 process.db 不存在(无空库与常驻连接开销)
        assert not (module_dir / "process.db").exists()
        assert manager._process_store is None  # pylint: disable=protected-access
        # 显式访问 process_store 属性触发建库
        store = manager.process_store
        assert (module_dir / "process.db").exists()
        # 再次访问复用同一实例
        assert manager.process_store is store

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_skips_uninstantiated_process_store(
        ssas_home: Path,
    ) -> None:
        """验证 process_store 未实例化时 cleanup 正常:不建库,result.db 正常清理。"""
        import time

        now = time.time()
        manager = ModuleStorageManager("cleanup_lazy_module", ssas_home)
        module_dir = ssas_home / "ssas" / "modules" / "cleanup_lazy_module"
        # result.db 写入 91 天前数据(超过 alert_ttl=90 应清理)
        await manager.result_store.record_event(
            {"event_id": "r_old", "timestamp": now - 91 * 86400}
        )

        # process_store 未实例化时 cleanup 不报错、不建 process.db
        await manager.cleanup(30, 90)
        assert not (module_dir / "process.db").exists()
        # result.db 清理正常执行
        result_events = await manager.result_store.get_events(limit=10)
        assert result_events == []
        await manager.close()

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_close_skips_uninstantiated_process_store(
        ssas_home: Path,
    ) -> None:
        """验证 process_store 未实例化时 close 安全(不报错、不建库)。"""
        manager = ModuleStorageManager("close_lazy_module", ssas_home)
        module_dir = ssas_home / "ssas" / "modules" / "close_lazy_module"
        # process_store 未实例化时 close 不报错
        await manager.close()
        assert not (module_dir / "process.db").exists()

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_empty_module_name_raises(ssas_home: Path) -> None:
        """验证空 module_name 抛出 ValueError。"""
        with pytest.raises(ValueError):
            ModuleStorageManager("", ssas_home)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_process_and_result_store_independent(
        ssas_home: Path,
    ) -> None:
        """验证过程库和结果库相互独立。"""
        manager = ModuleStorageManager("test_module", ssas_home)
        await manager.process_store.record_event({"event_id": "p1", "event_type": "tool_input"})
        await manager.result_store.record_event({"event_id": "r1", "event_type": "alert"})
        process_events = await manager.process_store.get_events(limit=10)
        result_events = await manager.result_store.get_events(limit=10)
        assert len(process_events) == 1
        assert process_events[0]["event_id"] == "p1"
        assert len(result_events) == 1
        assert result_events[0]["event_id"] == "r1"
        await manager.close()


class TestMemoryStore:
    """MemoryStore 基本功能。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_and_get_events(memory_store: MemoryStore) -> None:
        """验证 record_event + get_events 基本读写。"""
        await memory_store.record_event(_make_event())
        events = await memory_store.get_events(limit=10)
        assert len(events) == 1
        assert events[0]["event_id"] == "test1"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_filter_by_session_id(memory_store: MemoryStore) -> None:
        """验证按 session_id 过滤。"""
        await memory_store.record_event(_make_event(session_id="s1"))
        await memory_store.record_event(_make_event(event_id="e2", session_id="s2"))
        events = await memory_store.get_events(session_id="s1")
        assert len(events) == 1
        assert events[0]["session_id"] == "s1"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_create_and_get_alerts(memory_store: MemoryStore) -> None:
        """验证 create_alert + get_alerts 基本读写。"""
        await memory_store.create_alert({"alert_id": "a1", "risk_level": "high"})
        alerts = await memory_store.get_alerts()
        assert len(alerts) == 1
        assert alerts[0]["alert_id"] == "a1"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_record_raw_event_and_get_by_trace(
        memory_store: MemoryStore,
    ) -> None:
        """验证 record_raw_event + get_events_by_trace_id。"""
        await memory_store.record_event(_make_event(event_id="e1", ids=EventIds(trace_id="trace-1")))
        await memory_store.record_raw_event(
            {
                "common": {
                    "event_type": "tool_input",
                    "interaction_seq": 0,
                    "session_id": "s1",
                    "trace_id": "trace-1",
                    "timestamp": 0.0,
                },
                "payload": {},
                "metadata": {},
            }
        )
        results = await memory_store.get_events_by_trace_id("trace-1")
        assert len(results) == 2


class TestMemoryStoreCleanupExpired:
    """MemoryStore TTL 过期数据清理(cleanup_expired)。

    语义与 SQLiteStore.cleanup_expired 对齐(P10 契约完善)。
    """

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_events_by_ttl(memory_store: MemoryStore) -> None:
        """验证 events 按 TTL 清理过期数据,未过期数据保留。"""
        now = time.time()
        # 一条 31 天前(过期,event_ttl=30),一条 1 天前(未过期)
        await memory_store.record_event(_make_event(event_id="old", timestamp=now - 31 * 86400))
        await memory_store.record_event(_make_event(event_id="new", timestamp=now - 1 * 86400))
        deleted = await memory_store.cleanup_expired("events", 30, now=now)
        assert deleted == 1
        remaining = await memory_store.get_events(limit=10)
        assert [e["event_id"] for e in remaining] == ["new"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_alerts_by_ttl(memory_store: MemoryStore) -> None:
        """验证 alerts 表按 90 天 TTL 清理。"""
        now = time.time()
        await memory_store.create_alert({"alert_id": "old_alert", "timestamp": now - 91 * 86400})
        await memory_store.create_alert({"alert_id": "new_alert", "timestamp": now - 89 * 86400})
        deleted = await memory_store.cleanup_expired("alerts", 90, now=now)
        assert deleted == 1
        alerts = await memory_store.get_alerts()
        assert [a["alert_id"] for a in alerts] == ["new_alert"]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_raw_events_by_ttl(memory_store: MemoryStore) -> None:
        """验证 raw_events 表按 common.timestamp 清理。"""
        now = time.time()
        await memory_store.record_raw_event(
            {
                "common": {"event_type": "tool_input", "trace_id": "t1", "timestamp": now - 31 * 86400},
                "payload": {},
                "metadata": {},
            }
        )
        await memory_store.record_raw_event(
            {
                "common": {"event_type": "tool_input", "trace_id": "t2", "timestamp": now - 86400},
                "payload": {},
                "metadata": {},
            }
        )
        deleted = await memory_store.cleanup_expired("raw_events", 30, now=now)
        assert deleted == 1
        remaining = await memory_store.get_events_by_trace_id("t1")
        assert remaining == []
        kept = await memory_store.get_events_by_trace_id("t2")
        assert len(kept) == 1

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_ttl_zero_disabled(memory_store: MemoryStore) -> None:
        """验证 ttl_days <= 0 时禁用清理(不删除任何数据)。"""
        now = time.time()
        await memory_store.record_event(_make_event(event_id="old", timestamp=now - 365 * 86400))
        deleted = await memory_store.cleanup_expired("events", 0, now=now)
        assert deleted == 0
        events = await memory_store.get_events()
        assert len(events) == 1
        deleted = await memory_store.cleanup_expired("events", -1, now=now)
        assert deleted == 0

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_invalid_table_raises(memory_store: MemoryStore) -> None:
        """验证非法表名抛出 ValueError(与 SQLiteStore 白名单行为一致)。"""
        with pytest.raises(ValueError, match="events/alerts/raw_events"):
            await memory_store.cleanup_expired("sessions; DROP TABLE events", 30)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_cleanup_preserves_zero_timestamp_records(
        memory_store: MemoryStore,
    ) -> None:
        """验证 timestamp=0.0 的记录清理后仍保留(与 SQLiteStore 防护语义一致)。"""
        now = time.time()
        await memory_store.record_event(_make_event(event_id="zero_ts", timestamp=0.0))
        # 正常过期行(31 天前,超过 event_ttl=30,应被删除)
        await memory_store.record_event(_make_event(event_id="old", timestamp=now - 31 * 86400))
        deleted = await memory_store.cleanup_expired("events", 30, now=now)
        assert deleted == 1
        remaining_ids = {e["event_id"] for e in await memory_store.get_events(limit=10)}
        assert "old" not in remaining_ids
        # timestamp=0.0 的记录保留,不被误删
        assert "zero_ts" in remaining_ids

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_cleanup_expired_sqlite_memory_semantics_aligned(
        sqlite_store: SQLiteStore,
        memory_store: MemoryStore,
    ) -> None:
        """验证同一批数据在两种后端的清理结果一致(契约语义对齐)。"""
        now = time.time()
        for store in (sqlite_store, memory_store):
            await store.record_event(_make_event(event_id="old", timestamp=now - 31 * 86400))
            await store.record_event(_make_event(event_id="new", timestamp=now - 86400))
            await store.record_event(_make_event(event_id="zero_ts", timestamp=0.0))
        sqlite_deleted = await sqlite_store.cleanup_expired("events", 30, now=now)
        memory_deleted = await memory_store.cleanup_expired("events", 30, now=now)
        assert sqlite_deleted == memory_deleted == 1
        sqlite_ids = {e["event_id"] for e in await sqlite_store.get_events(limit=10)}
        memory_ids = {e["event_id"] for e in await memory_store.get_events(limit=10)}
        assert sqlite_ids == memory_ids == {"new", "zero_ts"}


class TestMemoryStoreClose:
    """MemoryStore 关闭语义(P10:关闭即清空内存数据)。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    async def test_close_clears_all_data(memory_store: MemoryStore) -> None:
        """验证 close 后全部数据被清空(events/alerts/raw_events)。"""
        await memory_store.record_event(_make_event())
        await memory_store.create_alert({"alert_id": "a1", "risk_level": "high"})
        await memory_store.record_raw_event(
            {"common": {"event_type": "tool_input", "trace_id": "t1", "timestamp": 0.0}}
        )
        await memory_store.close()
        # 关闭即数据生命周期终点:查询返回空(存储对象仍可复用)
        events = await memory_store.get_events(limit=10)
        alerts = await memory_store.get_alerts()
        assert events == []
        assert alerts == []

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    async def test_close_idempotent(memory_store: MemoryStore) -> None:
        """验证重复 close 不报错。"""
        await memory_store.record_event(_make_event())
        await memory_store.close()
        await memory_store.close()
        assert await memory_store.get_events(limit=10) == []


class TestStoragePluginContract:
    """StoragePlugin 契约:SQLiteStore/MemoryStore 均满足新协议方法。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_sqlite_store_satisfies_protocol(sqlite_store: SQLiteStore) -> None:
        """验证 SQLiteStore 是 StoragePlugin(runtime_checkable isinstance)。"""
        assert isinstance(sqlite_store, StoragePlugin)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_memory_store_satisfies_protocol(memory_store: MemoryStore) -> None:
        """验证 MemoryStore 是 StoragePlugin(runtime_checkable isinstance)。"""
        assert isinstance(memory_store, StoragePlugin)

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_lifecycle_methods_present(
        sqlite_store: SQLiteStore, memory_store: MemoryStore
    ) -> None:
        """验证两个后端均具备 cleanup_expired/close 契约方法且为可等待。"""
        import inspect

        for store in (sqlite_store, memory_store):
            for method_name in ("cleanup_expired", "close"):
                method = getattr(store, method_name, None)
                assert callable(method), (
                    f"{type(store).__name__} 缺少契约方法 {method_name}"
                )
                assert inspect.iscoroutinefunction(method), (
                    f"{type(store).__name__}.{method_name} 应为异步方法"
                )
