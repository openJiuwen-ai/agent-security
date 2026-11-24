# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""配置模块单元测试。

验证 AgentSSASConfig 默认值、自定义值、storage_path、from_dict、
_resolve_ssas_home 环境变量优先级。
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_ssas.core.framework.config import AgentSSASConfig, AgentSSASMode


class TestAgentSSASConfig:
    """AgentSSASConfig 加载与字段默认值。"""

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_default_values() -> None:
        """验证默认配置值。"""
        c = AgentSSASConfig()
        assert c.enabled is True
        assert c.mode == AgentSSASMode.INPROCESS
        assert c.rail_priority == 80
        assert c.event_ttl_days == 30
        assert c.alert_ttl_days == 90
        assert c.report_file_ttl_days == 90
        assert c.cleanup_interval_hours == 24
        assert c.storage_backend == "sqlite"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_storage_backend_default_is_sqlite() -> None:
        """验证 storage_backend 默认值为 sqlite,from_dict 不传时回归。"""
        c = AgentSSASConfig.from_dict({})
        assert c.storage_backend == "sqlite"

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_storage_backend_non_sqlite_warns_not_raises(
        caplog: pytest.LogCaptureFixture,
    ) -> None:
        """验证 from_dict 传入非 sqlite 值不抛错,记 warning,值按传入记录。

        storage_backend 为预留字段(v0.1 仅支持 sqlite,无其他后端实现),
        fail-open 风格:配置错误不阻断启动,行为透明(值保留原样)。
        """
        import logging

        with caplog.at_level(logging.WARNING, logger="agent_ssas.core.framework.config.settings"):
            c = AgentSSASConfig.from_dict({"storage_backend": "postgres"})
        # 不抛错,值按传入记录(行为透明)
        assert c.storage_backend == "postgres"
        # 记录 warning 提示配置无效
        assert any(
            "storage_backend" in record.message for record in caplog.records
        ), f"应记录 storage_backend 预留字段 warning,实际: {caplog.records}"

        # "sqlite" 正常值不告警
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="agent_ssas.core.framework.config.settings"):
            c2 = AgentSSASConfig.from_dict({"storage_backend": "sqlite"})
        assert c2.storage_backend == "sqlite"
        assert not any(
            "storage_backend" in record.message for record in caplog.records
        )

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_custom_values() -> None:
        """验证自定义字段覆盖默认值。"""
        c = AgentSSASConfig(
            enabled=False,
            mode=AgentSSASMode.HTTP,
            rail_priority=50,
            event_ttl_days=7,
            alert_ttl_days=14,
            report_file_ttl_days=30,
            cleanup_interval_hours=12,
        )
        assert c.enabled is False
        assert c.mode == AgentSSASMode.HTTP
        assert c.rail_priority == 50
        assert c.event_ttl_days == 7
        assert c.alert_ttl_days == 14
        assert c.report_file_ttl_days == 30
        assert c.cleanup_interval_hours == 12

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_storage_path_explicit_home(ssas_home: Path) -> None:
        """验证显式 ssas_home 时 storage_path 正确推导。"""
        c = AgentSSASConfig(ssas_home=str(ssas_home))
        assert c.storage_path == str(ssas_home / "ssas")

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_storage_path_none_resolves_env(ssas_home: Path) -> None:
        """验证 ssas_home 为 None 时从 SSAS_HOME 环境变量解析。"""
        c = AgentSSASConfig()
        # 根 conftest 已设置 SSAS_HOME 环境变量
        assert c.storage_path == str(ssas_home / "ssas")

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_from_dict_known_fields() -> None:
        """验证 from_dict 识别已知字段。"""
        c = AgentSSASConfig.from_dict(
            {
                "enabled": False,
                "mode": "http",
                "rail_priority": 100,
                "event_ttl_days": 60,
                "report_file_ttl_days": 15,
            }
        )
        assert c.enabled is False
        assert c.mode == AgentSSASMode.HTTP
        assert c.rail_priority == 100
        assert c.event_ttl_days == 60
        assert c.report_file_ttl_days == 15

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_report_file_ttl_env_override(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """验证 SSAS_REPORT_FILE_TTL_DAYS 环境变量覆盖 report_file_ttl_days。"""
        monkeypatch.setenv("SSAS_REPORT_FILE_TTL_DAYS", "7")
        # 环境变量覆盖经 from_dict 的 _apply_env_overrides 生效
        c = AgentSSASConfig.from_dict(None)
        assert c.report_file_ttl_days == 7
        # 非法值忽略,保留默认值
        monkeypatch.setenv("SSAS_REPORT_FILE_TTL_DAYS", "not-a-number")
        c2 = AgentSSASConfig.from_dict(None)
        assert c2.report_file_ttl_days == 90

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_cleanup_interval_hours_env_override(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """验证 SSAS_CLEANUP_INTERVAL_HOURS 环境变量覆盖 cleanup_interval_hours。"""
        monkeypatch.setenv("SSAS_CLEANUP_INTERVAL_HOURS", "6")
        c = AgentSSASConfig.from_dict(None)
        assert c.cleanup_interval_hours == 6
        # 非法值忽略,保留默认值
        monkeypatch.setenv("SSAS_CLEANUP_INTERVAL_HOURS", "not-a-number")
        c2 = AgentSSASConfig.from_dict(None)
        assert c2.cleanup_interval_hours == 24

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_cleanup_interval_hours_from_dict() -> None:
        """验证 from_dict 识别 cleanup_interval_hours 字段(含覆盖默认值)。"""
        c = AgentSSASConfig.from_dict({"cleanup_interval_hours": 48})
        assert c.cleanup_interval_hours == 48
        # 未提供时保留默认值
        c2 = AgentSSASConfig.from_dict({})
        assert c2.cleanup_interval_hours == 24

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_from_dict_ignores_unknown_fields() -> None:
        """验证 from_dict 忽略未知字段。"""
        c = AgentSSASConfig.from_dict({"enabled": False, "unknown_field": "value"})
        assert c.enabled is False
        # 未知字段不会成为 dataclass 字段

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level0
    def test_from_dict_none_returns_default() -> None:
        """验证 from_dict(None) 返回默认配置。"""
        c = AgentSSASConfig.from_dict(None)
        assert c.enabled is True
        assert c.mode == AgentSSASMode.INPROCESS

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_from_dict_invalid_type_raises() -> None:
        """验证 from_dict 传入非 dict 时抛出 TypeError。"""
        with pytest.raises(TypeError):
            AgentSSASConfig.from_dict("not a dict")  # type: ignore[arg-type]

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_resolve_ssas_home_priority(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """验证环境变量优先级:SSAS_HOME > JIUWENSWARM_DATA_DIR > JIUWENSWARM_HOME。

        设置三个环境变量后,SSAS_HOME 应优先被选中。
        """
        c = AgentSSASConfig()
        monkeypatch.setenv("SSAS_HOME", "/tmp/ssas_home")
        monkeypatch.setenv("JIUWENSWARM_DATA_DIR", "/tmp/data_dir")
        monkeypatch.setenv("JIUWENSWARM_HOME", "/tmp/jw_home")
        resolved = c._resolve_ssas_home()  # pylint: disable=protected-access
        assert resolved == Path("/tmp/ssas_home")

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_resolve_ssas_home_fallback_data_dir(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """验证无 SSAS_HOME 时回退到 JIUWENSWARM_DATA_DIR。"""
        c = AgentSSASConfig()
        monkeypatch.delenv("SSAS_HOME", raising=False)
        monkeypatch.setenv("JIUWENSWARM_DATA_DIR", "/tmp/data_dir")
        monkeypatch.delenv("JIUWENSWARM_HOME", raising=False)
        resolved = c._resolve_ssas_home()  # pylint: disable=protected-access
        assert resolved == Path("/tmp/data_dir")

    @staticmethod
    @pytest.mark.unit
    @pytest.mark.level1
    def test_resolve_ssas_home_fallback_jw_home(
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """验证无 SSAS_HOME 和 JIUWENSWARM_DATA_DIR 时回退到 JIUWENSWARM_HOME。"""
        c = AgentSSASConfig()
        monkeypatch.delenv("SSAS_HOME", raising=False)
        monkeypatch.delenv("JIUWENSWARM_DATA_DIR", raising=False)
        monkeypatch.setenv("JIUWENSWARM_HOME", "/tmp/jw_home")
        resolved = c._resolve_ssas_home()  # pylint: disable=protected-access
        assert resolved == Path("/tmp/jw_home")
