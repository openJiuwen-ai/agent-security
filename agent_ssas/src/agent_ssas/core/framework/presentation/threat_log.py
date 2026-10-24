# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""AgentSSAS 威胁日志呈现插件。

AgentSSASThreatLog 接收简化格式的威胁分析报告,结合报告中的
aux_ids、event_node 等信息,调用 ocsf.build_ocsf_report 构建完整的
OCSF Detection Finding 格式报告,落盘存储为 JSON 文件。
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path

from agent_ssas.core.framework.config.settings import AgentSSASConfig
from agent_ssas.core.framework.presentation.ocsf import build_ocsf_report

logger = logging.getLogger(__name__)

# 威胁报告文件名时间戳格式:threat_{trace}_{module}_{YYYYMMDD_HHMMSS}_{mmm}.json
_FILENAME_TIME_PATTERN = re.compile(r"_(\d{8})_(\d{6})_\d{3}\.json$")


class AgentSSASThreatLog:
    """威胁日志呈现插件。

    输入简化格式的威胁分析报告,结合事件数据构建完整的
    OCSF Detection Finding 格式报告,落盘存储。

    0.1 版本简化实现:trace_id 关联查询暂不实际查询存储模块,
    related_events 传空列表,后续版本可接入存储模块完成关联查询。
    """

    name = "AgentSSASThreatLog"

    def __init__(self, config: AgentSSASConfig) -> None:
        """初始化威胁日志呈现插件。

        从 config 的 storage_path 推导输出目录,在
        `<storage_path>/reports/threat_log` 下落盘存储报告 JSON 文件。

        Args:
            config: AgentSSASConfig 配置实例,用于解析存储根目录。
        """
        self._config = config
        # 输出目录:<storage_path>/reports/threat_log
        self._output_dir = Path(config.storage_path) / "reports" / "threat_log"
        self._output_dir.mkdir(parents=True, exist_ok=True)

    async def render(self, report: dict) -> None:
        """构建 OCSF 格式报告并落盘。

        从 report 中获取 aux_ids(包含 trace_id、session_id 等)和
        event_node,调用 build_ocsf_report 构建完整的 OCSF 格式报告,
        落盘存储为 JSON 文件。

        Args:
            report: 威胁分析报告(简化格式),包含风险检测结果
                及 aux_ids(trace_id、session_id 等关联字段)、
                event_node 等信息。

        Raises:
            TypeError: report 不是 dict 类型时。
            ValueError: report 为空 dict 时。
        """
        if not isinstance(report, dict):
            raise TypeError(
                f"report 必须为 dict,实际类型: {type(report).__name__}"
            )
        if not report:
            raise ValueError("report 不能为空 dict")

        # 构建完整的 OCSF 格式报告
        ocsf_event = self._to_ocsf(report)

        # 落盘存储,文件名包含 trace_id、module_name 和本地时区可读时间
        # (YYYYMMDD_HHMMSS_mmm,冒号替换为下划线保证 Windows 文件名合法,
        # 毫秒保留避免同秒覆盖)
        aux_ids = report.get("aux_ids", {})
        trace_id = aux_ids.get("trace_id", "")
        safe_trace_id = trace_id or "notrace"
        module_name = report.get("module_name", "unknown")
        now = time.time()
        # DTZ006: 刻意使用本地时区(便于运维直接查看),非 UTC
        now_dt = datetime.fromtimestamp(now)  # noqa: DTZ006
        time_text = now_dt.strftime("%Y%m%d_%H%M%S") + f"_{int(now * 1000) % 1000:03d}"
        file_path = (
            self._output_dir
            / f"threat_{safe_trace_id}_{module_name}_{time_text}.json"
        )
        await self._write_json(file_path, ocsf_event)

    @staticmethod
    def _to_ocsf(report: dict) -> dict:
        """构建 OCSF Detection Finding 格式。

        委托 ocsf.build_ocsf_report 完成实际构建,此方法保留
        作为插件的扩展点,子类可覆写以定制格式。

        Args:
            report: 威胁分析报告(简化格式),包含 aux_ids、event_node、
                has_risk、risk_level、module_name、title、description 等。

        Returns:
            OCSF Detection Finding 格式 dict。
        """
        return build_ocsf_report(report)

    @staticmethod
    def _parse_filename_timestamp(file_name: str) -> float | None:
        """从报告文件名解析时间戳(Unix 秒)。

        文件名格式 threat_{trace}_{module}_{YYYYMMDD_HHMMSS}_{mmm}.json,
        尾部三段数字(日期_时间_毫秒)即渲染时刻。解析失败返回 None。

        Args:
            file_name: 报告文件名。

        Returns:
            渲染时刻的 Unix 时间戳(本地时区);无法解析时返回 None。
        """
        match = _FILENAME_TIME_PATTERN.search(file_name)
        if match is None:
            return None
        try:
            # DTZ006: 文件名时间为本地时区(渲染时刻),非 UTC
            dt = datetime.strptime(  # noqa: DTZ007
                f"{match.group(1)}{match.group(2)}", "%Y%m%d%H%M%S"
            )
            return dt.timestamp()
        except ValueError:
            return None

    async def cleanup_expired(
        self, ttl_days: int, now: float | None = None
    ) -> int:
        """清理超过 TTL 的威胁报告 JSON 文件,返回删除的文件数。

        扫描输出目录下所有 *.json 文件,按文件名内嵌的渲染时间戳
        (解析失败回退文件 mtime)判断是否超过保留期,删除过期文件。
        单个文件删除失败(如 Windows 句柄占用)记日志跳过,不抛异常。
        ttl_days <= 0 视为禁用清理(与现有 TTL 语义一致)。

        Args:
            ttl_days: 报告文件保留天数。<= 0 时不执行清理(禁用语义)。
            now: 当前时间戳(Unix 秒)。None 时取 time.time()。

        Returns:
            删除的文件数。TTL 禁用或目录不存在时返回 0。
        """
        if ttl_days <= 0:
            return 0

        current = now if now is not None else time.time()
        cutoff = current - ttl_days * 86400

        return await asyncio.to_thread(self._cleanup_expired_sync, cutoff)

    def _cleanup_expired_sync(self, cutoff: float) -> int:
        """同步删除过期报告文件(通过线程调用)。"""
        if not self._output_dir.is_dir():
            return 0

        deleted = 0
        for file_path in self._output_dir.glob("*.json"):
            file_ts = self._parse_filename_timestamp(file_path.name)
            if file_ts is None:
                # 文件名无时间戳(非标准命名),回退文件 mtime
                try:
                    file_ts = file_path.stat().st_mtime
                except OSError:
                    continue
            if file_ts >= cutoff:
                continue
            try:
                file_path.unlink()
                deleted += 1
            except OSError:
                # Windows 下句柄占用等场景:记日志跳过,不中断清理
                logger.warning(
                    "删除过期威胁报告失败,跳过: file=%s", file_path
                )
        return deleted

    async def _write_json(self, file_path: Path, data: dict) -> None:
        """异步写入 JSON 文件。

        通过 asyncio.to_thread 将同步文件 I/O 操作放到线程中执行,
        避免阻塞事件循环。写入时使用 ensure_ascii=False 以支持中文,
        indent=2 保证可读性。

        Args:
            file_path: 目标 JSON 文件路径。
            data: 待写入的 dict 数据。
        """
        await asyncio.to_thread(self._write_json_sync, file_path, data)

    @staticmethod
    def _write_json_sync(file_path: Path, data: dict) -> None:
        """同步写入 JSON 文件(供 _write_json 通过线程调用)。

        使用 utf-8 编码写入,ensure_ascii=False 支持中文,
        indent=2 保证可读性。

        Args:
            file_path: 目标 JSON 文件路径。
            data: 待写入的 dict 数据。
        """
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
