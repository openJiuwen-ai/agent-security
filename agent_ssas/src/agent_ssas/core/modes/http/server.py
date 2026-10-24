# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

# agent_ssas/core/modes/http/server.py
"""AgentSSAS HTTP 服务模式启动入口。

通过 uvicorn 启动 FastAPI 应用,监听事件上报请求。

启动方式:
    python -m agent_ssas.core.modes.http.server

监听地址与端口来自 AgentSSASConfig,可由环境变量 SSAS_HTTP_HOST、
SSAS_HTTP_PORT 覆盖。未设置 SSAS_HTTP_HOST 时只绑定本机回环地址,
避免管理端口暴露在全部网络接口上。
"""

from __future__ import annotations

import uvicorn

from agent_ssas.core.framework.access_adapter.http_server import create_app
from agent_ssas.core.framework.config.settings import AgentSSASConfig


def main() -> None:
    """启动 AgentSSAS HTTP 服务端。"""
    config = AgentSSASConfig()
    app = create_app(config)
    uvicorn.run(
        app,
        host=config.http_host,
        port=config.http_port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
