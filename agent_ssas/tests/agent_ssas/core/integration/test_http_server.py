# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

# tests/agent_ssas/core/integration/test_http_server.py
"""FastAPI HTTP 服务端端点测试。

使用 httpx.AsyncClient + ASGI transport 测试 FastAPI,不启动真实端口。
"""

import uuid

import httpx
import pytest
from agent_ssas.core.framework.access_adapter.http_server import create_app
from agent_ssas.core.framework.config.settings import AgentSSASConfig
from httpx import ASGITransport

# 运行时生成,避免在源码中写入 token 字面量(静态检查)。
TEST_TOKEN = uuid.uuid4().hex
ANY_HOST = "0.0.0.0"
LOOPBACK_HOST = "127.0.0.1"
DOC_HOST = "192.0.2.10"


@pytest.fixture
def ssas_config(tmp_path):
    """测试用 AgentSSASConfig,指向临时目录。"""
    return AgentSSASConfig(ssas_home=str(tmp_path))


@pytest.fixture
def app(ssas_config):
    """创建 FastAPI 应用。"""
    return create_app(ssas_config)


@pytest.fixture
async def client(app):
    """创建 httpx 异步客户端,通过 ASGI transport 直连 FastAPI。"""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.integration
@pytest.mark.level1
class TestHttpServer:
    """FastAPI 端点测试。"""

    @pytest.mark.asyncio
    async def test_post_events_returns_assessment(self, client):
        """POST /api/v1/events 正常请求返回 RiskAssessment。"""
        raw_event = {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "tool_input",
                "event_class": "lifecycle",
                "timestamp": 1715000000.0,
                "interaction_seq": 0,
                "session_id": "session-001",
                "conversation_id": "session-001",
                "agent_id": "deep-agent-1",
                "trace_id": "trace-001",
                "context_id": "ctx-001",
                "llm_call_seq": 0,
                "tool_call_seq": 0,
                "subsession_id": "",
                "tool_call_id": "call_abc123",
            },
            "payload": {
                "content": {"tool_args": {"command": "ls -la"}},
                "tool_name": "bash",
                "tool_call_id": "call_abc123",
            },
            "metadata": {},
        }
        resp = await client.post("/api/v1/events", json={"raw_event": raw_event})
        assert resp.status_code == 200
        data = resp.json()
        assert "assessment" in data
        assessment = data["assessment"]
        assert "risk_level" in assessment
        assert "has_risk" in assessment

    @pytest.mark.asyncio
    async def test_post_events_empty_raw_event(self, client):
        """空 raw_event 请求时 fail-open 返回无风险。"""
        resp = await client.post(
            "/api/v1/events", json={"raw_event": {}}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["assessment"]["risk_level"] == "safe"
        assert data["assessment"]["has_risk"] is False

    @pytest.mark.asyncio
    async def test_post_events_security_event_high_risk(self, client):
        """安全检测事件(notify 模式下返回 SAFE)。"""
        raw_event = {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "permission_interrupt_tool",
                "event_class": "security",
                "timestamp": 1715000005.0,
                "interaction_seq": 0,
                "session_id": "session-001",
                "conversation_id": "session-001",
                "agent_id": "deep-agent-1",
                "trace_id": "trace-001",
                "context_id": "ctx-001",
                "llm_call_seq": 0,
                "tool_call_seq": 0,
                "subsession_id": "",
                "tool_call_id": "call_abc123",
            },
            "payload": {
                "content": {"tool_args": {"command": "rm -rf /"}},
                "tool_name": "bash",
                "tool_call_id": "call_abc123",
                "risk_source": "PermissionInterruptRail",
                "risk_type": "tool_permission_denied",
                "risk_level": "high",
                "decision": "reject",
                "evidence": {"reason": "PermissionInterruptRail denied"},
            },
            "metadata": {},
        }
        resp = await client.post("/api/v1/events", json={"raw_event": raw_event})
        assert resp.status_code == 200
        assessment = resp.json()["assessment"]
        assert assessment["risk_level"] == "safe"
        assert assessment["has_risk"] is False

    @pytest.mark.asyncio
    async def test_health_check(self, client):
        """健康检查端点。"""
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


def _make_raw_event_payload() -> dict:
    """构造最小合法 raw_event 请求体。"""
    return {
        "raw_event": {
            "common": {
                "source": "AgentSSASSecurityRail",
                "event_type": "invoke_start",
                "event_class": "lifecycle",
                "timestamp": 1715000000.0,
                "interaction_seq": 0,
                "session_id": "session-auth",
                "conversation_id": "session-auth",
                "agent_id": "deep-agent-1",
                "trace_id": "trace-auth",
                "context_id": "ctx-auth",
                "llm_call_seq": -1,
                "tool_call_seq": -1,
                "subsession_id": "",
                "tool_call_id": "",
            },
            "payload": {},
            "metadata": {},
        }
    }


@pytest.mark.integration
@pytest.mark.level1
class TestTokenAuth:
    """Bearer token 认证中间件测试(TokenAuthMiddleware)。

    补齐 issue 测试承诺"覆盖维度-安全"中缺失的 token 认证 401 测试。
    """

    @pytest.mark.asyncio
    async def test_no_token_configured_allows_requests(self, tmp_path):
        """未配置 http_token 时请求正常放行(不启用认证)。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path))
        assert config.http_token is None
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/events", json=_make_raw_event_payload())
            assert resp.status_code == 200
            assert "assessment" in resp.json()

    @pytest.mark.parametrize("token", ["", "   ", "\t\n"])
    def test_empty_token_is_rejected(self, tmp_path, token):
        """空 token 视为配置错误:启动即失败,不能静默关闭认证。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token=token)
        with pytest.raises(ValueError, match="http_token"):
            create_app(config)

    def test_empty_env_token_is_rejected(self, tmp_path, monkeypatch):
        """SSAS_HTTP_TOKEN 为空字符串时同样拒绝启动。"""
        monkeypatch.setenv("SSAS_HTTP_TOKEN", "")
        config = AgentSSASConfig.from_dict({"ssas_home": str(tmp_path)})
        assert config.http_token == ""
        with pytest.raises(ValueError, match="http_token"):
            create_app(config)

    @pytest.mark.asyncio
    async def test_surrounding_whitespace_in_token_is_ignored(self, tmp_path):
        """token 两端空白被忽略,避免部署注入换行导致认证不可用。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token=f"  {TEST_TOKEN}\n")
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            ok = await client.post(
                "/api/v1/events",
                json=_make_raw_event_payload(),
                headers={"Authorization": f"Bearer {TEST_TOKEN}"},
            )
            missing = await client.post("/api/v1/events", json=_make_raw_event_payload())
            assert ok.status_code == 200
            assert missing.status_code == 401

    @pytest.mark.asyncio
    async def test_token_configured_missing_header_returns_401(self, tmp_path):
        """配置 token 后无 Authorization 头返回 401。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token="secret-token")
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post("/api/v1/events", json=_make_raw_event_payload())
            assert resp.status_code == 401
            assert resp.json() == {"detail": "Unauthorized"}

    @pytest.mark.asyncio
    async def test_token_configured_wrong_token_returns_401(self, tmp_path):
        """配置 token 后错误 token 返回 401。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token="secret-token")
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/events",
                json=_make_raw_event_payload(),
                headers={"Authorization": "Bearer wrong-token"},
            )
            assert resp.status_code == 401
            assert resp.json() == {"detail": "Unauthorized"}

    @pytest.mark.asyncio
    async def test_token_configured_correct_token_returns_200(self, tmp_path):
        """配置 token 后正确 token 请求返回 200。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token="secret-token")
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.post(
                "/api/v1/events",
                json=_make_raw_event_payload(),
                headers={"Authorization": "Bearer secret-token"},
            )
            assert resp.status_code == 200
            assert "assessment" in resp.json()

    @pytest.mark.asyncio
    async def test_health_endpoint_exempt_from_auth(self, tmp_path):
        """/health 端点免认证(token 配置后仍可直接访问)。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_token="secret-token")
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            resp = await client.get("/health")
            assert resp.status_code == 200
            assert resp.json() == {"status": "ok"}


@pytest.mark.integration
@pytest.mark.level1
class TestHttpExposure:
    """默认监听面与认证开关的组合约束。"""

    def test_default_host_is_loopback(self, tmp_path):
        """默认配置只绑定回环地址。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path))
        assert config.http_host == LOOPBACK_HOST

    @pytest.mark.parametrize("host", [ANY_HOST, "::", "", DOC_HOST])
    def test_non_loopback_without_token_is_rejected(self, tmp_path, host):
        """未启用认证时禁止绑定非回环地址,避免接口默认暴露到网络。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_host=host)
        with pytest.raises(ValueError, match="http_host"):
            create_app(config)

    def test_non_loopback_with_token_is_allowed(self, tmp_path):
        """显式配置 token 后允许绑定任意地址。"""
        config = AgentSSASConfig(
            ssas_home=str(tmp_path), http_host=ANY_HOST, http_token=TEST_TOKEN
        )
        assert create_app(config) is not None

    @pytest.mark.parametrize("host", [LOOPBACK_HOST, "localhost", "::1", "[::1]"])
    def test_loopback_without_token_is_allowed(self, tmp_path, host):
        """回环地址允许在无认证模式下使用。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path), http_host=host)
        assert create_app(config) is not None

    def test_main_applies_env_overrides(self, monkeypatch):
        """入口必须应用 SSAS_HTTP_HOST/SSAS_HTTP_TOKEN 环境变量。"""
        from agent_ssas.core.modes.http import server as http_mode_server

        monkeypatch.setenv("SSAS_HTTP_HOST", ANY_HOST)
        monkeypatch.setenv("SSAS_HTTP_TOKEN", TEST_TOKEN)
        called = {}
        monkeypatch.setattr(http_mode_server.uvicorn, "run", lambda app, **kw: called.update(kw))
        http_mode_server.main()
        assert called["host"] == ANY_HOST

    def test_main_rejects_exposed_unauthenticated(self, monkeypatch):
        """入口按环境变量绑定非回环地址且未配置 token 时必须拒绝启动。"""
        from agent_ssas.core.modes.http import server as http_mode_server

        monkeypatch.setenv("SSAS_HTTP_HOST", ANY_HOST)
        monkeypatch.delenv("SSAS_HTTP_TOKEN", raising=False)
        with pytest.raises(ValueError, match="http_host"):
            http_mode_server.main()

    def test_create_app_without_config_applies_env(self, monkeypatch):
        """create_app() 无参调用同样应用 SSAS_HTTP_* 环境变量。"""
        monkeypatch.setenv("SSAS_HTTP_HOST", ANY_HOST)
        monkeypatch.setenv("SSAS_HTTP_TOKEN", TEST_TOKEN)
        assert create_app() is not None

    def test_create_app_without_config_rejects_exposed_unauthenticated(self, monkeypatch):
        """create_app() 无参且环境变量未配置 token 时拒绝非回环绑定。"""
        monkeypatch.setenv("SSAS_HTTP_HOST", ANY_HOST)
        monkeypatch.delenv("SSAS_HTTP_TOKEN", raising=False)
        with pytest.raises(ValueError, match="http_host"):
            create_app()


@pytest.mark.integration
@pytest.mark.level1
class TestLifespanShutdown:
    """FastAPI lifespan shutdown 钩子测试。

    验证应用关闭时 backend.close() 被调用(释放 SQLite WAL 句柄等资源),
    以及懒初始化后端与 initialize_app 注入后端两种模式均被安全关闭。
    """

    @pytest.mark.asyncio
    async def test_shutdown_closes_lazy_initialized_backend(self, tmp_path):
        """懒初始化模式:处理过请求的后端在 shutdown 时被 close。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path))
        app = create_app(config)
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            # 触发懒初始化(首次请求创建后端)
            resp = await client.post(
                "/api/v1/events", json=_make_raw_event_payload()
            )
            assert resp.status_code == 200
            backend = app.state.ssas_backend
            assert backend is not None
            close_calls = []
            original_close = backend.close

            async def _spy_close():
                close_calls.append(1)
                await original_close()

            backend.close = _spy_close

            # 触发 lifespan shutdown(ASGITransport 不触发,手动驱动)
            async with app.router.lifespan_context(app):
                pass
            assert len(close_calls) == 1

    @pytest.mark.asyncio
    async def test_shutdown_closes_injected_backend(self, tmp_path):
        """initialize_app 注入模式:外部初始化的后端在 shutdown 时被 close。"""
        from agent_ssas.core.framework.access_adapter.http_server import (
            initialize_app,
        )

        config = AgentSSASConfig(ssas_home=str(tmp_path))
        app = create_app(config)
        await initialize_app(app, config)
        backend = app.state.ssas_backend
        assert backend is not None
        close_calls = []
        original_close = backend.close

        async def _spy_close():
            close_calls.append(1)
            await original_close()

        backend.close = _spy_close

        async with app.router.lifespan_context(app):
            pass
        assert len(close_calls) == 1

    @pytest.mark.asyncio
    async def test_shutdown_without_backend_is_noop(self, tmp_path):
        """未初始化后端(无请求)时 shutdown 安全跳过(空操作)。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path))
        app = create_app(config)
        assert app.state.ssas_backend is None
        # 不应抛错
        async with app.router.lifespan_context(app):
            pass

    @pytest.mark.asyncio
    async def test_shutdown_backend_close_exception_does_not_propagate(
        self, tmp_path,
    ):
        """backend.close() 抛异常时 shutdown 记 warning 不抛出(不阻断关闭)。"""
        config = AgentSSASConfig(ssas_home=str(tmp_path))
        app = create_app(config)
        app.state.ssas_backend = _FailingCloseBackend()

        # lifespan shutdown 捕获异常,不向外抛出
        async with app.router.lifespan_context(app):
            pass


class _FailingCloseBackend:
    """close() 抛异常的桩后端,验证 shutdown 容错。"""

    async def close(self):
        raise RuntimeError("simulated close failure")
