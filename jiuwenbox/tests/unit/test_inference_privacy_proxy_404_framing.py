# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""404 响应的 HTTP 帧正确性回归测试。

Content-Length 必须等于 body 实际字节数。历史上 404 分支硬编码
Content-Length: 20,而 body 是 "No route matched: <不定长路径>",
帧错位会让 keep-alive 客户端把 body 剩余字节当下一条响应的开头。
"""
import asyncio
import contextlib
import socket

import pytest
from jiuwenbox.iptext import ipv4
from jiuwenbox.proxy.inference_privacy_proxy import (
    InferencePrivacyProxy,
    InferencePrivacyProxyConfig,
    ProxyRoute,
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((ipv4(127, 0, 0, 1), 0))
        return sock.getsockname()[1]


async def _request_404(port: int, path: str) -> tuple[dict[str, str], bytes]:
    """发送请求,按 Content-Length 声明精确核对 body 字节数。"""
    reader, writer = await asyncio.open_connection(ipv4(127, 0, 0, 1), port)
    try:
        writer.write(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        await writer.drain()

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                raise AssertionError(f"connection closed before headers: {raw!r}")
            raw += chunk

        head, _, body = raw.partition(b"\r\n\r\n")
        headers: dict[str, str] = {}
        for line in head.decode("utf-8").split("\r\n")[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        content_length = int(headers["content-length"])

        # 声明的 body 可能已被第一次 read 一并读出,不足部分继续读
        while len(body) < content_length:
            body += await asyncio.wait_for(reader.read(content_length), timeout=5.0)
        # 多出来的字节说明 Content-Length 声明小于实际 body(帧错位)
        extra = body[content_length:]
        if not extra:
            extra = await asyncio.wait_for(reader.read(64), timeout=1.0)
        return headers, body[:content_length] + extra
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


@pytest.mark.asyncio
@pytest.mark.parametrize("path", ["/some/other/route", "/中文/路径"])
async def test_404_content_length_matches_body_bytes(path):
    port = _free_port()
    config = InferencePrivacyProxyConfig(
        listen_port=port,
        routes=[
            ProxyRoute(path_prefix="/openai", target_endpoint="https://api.openai.com"),
        ],
    )
    proxy = InferencePrivacyProxy(config)
    proxy.enable_route("/openai")
    await proxy.start()
    try:
        headers, body = await _request_404(port, path)
        assert headers.get("content-type") == "text/plain"
        # Content-Length 必须是 UTF-8 字节数:非 ASCII 路径下码点数 < 字节数,
        # 用 len(str) 会让 keep-alive 连接帧错位。
        expected = f"No route matched: {path}".encode()
        assert headers["content-length"] == str(len(expected))
        assert body == expected
    finally:
        await proxy.stop()
