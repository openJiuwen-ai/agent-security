"""IPC accepts complete long requests and still rejects invalid framing."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from agent_shield.intercepts.native_call.dll_guard.bridge import (
    _MAX_REQUEST_BYTES,
    _REPLY,
    _REQUEST,
    _PipeRequest,
)


def request():
    owner = SimpleNamespace(check_resource=AsyncMock(return_value=True))
    protocol = _PipeRequest(owner)
    protocol.pid = 123
    protocol.transport = Mock()
    protocol.transport.is_closing.return_value = False
    protocol.deadline = Mock()
    return owner, protocol


@pytest.mark.asyncio
@pytest.mark.parametrize("length", [8193, 70000, _MAX_REQUEST_BYTES])
async def test_fragmented_long_request_reaches_policy_without_truncation(length):
    owner, protocol = request()
    resource = "https://example.test/" + "x" * (length - len("https://example.test/"))
    body = resource.encode("utf-8")
    header = _REQUEST.pack(0x44475231, 123, 7, 32, len(body))
    protocol.data_received(header[:7])
    protocol.data_received(header[7:] + body[:4096])
    owner.check_resource.assert_not_awaited()
    protocol.data_received(body[4096:])
    await protocol.task
    owner.check_resource.assert_awaited_once_with(123, {"kind": "url", "url": resource})
    assert _REPLY.unpack(protocol.transport.write.call_args.args[0]) == (0x44475031, 7, 1)
    protocol.deadline.cancel.assert_called_once()
    protocol.transport.close.assert_called_once()


@pytest.mark.parametrize(
    "magic,pid,length",
    [
        (0, 123, 1),
        (0x44475231, 999, 1),
        (0x44475231, 123, 0),
        (0x44475231, 123, _MAX_REQUEST_BYTES + 1),
    ],
)
def test_invalid_header_closes_before_policy(magic, pid, length):
    owner, protocol = request()
    protocol.data_received(_REQUEST.pack(magic, pid, 7, 32, length))
    assert protocol.task is None
    owner.check_resource.assert_not_awaited()
    protocol.transport.close.assert_called_once()


@pytest.mark.asyncio
@pytest.mark.parametrize("action,source_mask", [(16, 8), (17, 2)])
async def test_rename_and_link_keep_distinct_source_actions(action, source_mask):
    owner, protocol = request()
    owner.check_file_batch = AsyncMock(return_value=True)
    await getattr(protocol, "_respond")(7, action, b"C:/source.txt\0C:/target.txt")
    owner.check_file_batch.assert_awaited_once_with(
        123, [("C:/source.txt", source_mask), ("C:/target.txt", 2)]
    )
    assert _REPLY.unpack(protocol.transport.write.call_args.args[0]) == (0x44475031, 7, 1)
