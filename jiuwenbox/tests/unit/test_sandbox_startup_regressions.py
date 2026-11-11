# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Windows startup must acknowledge a usable backend, with no privileged tests."""
# pylint: disable=protected-access
# Test backend startup directly without entering the privileged app lifespan.
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from jiuwenbox.models.policy import NetworkRulePolicy, SecurityPolicy
from jiuwenbox.server import app as server
from jiuwenbox.supervisor import win_proxy, win_setup


def _backend(monkeypatch):
    reader = SimpleNamespace(load_policy=Mock(return_value=SecurityPolicy()), policy_path='policy.yaml')
    monkeypatch.setattr(win_setup, 'collect_preinstall_paths', Mock(return_value=[]))
    setup = Mock()
    monkeypatch.setattr(win_setup, 'ensure_windows_setup', setup)
    proxy = AsyncMock(return_value=(None, None))
    monkeypatch.setattr(win_proxy, 'serve_windows_proxy', proxy)
    monkeypatch.setenv('JIUWENBOX_SOFT_DELETE', '0')
    monkeypatch.setattr(server, '_win_proxy_task', None)
    monkeypatch.setattr(server, '_win_proxy_stop_event', None)
    return reader, setup, proxy


def test_invalid_root_policy_cannot_mutate_acl_with_default_setup_arguments(monkeypatch):
    reader, setup, proxy = _backend(monkeypatch)
    reader.load_policy.side_effect = ValueError('invalid root policy')
    with pytest.raises(ValueError, match='invalid root policy'):
        asyncio.run(server._start_windows_backend(reader))
    setup.assert_not_called()
    proxy.assert_not_called()


def test_setup_failure_is_not_reported_as_backend_startup_success(monkeypatch):
    reader, setup, proxy = _backend(monkeypatch)
    setup.side_effect = RuntimeError('setup incomplete')
    with pytest.raises(RuntimeError, match='setup incomplete'):
        asyncio.run(server._start_windows_backend(reader))
    proxy.assert_not_called()


def test_proxy_failure_is_not_reported_as_backend_startup_success(monkeypatch):
    reader, _, proxy = _backend(monkeypatch)
    proxy.side_effect = OSError('port occupied')
    with pytest.raises(OSError, match='port occupied'):
        asyncio.run(server._start_windows_backend(reader))


def test_backend_setup_and_proxy_use_one_policy_snapshot(monkeypatch):
    reader, setup, proxy = _backend(monkeypatch)
    reader.load_policy.side_effect = [SecurityPolicy(), ValueError('changed after setup')]
    asyncio.run(server._start_windows_backend(reader))
    assert reader.load_policy.call_count == 1
    assert setup.call_args.kwargs['allow_elevation'] is False
    assert setup.call_args.kwargs['proxy_port_start'] == proxy.call_args.kwargs['port_range_start']


@pytest.mark.parametrize('failure', [OSError('bind failed'), ValueError('bind failed')])
def test_proxy_bind_failure_is_raised_before_returning_a_successful_task(monkeypatch, failure):
    async def run():
        monkeypatch.setattr(win_proxy.asyncio, 'start_server', AsyncMock(side_effect=failure))
        task = None
        stop = asyncio.Event()
        try:
            with pytest.raises(type(failure), match='bind failed'):
                task, _ = await win_proxy.serve_windows_proxy(NetworkRulePolicy(), stop_event=stop)
        finally:
            stop.set()
            if task is not None:
                await task
    asyncio.run(run())


def test_proxy_cancel_during_bind_leaves_no_listener_tasks(monkeypatch):
    async def run():
        binding = asyncio.Event()
        cancelled = asyncio.Event()

        async def bind(*_args, **_kwargs):
            binding.set()
            try:
                await asyncio.Event().wait()
            finally:
                cancelled.set()

        monkeypatch.setattr(win_proxy.asyncio, 'start_server', bind)
        task = asyncio.create_task(win_proxy.serve_windows_proxy(NetworkRulePolicy()))
        await asyncio.wait_for(binding.wait(), 1)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0)
        assert cancelled.is_set()
        assert not [
            t for t in asyncio.all_tasks()
            if t is not asyncio.current_task() and t.get_name().startswith('win-proxy')
        ]
    asyncio.run(run())


def test_real_occupied_loopback_port_prevents_proxy_startup():
    async def run():
        listener = await asyncio.start_server(lambda _r, w: w.close(), '127.0.0.1', 0)
        try:
            port = listener.sockets[0].getsockname()[1]
            with pytest.raises(OSError):
                await win_proxy.serve_windows_proxy(NetworkRulePolicy(), port_range_start=port, port_range_end=port)
        finally:
            listener.close()
            await listener.wait_closed()
    asyncio.run(run())


def test_successful_proxy_returns_only_after_bind_and_closes_on_stop(monkeypatch):
    async def run():
        listener = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
        bind = AsyncMock(return_value=listener)
        monkeypatch.setattr(win_proxy.asyncio, 'start_server', bind)
        task, stop = await win_proxy.serve_windows_proxy(
            NetworkRulePolicy(), port_range_start=61000, port_range_end=61001,
        )
        try:
            assert bind.await_count == 1
            assert bind.call_args.kwargs == {'host': '127.0.0.1', 'port': 61000}
        finally:
            stop.set()
            await task
        listener.close.assert_called_once()
        listener.wait_closed.assert_awaited_once()
    asyncio.run(run())


@pytest.mark.parametrize('failure', [OSError('listener failed'), ValueError('listener failed')])
def test_proxy_listener_failure_after_ready_reaches_the_returned_task(monkeypatch, failure):
    async def run():
        trigger = asyncio.Event()

        class BrokenStop:
            async def wait(self):
                await trigger.wait()
                raise failure

        listener = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
        monkeypatch.setattr(win_proxy.asyncio, 'start_server', AsyncMock(return_value=listener))
        task, _ = await win_proxy.serve_windows_proxy(NetworkRulePolicy(), stop_event=BrokenStop())
        trigger.set()
        with pytest.raises(type(failure), match='listener failed'):
            await task
        listener.close.assert_called_once()
        listener.wait_closed.assert_awaited_once()
    asyncio.run(run())
