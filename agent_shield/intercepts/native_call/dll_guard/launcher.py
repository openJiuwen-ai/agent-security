# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Optional host launch adapter, scoped to the actual tool execution task."""

from __future__ import annotations

import logging
import sys
from asyncio.subprocess import Process
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from threading import Lock
from typing import Any

ProcessFactory = Callable[..., Awaitable[Process]]
LaunchAdapter = Callable[..., Awaitable[Process]]
_adapter: ContextVar[LaunchAdapter | None] = ContextVar(
    "local_process_launch_adapter", default=None
)
_approved_factory = ContextVar("dll_guard_process_factory", default=False)
_audit_lock = Lock()
_audit_installed = False


def _audit_process(event: str, _args: tuple) -> None:
    if event == "subprocess.Popen" and _adapter.get() is not None and not _approved_factory.get():
        token = _approved_factory.set(True)
        try:
            logging.getLogger(__name__).warning(
                "Subprocess started outside the DLL Guard launcher in a protected tool context"
            )
        finally:
            _approved_factory.reset(token)


async def start_guarded_factory(factory: ProcessFactory, *args: Any, **kwargs: Any) -> Process:
    token = _approved_factory.set(True)
    try:
        return await factory(*args, **kwargs)
    finally:
        _approved_factory.reset(token)


@contextmanager
def bind_process_launcher(adapter: LaunchAdapter) -> Iterator[None]:
    """Route create_process calls in the current tool_execution context to its launcher."""
    global _audit_installed
    if sys.platform == "win32" and not _audit_installed:
        with _audit_lock:
            if not _audit_installed:
                sys.addaudithook(_audit_process)
                _audit_installed = True
    token = _adapter.set(adapter)
    try:
        yield
    finally:
        _adapter.reset(token)


async def create_process(factory: ProcessFactory, *args: Any, **kwargs: Any) -> Process:
    """Preserve the normal subprocess path unless a host adapter is bound."""
    adapter = _adapter.get()
    if adapter is None:
        return await factory(*args, **kwargs)
    return await adapter(factory, *args, **kwargs)
