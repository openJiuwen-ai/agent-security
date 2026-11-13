# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Session-owned foreground and background execution manager."""

import asyncio
import logging
import sys
from collections.abc import Awaitable, Callable
from contextlib import AbstractContextManager, asynccontextmanager
from pathlib import Path
from typing import Any

from agent_shield.tool_permission.runtime.engine import HostPolicyAdapter, PermissionEngine

from .bridge import RuntimeApprovalRequests, WindowsGuardExecution
from .contracts import (
    PersistApproval,
    PolicyRevision,
    ProgramDecision,
    RuntimeApprovalEvent,
    RuntimePersistenceEvent,
    TakeApproval,
)
from .errors import GuardPolicyDenied
from .launcher import LaunchAdapter, bind_process_launcher
from .policy import SessionResourceGrants, is_command_tool


class RuntimeGuardManager:
    """Own Jobs until the process tree ends, even after the tool has returned."""

    def __init__(
        self,
        *,
        session_id: str,
        engine: PermissionEngine | Callable[[], PermissionEngine | HostPolicyAdapter],
        dll: str | Path | Callable[[], str | Path],
        enabled: Callable[[], bool] | None = None,
        revision: PolicyRevision | None = None,
        execution_factory: Callable[..., WindowsGuardExecution] = WindowsGuardExecution,
        take_approval: TakeApproval | None = None,
        program_decision: ProgramDecision | None = None,
        emit: Callable[[RuntimeApprovalEvent], Awaitable[None]] | None = None,
        approval_timeout: float = 120,
        notify: Callable[[RuntimePersistenceEvent], Awaitable[None]] | None = None,
        persist: PersistApproval | None = None,
        approvals: RuntimeApprovalRequests | None = None,
        bind_launcher: Callable[[LaunchAdapter], AbstractContextManager] = bind_process_launcher,
    ):
        self.session_id, self.engine = session_id, engine
        self.dll = dll if callable(dll) else Path(dll)
        self.enabled = enabled or (lambda: True)
        self.revision, self.execution_factory = revision, execution_factory
        self.bind_launcher = bind_launcher
        self.emit = emit
        self.approval_timeout = approval_timeout
        self.notify = notify
        self.persist = persist
        self.approvals = approvals if approvals is not None else RuntimeApprovalRequests()
        self.take_approval = take_approval
        self.program_decision = program_decision
        self.active: dict[WindowsGuardExecution, asyncio.Task | None] = {}
        self.watchers: set[asyncio.Task] = set()
        self.closing = False
        self.session_grants = SessionResourceGrants()

    @asynccontextmanager
    async def tool_execution(
        self,
        *,
        tool_name: str,
        inputs: dict[str, Any],
        session: Any,
        tool_call_id: str | None,
        channel: str | None = None,
    ):
        if not self.enabled():
            yield
            return
        if self.closing or not self.session_id or not tool_call_id:
            raise RuntimeError("DLL Guard has no active owning session/tool call")
        execution = None
        launch_lock = asyncio.Lock()
        owner = asyncio.current_task()

        async def decide_program(subject, result):
            if self.program_decision is None:
                return None
            return await self.program_decision(
                {**subject, "source_tool": tool_name, "source_shell": execution.source_shell},
                result,
                session=session,
                tool_call_id=tool_call_id,
                execution_id=execution.context.execution_id,
            )

        async def launch(factory, *args, **kwargs):
            nonlocal execution
            async with launch_lock:
                if self.closing:
                    raise RuntimeError("DLL Guard session is closing")
                if execution is None:
                    execution = self.execution_factory(
                        session_id=self.session_id,
                        tool_call_id=tool_call_id,
                        dll=self.dll() if callable(self.dll) else self.dll,
                        engine=self.engine,
                        emit=self.emit,
                        approval_timeout=self.approval_timeout,
                        persist=self.persist,
                        approvals=self.approvals,
                        policy_revision=self.revision,
                        notify=self.notify,
                        session_grants=self.session_grants,
                        channel=channel,
                        root_command_approved=is_command_tool(tool_name),
                        program_decision=decide_program,
                        source_tool=tool_name,
                    )
                    self.active[execution] = owner
                    await execution.__aenter__()
                    if self.take_approval is not None:
                        approval = self.take_approval(tool_call_id, tool_name, inputs)
                        if approval:
                            execution.seed_approved_operation(approval)
            return await execution.launch(factory, *args, **kwargs)

        keep_background = False
        try:
            with self.bind_launcher(launch):
                yield
            keep_background = True
        except GuardPolicyDenied:
            keep_background = True
            raise
        finally:
            if execution is not None:
                retained = keep_background and not self.closing and execution.job
                if retained and execution.job.active_processes():
                    # The root may already have exited; Job membership is authoritative.
                    self.active[execution] = None
                    watcher = asyncio.create_task(self._watch(execution))
                    self.watchers.add(watcher)
                    watcher.add_done_callback(self._watch_done)
                else:
                    pending = sys.exception()
                    try:
                        await self._release(execution)
                    except Exception:  # noqa: BLE001 -- keep the tool failure when cleanup also fails
                        logging.getLogger(__name__).exception("DLL Guard cleanup failed")
                        if pending is None:
                            raise

    async def _release(self, execution):
        await execution.close()
        self.active.pop(execution, None)

    def _watch_done(self, task):
        self.watchers.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logging.getLogger(__name__).error(
                "DLL Guard background cleanup failed", exc_info=task.exception()
            )

    async def _watch(self, execution):
        try:
            while execution.context.active and execution.job.active_processes():
                await asyncio.sleep(0.1)
        finally:
            await self._release(execution)

    async def close(self, *, permanent=False):
        self.closing = True
        current = asyncio.current_task()
        tasks = {task for task in self.active.values() if task is not None and task is not current}
        tasks.update(self.watchers)
        for task in tasks:
            task.cancel()
        errors = []
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            errors.extend(result for result in results if isinstance(result, Exception))
        for execution in list(self.active):
            try:
                await self._release(execution)
            except Exception as exc:  # noqa: BLE001 -- release every Job before reporting cleanup failures
                errors.append(exc)
        self.closing = permanent or bool(self.active)
        if permanent:
            self.session_grants.clear()
        if errors:
            raise ExceptionGroup("DLL Guard cleanup failed", errors)
