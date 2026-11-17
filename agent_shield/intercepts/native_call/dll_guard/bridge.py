"""Running-operation approvals and authenticated, execution-owned Windows IPC."""

from __future__ import annotations

import asyncio
import ctypes as ct
import hashlib
import json
import logging
import os
import secrets
import struct
from collections.abc import Awaitable, Callable
from contextlib import ExitStack, asynccontextmanager
from copy import deepcopy
from ctypes import wintypes as wt
from dataclasses import is_dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

from agent_shield.tool_permission.runtime.command_identity import (
    bind_native_command,
    literal_shell_words,
    native_command_identity,
)
from agent_shield.tool_permission.runtime.confirmation import normalize_confirmation_scope
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.policy_engine.core.ruleset import load_grants
from agent_shield.tool_permission.runtime.models import (
    PermissionConfirmResponse,
    PermissionLevel,
    PermissionResult,
)

from .context import RuntimeGuardContext
from .events import device_class_for, device_open_path
from .contracts import (
    ApprovalReceipt,
    PersistApproval,
    PolicyRevision,
    RuntimeApprovalEvent,
    RuntimePersistenceEvent,
)
from .errors import (
    GuardError,
    GuardInjectionError,
    GuardPolicyDenied,
    GuardStartupError,
    GuardTargetArchitectureError,
)
from .policy import (
    approved_program_matches,
    canonical_domain,
    program_tool_args,
    remembered_resource,
    resource_grant,
    resource_grant_matches,
    resource_source,
    url_domain_subject,
)
from .shell_launch import approved_programs
from .task_rules import TaskRuleResult

if TYPE_CHECKING:
    from .pipe import GuardPipeServer
    from .windows import WindowsJob


_REQUEST = struct.Struct("<5I")
_REPLY = struct.Struct("<3I")
_MAX_REQUEST_BYTES = 128 * 1024  # Matches GUARD_MAX_REQUEST_BYTES in guard.c.


class RuntimeApprovalRequests:
    """Correlate answers with pending operations in the owning session."""

    def __init__(self) -> None:
        self._pending: dict[str, tuple[str, str, asyncio.Future, asyncio.Task]] = {}
        self._session_locks: dict[str, tuple[asyncio.Lock, int]] = {}
        self._channels: dict[str, str | None] = {}
        self.settlements = 0

    async def request(
        self,
        context: RuntimeGuardContext,
        resource: dict,
        emit: Callable[[RuntimeApprovalEvent], Awaitable[None]] | None,
        timeout: float,
        channel=None,
        *,
        result: PermissionResult | None = None,
    ) -> PermissionConfirmResponse:
        async with self.turn(context, channel) as request_id:
            return await self.prompt(request_id, context, resource, emit, timeout, result)

    @asynccontextmanager
    async def turn(self, context, channel):
        """Serialize the prompt and its grant settlement, including queued cancellation."""
        if not context.active:
            raise RuntimeError("Guard execution has ended")
        request_id = "dll-runtime:" + secrets.token_urlsafe(24)
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = (context.session_id, context.execution_id, future, asyncio.current_task())
        self._channels[request_id] = channel
        lock, users = self._session_locks.get(context.session_id, (asyncio.Lock(), 0))
        self._session_locks[context.session_id] = (lock, users + 1)
        try:
            async with lock:
                if not context.active or future.cancelled():
                    raise asyncio.CancelledError
                try:
                    yield request_id
                finally:
                    self.settlements += 1
        finally:
            self._pending.pop(request_id, None)
            self._channels.pop(request_id, None)
            _lock, users = self._session_locks[context.session_id]
            if users == 1:
                self._session_locks.pop(context.session_id)
            else:
                self._session_locks[context.session_id] = (lock, users - 1)
            if not future.done():
                future.cancel()

    async def prompt(self, request_id, context, resource, emit, timeout, result):
        if emit is None:
            raise RuntimeError("Runtime approval requires a host emit callback")
        future = self._pending[request_id][2]
        async with asyncio.timeout(timeout):
            await emit({
                "request_id": request_id,
                "tool_call_id": context.tool_call_id,
                "execution_id": context.execution_id,
                "session_id": context.session_id,
                "resource": deepcopy(resource),
                "reason": result.reason if result else None,
                "matched_rule": result.matched_rule if result else None,
            })
            return await future

    def resolve(self, session_id: str, request_id: str, answer: PermissionConfirmResponse) -> bool:
        pending = self._pending.get(request_id)
        if pending is None:
            return False
        try:
            normalized = PermissionConfirmResponse.from_host(answer)
            params = getattr(type(answer), "__dataclass_params__", None)
            if not (is_dataclass(answer) and getattr(params, "frozen", False)):
                answer = normalized
        except (ValueError, TypeError):
            return False
        session, _execution, future, _waiter = pending
        if session != session_id or future.done():
            return False
        future.set_result(answer)
        return True

    def cancel_execution(self, execution_id: str) -> None:
        for _session, execution, future, waiter in list(self._pending.values()):
            if execution == execution_id and not future.done():
                future.cancel()
                waiter.cancel()

    def cancel_channel(self, channel: str) -> None:
        for request_id, (_session, _execution, future, waiter) in list(self._pending.items()):
            if self._channels.get(request_id) == channel and not future.done():
                future.cancel()
                waiter.cancel()


class _PipeRequest(asyncio.Protocol):
    def __init__(self, owner: WindowsGuardExecution):
        self.owner = owner
        self.buffer = bytearray()
        self.transport: asyncio.Transport | None = None
        self.task: asyncio.Task[None] | None = None
        self.pid = 0

    def connection_made(self, transport) -> None:
        self.transport = transport
        handle = transport.get_extra_info("pipe").fileno()
        pid = wt.ULONG()
        job = self.owner.job
        if job is None:
            transport.close()
            return
        get_pid = job.api("GetNamedPipeClientProcessId", wt.BOOL, wt.HANDLE, ct.POINTER(wt.ULONG))
        if not get_pid(handle, ct.byref(pid)) or not job.contains(pid.value):
            transport.close()
            return
        self.pid = pid.value
        self.owner.connections.add(self)
        self.deadline = asyncio.get_running_loop().call_later(5, self._expire_header)

    def _expire_header(self) -> None:
        if self.task is None and self.transport is not None:
            self.transport.close()

    def data_received(self, data: bytes) -> None:
        if self.transport is None:
            return
        if not self.pid or self.task is not None:
            self.transport.close()
            return
        self.buffer.extend(data)
        if len(self.buffer) < _REQUEST.size:
            return
        magic, pid, sequence, action, length = _REQUEST.unpack_from(self.buffer)
        if magic != 0x44475231 or pid != self.pid or not 0 < length <= _MAX_REQUEST_BYTES:
            self.transport.close()
            return
        expected = _REQUEST.size + length
        if len(self.buffer) > expected:
            self.transport.close()
        elif len(self.buffer) == expected:
            self.deadline.cancel()
            self.task = asyncio.create_task(
                self._respond(sequence, action, bytes(self.buffer[_REQUEST.size:]))
            )

    async def _respond(self, sequence: int, action: int, data: bytes) -> None:
        allowed = False
        # Only clients that negotiated native cache support understand reply 2.
        cache_request = bool(action & 0x80000000)
        action &= 0x7FFFFFFF
        cacheable = False
        wait_handle = 0
        try:
            resource = data.decode("utf-8", errors="strict")
            cache_ready = cache_request and self.owner.has_native_cache()
            cache_request = cache_ready and self.owner.cache_engine.permission_checks_enabled
            if action in (42, 43):
                operation_id, payload = resource.split("\0", 1)
                if action == 42:
                    allowed = await self.owner.check_delete(self.pid, operation_id, payload)
                else:
                    allowed = self.owner.finish_delete(self.pid, operation_id, payload)
            elif action == 46:
                operation_id, path = resource.split("\0", 1)
                allowed = await self.owner.check_delete(self.pid, operation_id, path, recheck=True)
            elif action == 47:
                operation_id, payload = resource.split("\0", 1)
                allowed = self.owner.report_operation_stage(self.pid, operation_id, payload)
            elif action == 48:
                operation_id, stage, source, target, backup = resource.split("\0")
                phase = int(stage) & 255
                has_target = bool(int(stage) & 256)
                if phase in (2, 3):
                    paths = [(source, 8), (target, 10 if has_target else 2)]
                    if backup:
                        paths.append((backup, 2))
                    allowed = await self.owner.check_file_batch(
                        self.pid, paths, operation="replace" if phase == 3 else "rename",
                        operation_id=operation_id, reserve_delete=has_target,
                    )
                    if not has_target:
                        self.owner.note_finished_delete(
                            operation_id, self.pid, str(self.owner.file_path(target))
                        )
            elif action == 44:
                name, port = resource.split("\0")
                port = int(port)
                if 0 <= port <= 65535:
                    allowed = await self.owner.check_resource(self.pid, {
                        "kind": "connection", "hostname": canonical_domain(name), "port": port,
                    })
            elif action == 45:
                allowed = self.owner.context.active and self.owner.job.register_child_handle(
                    self.pid, int(resource), authorize=self.owner.authorize_child_identity,
                )
            elif action == 41:
                if not cache_request and resource == "cache" and self.owner.has_native_cache():
                    wait_handle = self.owner.duplicate_cache_wait(self.pid)
            elif action == 49:
                if not cache_request and resource == "ready":
                    wait_handle = self.owner.duplicate_ready_signal(self.pid)
            elif action == 50:
                if device_open_path(resource) is not None:
                    allowed = await self.owner.check_access(self.pid, resource, 2)
                else:
                    allowed = await self.owner.check_file_batch(
                        self.pid, [(resource, 2)], operation="hardlink_source_open"
                    )
            elif 65 <= action <= 79:
                allowed = await self.owner.check_named_pipe(self.pid, resource, action & 15)
            elif action in (16, 17, 18, 19):
                paths = resource.split("\0")
                kinds = {16: "rename", 17: "hardlink", 18: "copy", 19: "symlink"}
                masks = {16: (8, 2), 17: (2, 2), 18: (1, 2), 19: (1, 2)}
                kind = kinds.get(action)
                mask = masks.get(action)
                enough_paths = len(paths) == 2
                if kind is not None and mask is not None and enough_paths:
                    allowed = await self.owner.check_file_batch(
                        self.pid, list(zip(paths, mask)), operation=kind
                    )
            elif action == 32:
                allowed = await self.owner.check_resource(
                    self.pid, {"kind": "url", "url": resource}
                )
            elif action in (35, 36):
                check = (
                    self.owner.check_transport_resource
                    if action == 36
                    else self.owner.check_resource
                )
                allowed = await check(
                    self.pid,
                    {
                        "kind": "domain",
                        "hostname": canonical_domain(resource),
                    },
                )
            elif action in (33, 34, 37, 38):
                address, _, port = resource.rpartition(":")
                check = (
                    self.owner.check_transport_resource
                    if action in (37, 38)
                    else self.owner.check_resource
                )
                allowed = await check(
                    self.pid,
                    {
                        "kind": "endpoint",
                        "address": address.strip("[]"),
                        "port": int(port),
                        "protocol": "tcp" if action in (33, 37) else "udp",
                    },
                )
                endpoint_ready = cache_request and allowed and self.owner.has_native_cache()
                if endpoint_ready and action in (33, 34):
                    cacheable = self.owner.cacheable_endpoint(address, int(port))
            elif action == 40:
                from .windows import windows_argv

                fields = resource.split("\0")
                if len(fields) == 3:
                    executable, command, cwd = fields
                    allowed = await self.owner.check_resource(
                        self.pid,
                        {
                            "kind": "program",
                            "exe": str(self.owner.file_path(executable)),
                            "argv": windows_argv(command)[1:],
                            "command_line": command,
                            "cwd": str(self.owner.file_path(cwd)),
                        },
                    )
            elif 1 <= action <= 15:
                allowed = await self.owner.check_access(self.pid, resource, action)
                read_ready = cache_request and action == 1 and allowed
                cacheable = read_ready and self.owner.uniform_native_reads()
        except (ValueError, OSError, RuntimeError, asyncio.CancelledError) as exc:
            if action == 45:
                logging.getLogger(__name__).warning("Guard child registration failed for parent %s: %s", self.pid, exc)
        finally:
            if self.transport is not None and not self.transport.is_closing():
                answer = wait_handle if action in (41, 49) else (2 if cacheable else int(allowed))
                self.transport.write(_REPLY.pack(0x44475031, sequence, answer))
                self.transport.close()

    def connection_lost(self, exc) -> None:
        self.owner.connections.discard(self)
        if hasattr(self, "deadline"):
            self.deadline.cancel()
        if self.task is not None and not self.task.done():
            self.task.cancel()


class WindowsGuardExecution:
    """Bind an explicit ToolCall to an injected process tree and live approvals."""

    def __init__(
        self,
        *,
        session_id: str,
        tool_call_id: str,
        dll: Path,
        engine: Callable[[], Any] | PermissionEngine,
        emit: Callable[[RuntimeApprovalEvent], Awaitable[None]] | None,
        approvals: RuntimeApprovalRequests,
        approval_timeout: float = 120,
        persist: PersistApproval | None = None,
        persist_batch=None,
        policy_revision: PolicyRevision | None = None,
        subscribe_policy_changes=None,
        notify: Callable[[RuntimePersistenceEvent], Awaitable[None]] | None = None,
        session_grants=None,
        root_command_approved=False,
        channel=None,
        program_decision: Callable[[dict, PermissionResult], Awaitable[PermissionResult | None]]
        | None = None,
        source_tool=None,
        source_shell=None,
        native_command=None,
        delete_mode="recover",
        delete_ledger=None,
        task_id=None,
        audit=None,
    ):
        self.context = RuntimeGuardContext(session_id, tool_call_id, "initial")
        if delete_mode not in {"recover", "permanent"}:
            raise ValueError("Invalid delete mode")
        self.task_id = task_id or tool_call_id
        self.delete_ledger = delete_ledger if delete_ledger is not None else {"success": 0, "reserved": 0}
        self._delete_requests = {}
        self._finished_deletes = {}
        self._delete_versions = {}
        self._delete_subjects = {}
        self._operation_stages = set()
        self.audit = audit
        self.delete_mode = delete_mode
        self.dll_source = Path(dll).resolve()
        self._fixed_engine = engine if isinstance(engine, PermissionEngine) else None
        self.engine = (lambda: engine) if self._fixed_engine is not None else engine
        self.emit, self.approvals = emit, approvals
        self._cache = None
        self.cache_engine = None
        self._subscribe_policy_changes = subscribe_policy_changes
        self._unsubscribe_policy_changes = None
        self.approval_timeout = approval_timeout
        self.persist, self.policy_revision, self.notify = persist, policy_revision, notify
        self.persist_batch = persist_batch
        self.session_grants = session_grants
        self.root_command_approved = root_command_approved
        self.channel = channel
        self.program_decision = program_decision
        self.source_tool = source_tool
        self.source_shell = source_shell
        self.native_command = native_command
        self.approved_programs: list[dict] = []
        self._receipt_programs: list[dict] = []
        self._scoped_task_grants = {}
        self.approved_programs_version = None
        self._policy_state = None
        self._policy_version = None
        self.dll = None
        self.pipe_name = None
        self.bootstrap = None
        self.job: WindowsJob | None = None
        self.servers: list[GuardPipeServer] = []
        self._bundle_handles = ExitStack()
        self.ready = None
        self.connections: set[_PipeRequest] = set()
        self.pending: dict[str, asyncio.Task] = {}
        self._approval_operations = {}
        self._process_identities: dict[str, dict] = {}
        self._operation_processes: dict[str, dict] = {}
        self.processes: list[asyncio.subprocess.Process] = []
        self.launch_lock = asyncio.Lock()
        self.close_lock = asyncio.Lock()
        self.closed = False

    async def __aenter__(self):
        from .bundle import pin_guard_bundle, require_guard_platform

        require_guard_platform()
        from .pipe import GuardPipeServer
        from .windows import WindowsJob

        try:
            self.dll = self._bundle_handles.enter_context(pin_guard_bundle(self.dll_source))
            x86 = self.dll.parent.parent / "x86" / self.dll.name
            manifest_path = self.dll.with_suffix(".manifest.json")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            targets = manifest.get("target_architectures")
            if targets is None:
                raise ValueError("Guard manifest has no target architectures")
            if "x86" in targets:
                self._bundle_handles.enter_context(pin_guard_bundle(x86, architecture="x86"))
            self.job = WindowsJob()
            nonce = secrets.token_hex(16)
            pipe = os.path.join("\\\\.\\pipe", "jiuwen-guard-" + nonce)
            self.pipe_name = pipe
            event = "Local\\jiuwen-guard-ready-" + nonce
            if self._subscribe_policy_changes is not None or (
                self._fixed_engine is not None and self.policy_revision is None
            ):
                from .windows import CacheRevocation

                cache_engine = self.engine()
                cache = CacheRevocation(self.job)
                if cache_engine.register_native_cache(cache):
                    event += "-cache"
                    self._cache = cache
                    self.cache_engine = cache_engine
                    self.context.bind_cache_revoker(cache.revoke)
                    if self._subscribe_policy_changes is not None:
                        self._unsubscribe_policy_changes = self._subscribe_policy_changes(
                            lambda: cache_engine.revoke_native_cache(cache)
                        )
                        if not callable(self._unsubscribe_policy_changes):
                            raise ValueError("subscribe_policy_changes must return an unsubscribe callback")
                        # Catch a publication between reading the snapshot and subscribing.
                        if self.engine() is not cache_engine:
                            cache.revoke()
                else:
                    cache.close()
            create = self.job.api(
                "CreateEventW", wt.HANDLE, ct.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR
            )
            self.ready = self.job.check_result(create(None, True, False, event), "CreateEventW")
            config = struct.pack("<I", 0x44474333)
            for value in (pipe, event):
                config += (value + "\0").encode("utf-16-le").ljust(512, b"\0")
            self.bootstrap = config + struct.pack("<I", self.delete_mode == "permanent")
            self.servers = [GuardPipeServer(pipe, lambda: _PipeRequest(self))]
            return self
        except OSError as exc:
            await self.close()
            if isinstance(exc, GuardError):
                raise
            raise GuardStartupError(f"DLL Guard initialization failed: {exc}") from exc
        except BaseException:
            await self.close()
            raise

    async def launch(self, factory, *args, **kwargs):
        async with self.launch_lock:
            return await self._launch(factory, *args, **kwargs)

    async def _launch(self, factory, *args, **kwargs):
        if not self.context.active or self.job is None:
            raise RuntimeError("Guard execution is not active")
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | 0x4 | 0x08000000
        process = await factory(*args, **kwargs)
        self.processes.append(process)
        try:
            try:
                self.job.attach(process.pid)
                executable = self.job.process_image(process.pid)
                command_line = self.job.process_command_line(process.pid)
            except OSError as exc:
                raise GuardStartupError(
                    f"Cannot establish Job ownership for PID {process.pid}: {exc}"
                ) from exc
            arguments = (
                ["/c", str(args[0])]
                if factory is asyncio.create_subprocess_shell
                else [str(arg) for arg in args[1:]]
            )
            if self.source_shell is None:
                self.source_shell = program_tool_args(
                    {
                        "exe": executable,
                        "argv": arguments,
                        "cwd": str(Path(kwargs.get("cwd") or os.getcwd()).resolve()),
                    },
                    self.source_tool,
                )["shell_type"]
            if not await self.check_resource(
                process.pid,
                {
                    "kind": "program",
                    "exe": executable,
                    "argv": arguments,
                    "command_line": command_line,
                    "cwd": str(Path(kwargs.get("cwd") or os.getcwd()).resolve()),
                    "root_command_approved": self.root_command_approved,
                },
            ):
                raise GuardPolicyDenied("Runtime policy denied program startup")
            reset = self.job.api("ResetEvent", wt.BOOL, wt.HANDLE)
            try:
                self.job.check_result(reset(self.ready), "ResetEvent")
                self.job.inject_and_resume(process.pid, self.dll, self.bootstrap)
            except (OSError, ValueError) as exc:
                if getattr(exc, "winerror", None) == 216:
                    raise GuardTargetArchitectureError("Unsupported Guard target architecture") from exc
                raise GuardInjectionError(
                    f"Guard setup failed for PID {process.pid}: {exc}"
                ) from exc
            wait = self.job.api("WaitForSingleObject", wt.DWORD, wt.HANDLE, wt.DWORD)
            status = await asyncio.to_thread(wait, self.ready, 5000)
            if status != 0:
                if process.returncode is not None:
                    raise GuardInjectionError(
                        f"Guard did not signal readiness before process exit (code {process.returncode:#x})"
                    )
                if status == 258:
                    raise GuardInjectionError("DLL Guard initialization timed out after 5 seconds")
                raise GuardInjectionError(f"Waiting for DLL Guard readiness failed ({status:#x})")
            logging.getLogger(__name__).info(
                "DLL Guard ready session=%s tool_call=%s execution=%s pid=%s",
                self.context.session_id,
                self.context.tool_call_id,
                self.context.execution_id,
                process.pid,
            )
            return process
        except GuardPolicyDenied:
            # A denied root is still suspended and cannot have descendants.
            try:
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                await asyncio.wait_for(process.communicate(), 5)
                self.processes.remove(process)
            except BaseException:
                await self.close()
                raise
            raise
        except BaseException:
            await self.close()
            raise

    def _policy(self):
        engine, version, _ = self._refresh_policy()
        return engine, version

    def _refresh_policy(self, *, added_grants=()):
        """Return the live snapshot and the prior version compatible with this save."""
        engine = self.engine()
        state = {
            "config": engine.config,
            "trusted_dirs": engine.trusted_dirs,
            "permission_checks_enabled": engine.permission_checks_enabled,
            "host_revision": self.policy_revision() if self.policy_revision else None,
            "task_policy": getattr(getattr(engine, "task_rules", None), "policy_document", None),
        }
        previous_version = self._policy_version
        compatible_save = False
        if state != self._policy_state:
            revision = hashlib.sha256(
                json.dumps(state, sort_keys=True, default=str).encode()
            ).hexdigest()
            compatible_save = bool(added_grants) and self._only_added_grants(state, added_grants)
            preserve = compatible_save and self._policy_state["host_revision"] == state["host_revision"]
            self.context.update_policy_version(revision, preserve_grants=preserve)
            if preserve and self.approved_programs_version == previous_version:
                self.approved_programs_version = revision
            if not preserve:
                self._receipt_programs.clear()
                self._scoped_task_grants.clear()
            self._policy_state = deepcopy(state)
            self._policy_version = revision
        return engine, self._policy_version, previous_version if compatible_save else None

    def has_native_cache(self) -> bool:
        return self._cache is not None

    def uniform_native_reads(self) -> bool:
        engine = self.cache_engine
        return engine is not None and engine.uniform_native_reads

    def authorize_child_identity(self, identity):
        """Bind only the kernel-read child identity before its initial thread resumes."""
        from .pipe_security import PipeSecurity

        sid = identity["user_sid"]
        sids = set().union(*(server.security.allowed_sids for server in self.servers))
        if sid not in sids:
            # The target opens the ready event during DLL initialization.
            event_security = PipeSecurity(sids | {sid}, client_access=2)
            try:
                event_security.apply(self.ready)
            finally:
                event_security.close()
        for server in self.servers:
            server.allow_sid(sid)
        self._process_identities[identity["process_instance_id"]] = identity

    def duplicate_cache_wait(self, pid: int) -> int:
        if self._cache is None:
            return 0
        return self._cache.duplicate_wait_handle(pid)

    def duplicate_ready_signal(self, pid: int) -> int:
        if not self.context.active or self.job is None or not self.ready:
            return 0
        process = self.job.open_member(pid, 0x1040)
        if process is None:
            return 0
        try:
            remote = wt.HANDLE()
            duplicate = self.job.api("DuplicateHandle", wt.BOOL, wt.HANDLE, wt.HANDLE, wt.HANDLE,
                                     ct.POINTER(wt.HANDLE), wt.DWORD, wt.BOOL, wt.DWORD)
            if duplicate(-1, self.ready, process, ct.byref(remote), 2, False, 0):
                return remote.value
            return 0
        finally:
            self.job.close_handle(process)

    def cacheable_endpoint(self, address, port):
        if self._cache is None or not self.cache_engine.permission_checks_enabled:
            return False
        return self.cache_engine.check_network_access(f"{address}:{port}").is_allowed

    def _only_added_grants(self, state, added_grants):
        """Preserve old approvals only for the exact delta this execution just saved.

        Concurrent rule/host changes, removed approvals and changed scopes invalidate
        everything as before. A compose revision bump alone is metadata for this save.
        """
        if self._policy_state is None:
            return False
        old, new = deepcopy(self._policy_state), deepcopy(state)
        for item in (old, new):
            item.pop("host_revision")
            config = item["config"]
            if isinstance(config.get("composition"), dict):
                config["composition"].pop("revision", None)
        if added_grants[0].get("action") == "allow":
            before = old["config"].setdefault("approval_overrides", [])
            after = new["config"].setdefault("approval_overrides", [])
        else:
            if not old["task_policy"] or not new["task_policy"]:
                return False
            before_task = old["task_policy"]["tasks"].get(self.task_id)
            after_task = new["task_policy"]["tasks"].get(self.task_id)
            if before_task is None or after_task is None:
                return False
            before = before_task.setdefault("grants", [])
            after = after_task.setdefault("grants", [])
        if not isinstance(before, list) or not isinstance(after, list):
            return False
        for grant in added_grants:
            if grant in before or after.count(grant) != 1:
                return False
            after.remove(grant)
        return old == new

    def seed_approved_accesses(self, accesses):
        """Host-only transfer from the permission card at the invocation boundary."""
        if not accesses:
            return
        _engine, version = self._policy()
        normalized = []
        for path, action in accesses:
            # Follow FileGuard's tool-path read fallback for the display label.
            if action == "access":
                action = "read"
            if action not in {"read", "write", "exec", "delete"}:
                raise ValueError("Invalid pre-approved file operation")
            normalized.append((str(self.file_path(path)), action))
        if not normalized:
            return
        subject = {"kind": "file", "accesses": sorted(set(normalized))}
        grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
        self.context.remember(resource_source(subject), grant, policy_version=version, from_receipt=True)

    def seed_approved_operation(self, approval: ApprovalReceipt):
        """Consume the host's take_approval receipt at the tool-call boundary.

        confirmation is the original answer, before deriving a default scope.
        """
        answer = approval.get("confirmation")
        operation = approval.get("operation")
        if not isinstance(operation, dict):
            return
        confirmed_grant = None
        if answer is not None:
            try:
                answer = (
                    PermissionConfirmResponse(**answer)
                    if isinstance(answer, dict)
                    else PermissionConfirmResponse.from_host(answer)
                )
                if not answer.approved:
                    return
                if any(
                    field is not None and not isinstance(field, str)
                    for field in (answer.authorization_mode, answer.authorization_scope)
                ):
                    return
                if operation.get("kind") in {"file", "url"}:
                    confirmed_grant = resource_grant(
                        operation, normalize_confirmation_scope(answer, operation)
                    )
            except (TypeError, ValueError):
                # Discard the entire receipt before seeding any permission.
                return
        self.seed_approved_accesses(approval.get("accesses", []))
        _engine, version = self._policy()
        if operation.get("kind") in {"file", "url"}:
            self._remember_resource(operation, version, from_receipt=True)
            if confirmed_grant is not None:
                self.context.remember(
                    resource_source(operation), confirmed_grant, policy_version=version, from_receipt=True
                )
            elif operation["kind"] == "file":
                # Older hosts hand off the selected file scope in the grants alone.
                for grant in approval.get("grants", []):
                    if resource_grant_matches(grant, operation):
                        self.context.remember(grant["tools"][0], grant, policy_version=version, from_receipt=True)
        elif operation.get("kind") == "command":
            for grant in approval.get("grants", []):
                if (
                    grant.get("tools") == ["file_resource"]
                    and json.loads(grant["pattern"]).get("scope") == "exact"
                ):
                    self.context.remember("file_resource", grant, policy_version=version, from_receipt=True)
        self.approved_programs = approved_programs(operation)
        self._receipt_programs = self.approved_programs.copy()
        self.approved_programs_version = version

    def _remember_resource(self, subject, version, *, from_receipt=False):
        grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
        self.context.remember(resource_source(subject), grant, policy_version=version, from_receipt=from_receipt)
        domain = url_domain_subject(subject)
        if domain is not None:
            grant = resource_grant(domain, PermissionConfirmResponse(approved=True))
            self.context.remember(resource_source(domain), grant, policy_version=version, from_receipt=from_receipt)

    async def _evaluate_resource(self, engine, subject, *, approved_transport=False):
        version = self.context.policy_version
        approved = self.approved_programs_version == version and approved_program_matches(
            self.approved_programs, subject, self.source_tool, self.source_shell
        )
        options = {}
        if subject["kind"] == "program":
            options["resolve_program"] = self._resolve_program
        if getattr(engine, "task_rules", None) is not None:
            options["task"] = (self.task_id, self.context.tool_call_id, self.source_tool)
            if self._scoped_task_grants:
                options["task"] += (self._scoped_task_grants.values(),)
            options["approved_transport"] = approved_transport
        result = await engine.evaluate_operation(subject, {
            "command_approved": approved, "source_tool": self.source_tool, "source_shell": self.source_shell,
        }, **options)
        # A host/cloud callback can suspend while the live policy or execution
        # changes. Never resume the native operation with that stale result.
        # File/network evaluation is synchronous (the coroutine does not yield).
        # Only program evaluation can suspend in the SDK or a host/cloud callback.
        current_version = self._policy()[1] if subject["kind"] == "program" else version
        if not self.context.active or version != current_version:
            result = PermissionResult(
                PermissionLevel.DENY, reason="Runtime permission decision became stale"
            )
        return result

    async def _resolve_program(self, subject, local):
        result = await self._host_program_decision(subject, local)
        if result is not None and not isinstance(result, PermissionResult):
            try:
                result = PermissionResult(
                    PermissionLevel(result.permission), result.matched_rule, result.reason,
                    external_paths=result.external_paths,
                )
            except (AttributeError, TypeError, ValueError):
                result = None
        if result is None or result.is_undetermined:
            result = PermissionResult(
                PermissionLevel.ASK, local.matched_rule,
                "Runtime program has no effective host permission decision",
            )
        logging.getLogger(__name__).info(
            "DLL Guard program decision session=%s tool_call=%s execution=%s exe=%s "
            "local=%s matched_rule=%s decision=%s reason=%s",
            self.context.session_id, self.context.tool_call_id, self.context.execution_id,
            subject["exe"], local.permission.value, local.matched_rule, result.permission.value,
            (result.reason or "")[:256],
        )
        return result

    async def _host_program_decision(self, subject, local):
        """Keep authenticated argv bound through an asynchronous host callback."""
        if self.program_decision is None:
            return None
        from .policy import program_tool_name

        args = program_tool_args(subject, self.source_tool, self.source_shell)
        identity = native_command_identity(
            subject["exe"], subject["argv"], subject["cwd"], args["shell_type"]
        )
        tool = program_tool_name(subject, self.source_tool)
        words = [subject["exe"], *subject["argv"]]
        with ExitStack() as stack:
            stack.enter_context(bind_native_command(tool, args, identity, words=words))
            host_binding = self.native_command or getattr(self.engine(), "native_command", None)
            if host_binding is not None:
                stack.enter_context(host_binding(tool, args, identity, words=words))
            return await self.program_decision(subject, local)

    @staticmethod
    def file_path(raw_path: str) -> Path:
        if raw_path.startswith(("\\??\\", "\\\\?\\")):
            raw_path = raw_path[4:]
            if raw_path.lower().startswith("global\\"):
                # Resolve the global DOS device in its own namespace before
                # converting the resulting Win32 path to a FileGuard identity.
                resolved = str(Path(os.path.join("\\\\?\\", raw_path)).resolve())
                raw_path = resolved.removeprefix("\\\\?\\")
        if raw_path.lower().startswith("globalroot\\"):
            raw_path = raw_path[len("GLOBALROOT"):]
        if raw_path.lower().startswith("\\device\\mup\\"):
            raw_path = os.path.join("\\\\", raw_path[len("\\Device\\Mup\\"):])
        if raw_path.lower().startswith(("\\device\\", "volume{")):
            query = ct.WinDLL("kernel32", use_last_error=True).QueryDosDeviceW
            query.argtypes, query.restype = [wt.LPCWSTR, wt.LPWSTR, wt.DWORD], wt.DWORD
            buffer = ct.create_unicode_buffer(32768)
            if raw_path.lower().startswith("volume{"):
                volume, separator, tail = raw_path.partition("\\")
                if separator and query(volume, buffer, len(buffer)):
                    raw_path = buffer.value + "\\" + tail
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                if query(letter + ":", buffer, len(buffer)):
                    device = buffer.value
                    if raw_path.lower().startswith(device.lower() + "\\"):
                        raw_path = os.path.join(f"{letter}:", raw_path[len(device):])
                        break
        if raw_path.lower().startswith("unc\\"):
            raw_path = os.path.join("\\\\", raw_path[4:])
        path = Path(raw_path)
        if not path.is_absolute():
            raise ValueError("Runtime file path must be absolute")
        # NTFS alternate streams share the base file's resource policy.
        drive, tail = path.drive, str(path)[len(path.drive):]
        return Path(drive + tail.split(":", 1)[0]).resolve()

    def _delete_event(self, operation_id, **fields):
        if self.audit:
            identity = self._operation_processes.get(operation_id)
            event = {
                "operation_ids": [operation_id],
                "execution_id": self.context.execution_id,
                "session_id": self.context.session_id,
                "task_id": self.task_id,
                "tool_call_id": self.context.tool_call_id,
                "tool_name": self.source_tool,
            }
            if identity:
                event["process"] = identity
                event["process_instance_id"] = identity.get("process_instance_id")
            event.update(fields)
            self.audit(event)

    async def check_delete(self, pid, operation_id, path, *, recheck=False, subject=None):
        UUID(operation_id)
        if not self.context.active or not self.job.contains(pid) or operation_id in self._finished_deletes:
            return False
        target = str(self.file_path(path))
        engine, version = self._policy()
        existing = self._delete_requests.get(operation_id)
        if existing:
            if not recheck or existing != (pid, target, True):
                return False
            if self._delete_versions.get(operation_id) == version:
                return True
            subject = self._delete_subjects[operation_id]
        elif recheck:
            return False
        threshold = engine.config.get("soft_delete", {}).get("batch_delete_threshold", 20)
        bulk = threshold != 0 and self.delete_ledger["success"] + self.delete_ledger["reserved"] >= threshold
        if not existing:
            self.delete_ledger["reserved"] += 1
            self._delete_requests[operation_id] = (pid, target, False)
        subject = dict(subject) if subject is not None else {"kind": "file", "accesses": [(target, "delete")]}
        if threshold == 0:
            # A policy recheck can carry a bulk flag from the previous threshold.
            subject.pop("bulk", None)
        elif bulk and not existing:
            subject["bulk"] = True
        allowed = False
        try:
            allowed = await self.check_resource(pid, subject, operation_id=operation_id)
            allowed = allowed and self.context.active and str(self.file_path(path)) == target
            self._delete_event(operation_id, kind="check", path=target, pid=pid, allowed=allowed, bulk=bulk)
            return allowed
        finally:
            if operation_id in self._delete_requests:
                if allowed:
                    self._delete_requests[operation_id] = (pid, target, True)
                    self._delete_versions[operation_id] = self._policy()[1]
                    self._delete_subjects[operation_id] = subject
                else:
                    self._delete_requests.pop(operation_id)
                    self._finished_deletes[operation_id] = (pid, target)
                    self.delete_ledger["reserved"] -= 1
                    self._delete_event(operation_id, kind="result", status="not_executed",
                                       path=target, pid=pid, disposition=None, os_error=5)

    def note_finished_delete(self, operation_id, pid, path):
        self._finished_deletes[operation_id] = (pid, path)

    def finish_delete(self, pid, operation_id, payload):
        entry = self._delete_requests.get(operation_id)
        if not entry or entry[0] != pid or not entry[2]:
            return False
        disposition, error = map(int, payload.split(","))
        outcomes = {-1: "unknown", 0: None, 1: "recycle_bin", 2: "archive", 3: "broker", 4: "permanent", 5: "backup"}
        if disposition not in outcomes or not 0 <= error <= 0xffffffff:
            return False
        if disposition >= 0:
            self.delete_ledger["reserved"] -= 1
            self._delete_requests.pop(operation_id)
            self._finished_deletes[operation_id] = (pid, entry[1])
            self.delete_ledger["success"] += int(disposition > 0)
        else:
            self._delete_requests[operation_id] = (pid, entry[1], False)
            self._finished_deletes[operation_id] = (pid, entry[1])
        if disposition > 0:
            status = "success"
        elif disposition < 0:
            status = "unknown"
        elif error == 995:
            status = "not_executed"
        else:
            status = "failed"
        self._delete_event(
            operation_id, kind="result", status=status,
            disposition=outcomes.get(disposition), os_error=error, path=entry[1], pid=pid,
        )
        return True

    def report_operation_stage(self, pid, operation_id, payload):
        entry = self._delete_requests.get(operation_id) or self._finished_deletes.get(operation_id)
        if not entry or entry[0] != pid:
            return False
        stage, status, error = map(int, payload.split(","))
        phases = {1: "handle_close", 2: "rename", 3: "replace"}
        if stage not in phases or not -(1 << 31) <= status < (1 << 31) or not 0 <= error <= 0xffffffff:
            return False
        key = (operation_id, stage, status, error)
        if key not in self._operation_stages:
            self._operation_stages.add(key)
            self._delete_event(
                operation_id, kind="operation_result", phase=phases[stage],
                status="success" if status >= 0 else "failed", native_status=status,
                os_error=error, path=entry[1], pid=pid,
            )
        return True

    async def check_access(self, pid: int, raw_path: str, action: int) -> bool:
        device = device_open_path(raw_path)
        if device is not None and getattr(self.engine(), "task_rules", None) is not None:
            accesses = [(device, access) for bit, access in ((1, "read"), (2, "write"), (4, "exec"), (8, "delete"))
                        if action & bit]
            return await self.check_resource(pid, {
                "kind": "file", "accesses": accesses,
                "operation": {"kind": "device_open", "resources": [{
                    "role": "subject", "path": device, "path_kind": "device",
                    "device_class": device_class_for(device),
                }]},
            })
        return await self.check_file_batch(pid, [(raw_path, action)])

    async def check_named_pipe(self, pid, raw_path, mask):
        for prefix in ("\\Device\\NamedPipe\\", "\\??\\PIPE\\"):
            if raw_path.casefold().startswith(prefix.casefold()):
                path = os.path.join("\\\\.\\pipe", raw_path[len(prefix):])
                break
        else:
            return False
        return await self.check_resource(pid, {
            "kind": "named_pipe", "path": path, "access": "write" if mask & 10 else "read",
        })

    async def check_file_batch(
        self, pid: int, resources, *, operation=None, operation_id=None, reserve_delete=False,
    ) -> bool:
        if not self.context.active or self.job is None or not self.job.contains(pid):
            return False
        accesses: list[tuple[Path, str]] = []
        roles = []
        captured = []
        for raw_path, action in resources:
            if action not in range(1, 16):
                return False
            path = self.file_path(raw_path)
            captured.append((raw_path, str(path)))
            if operation:
                roles.append({"role": ("source", "target", "backup")[len(roles)], "path": str(path)})
            accesses.extend(
                (path, name)
                for bit, name in ((1, "read"), (2, "write"), (4, "exec"), (8, "delete"))
                if action & bit
            )
        if not accesses:
            return False
        accesses = sorted(set(accesses))
        subject = {
            "kind": "file",
            "accesses": [(str(path), operation) for path, operation in accesses],
        }
        if operation:
            subject["operation"] = {"kind": operation, "resources": roles}

        def paths_still_match():
            return all(str(self.file_path(raw)) == initial for raw, initial in captured)

        if not reserve_delete:
            return await self.check_resource(
                pid, subject, operation_id=operation_id, verify_paths=paths_still_match
            )
        if not await self.check_delete(pid, operation_id, resources[1][0], subject=subject):
            return False
        if not paths_still_match():
            self.finish_delete(pid, operation_id, "0,995")
            return False
        return True

    async def check_transport_resource(self, pid, subject):
        """An authorized WinHTTP URL covers transport defaults, never explicit rules."""
        return await self.check_resource(pid, subject, _transport=True)

    async def check_resource(self, pid, subject, *, _transport=False, operation_id=None, verify_paths=None):
        if not self.context.active:
            return False
        engine, version = self._policy()
        process_identity = None
        audit_settlement = self.audit is not None and operation_id is None
        if self.audit is not None:
            instance_id = self.job.member_instance_id(pid)
            if instance_id is None:
                return False
            if instance_id not in self._process_identities:
                identity = getattr(self.job, "member_identity", None)
                self._process_identities[instance_id] = (
                    identity(pid) if identity else {"pid": pid, "process_instance_id": instance_id}
                )
        elif not self.job.contains(pid):
            return False
        result = await self._evaluate_resource(engine, subject, approved_transport=_transport)
        if not self.context.active:
            return False
        if self.audit is not None:
            if self.job.member_instance_id(pid) != instance_id:
                return False
            process_identity = self._process_identities[instance_id]
            if operation_id is None:
                operation_id = str(uuid4())
            else:
                # Native result and stage messages refer back to this ID.
                self._operation_processes[operation_id] = process_identity
            decision_event = {
                "kind": "policy_decision",
                "operation_ids": [operation_id],
                "task_id": self.task_id,
                "session_id": self.context.session_id,
                "tool_call_id": self.context.tool_call_id,
                "execution_id": self.context.execution_id,
                "tool_name": self.source_tool,
                "pid": pid,
                "resource_kind": subject["kind"],
                "action": result.permission.value,
                "matched_rule": result.matched_rule,
                "process_instance_id": instance_id,
                "process": process_identity,
                "operation": subject,
            }
            self.audit(dict(decision_event))
        elif not self.job.contains(pid):
            return False
        allowed = False
        try:
            settled = await self._settle_resource(
                engine, version, result, subject, _transport, operation_id, process_identity
            )
            # A link may have changed during approval. Audit the decision sent
            # back to the caller after checking the captured paths once more.
            allowed = settled and (verify_paths is None or verify_paths())
            return allowed
        finally:
            if audit_settlement:
                self.audit({
                    **decision_event, "kind": "policy_settled",
                    "policy_action": result.permission.value, "action": "allow" if allowed else "deny",
                })

    @staticmethod
    def _pending_file_accesses(engine, accesses):
        # FileGuard checks delete against the write policy, but the receipt
        # must cover the original delete action.
        pending = []
        for path, action in accesses:
            checked = "write" if action == "delete" else action
            if engine.check_file_accesses([(Path(path), checked)]).needs_approval:
                pending.append((path, action))
        return pending

    def _task_receipt_matches(self, engine, subject, result, version):
        # Only the host's tool-call receipt may satisfy a task ASK here. Grants
        # learned from other DLL checks may cover just the runtime policy.
        runtime = result.runtime_ask
        if subject["kind"] == "program":
            # A command receipt has already been applied to the command layer.
            # A remaining execution permission or host ASK is independent.
            return runtime is None and approved_program_matches(
                self._receipt_programs, subject, self.source_tool, self.source_shell
            )
        if subject.get("bulk"):
            # The task ledger just crossed its threshold. A file receipt
            # describes individual accesses, not approval of this batch.
            return False
        if subject["kind"] == "file":
            accesses = set(subject["accesses"])
            operation = subject.get("operation", {})
            if operation.get("kind") == "hardlink":
                # Task rules use source read; runtime file rules use source write.
                task_accesses = {
                    (item["path"], "read" if item["role"] == "source" else "write")
                    for item in operation["resources"]
                }
                if runtime is not None:
                    task_accesses.update(self._pending_file_accesses(engine, accesses))
                accesses = task_accesses
            exact_only = runtime is not None and runtime.matched_rule == "immutable_project_execution_config"
            return bool(accesses) and self.context.matches(
                {"kind": "file", "accesses": sorted(accesses)}, execution_id=self.context.execution_id,
                policy_version=version, receipt_only=True, exact_only=exact_only,
            )
        return self.context.matches(
            subject, execution_id=self.context.execution_id, policy_version=version, receipt_only=True,
        )

    @staticmethod
    def _force_once(result):
        if isinstance(result, TaskRuleResult):
            return not result.grants
        return result.matched_rule == "immutable_project_execution_config" or "del_guard" in (result.matched_rule or "")

    def _without_prompt(self, engine, version, result, subject, approved_transport):
        if approved_transport and not isinstance(result, TaskRuleResult) and result.matched_rule == "net_guard:defaults":
            return True
        if result.is_denied:
            return False
        if result.is_allowed:
            return True
        deletion_ask = "del_guard" in (result.matched_rule or "")
        force_once = self._force_once(result)
        matching_subject = subject
        task_ask = isinstance(result, TaskRuleResult)
        if task_ask:
            if self._task_receipt_matches(engine, subject, result, version):
                return True
        if subject["kind"] == "file" and not task_ask:
            # ALLOW axes need no receipt. A delete receipt can cover an open
            # requesting read metadata + delete, without also granting writes.
            matching_subject = {
                "kind": "file", "accesses": self._pending_file_accesses(engine, subject["accesses"]),
            }
        if not task_ask and not force_once and remembered_resource(engine.config, matching_subject):
            self._remember_resource(subject, version)
            return True
        has_session_grant = (
            self.session_grants is not None
            and self.session_grants.matches(matching_subject, version)
        )
        if not task_ask and not force_once and has_session_grant:
            self._remember_resource(subject, version)
            return True
        if not task_ask and not deletion_ask and self.context.matches(
            matching_subject,
            execution_id=self.context.execution_id,
            policy_version=version,
            exact_only=force_once,
        ):
            return True
        return None

    async def _settle_resource(self, engine, version, result, subject, _transport, operation_id,
                               process_identity):
        settled = self._without_prompt(engine, version, result, subject, _transport)
        if settled is not None:
            return settled
        key = json.dumps([version, subject, _transport], sort_keys=True)
        identifiers = self._approval_operations.setdefault(key, set())
        if operation_id is not None:
            identifiers.add(operation_id)
        if key not in self.pending:
            self.pending[key] = asyncio.create_task(
                self._approve(subject, version, result, self.approvals.settlements, approved_transport=_transport,
                              operation_ids=identifiers, process_identity=process_identity)
            )
        task = self.pending[key]
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self.pending.pop(key, None)
                self._approval_operations.pop(key, None)

    async def _recheck_approval(self, subject, version, result, *, added_grants=(), approved_transport=False):
        """Validate one pending decision after a host callback, before recording grants."""
        if not self.context.active:
            return None
        engine, current, compatible = self._refresh_policy(added_grants=added_grants)
        if version != current and version != compatible:
            return None
        decision = await self._evaluate_resource(engine, subject, approved_transport=approved_transport)
        if decision.is_denied:
            return None
        # A dynamic program decision may change its approval restrictions without
        # changing the host revision. A different ASK needs its own confirmation.
        if decision.needs_approval and (
            decision.matched_rule != result.matched_rule or type(decision) is not type(result)
        ):
            return None
        if subject["kind"] == "program" and isinstance(decision, TaskRuleResult) and decision.runtime_ask is not None:
            previous = result.runtime_ask
            if previous is None or previous.matched_rule != decision.runtime_ask.matched_rule:
                return None
        return engine, current

    async def _approve(self, subject, version, result, settlements, *, approved_transport=False,
                       operation_ids=None, process_identity=None):
        async with self.approvals.turn(self.context, self.channel) as request_id:
            if settlements != self.approvals.settlements:
                engine, version = self._policy()
                result = await self._evaluate_resource(engine, subject, approved_transport=approved_transport)
                settled = self._without_prompt(engine, version, result, subject, approved_transport)
                if settled is not None:
                    return settled
            return await self._prompt_and_settle(
                request_id, subject, version, result, approved_transport, operation_ids, process_identity,
            )

    async def _prompt_and_settle(self, request_id, subject, version, result, approved_transport,
                                 operation_ids, process_identity):
        force_once = self._force_once(result)
        def operation_fields():
            ids = sorted(operation_ids or ())
            identity = process_identity if len(ids) == 1 else None
            fields = {"operation_ids": ids}
            if identity:
                fields["pid"] = identity.get("pid")
                fields["process_instance_id"] = identity.get("process_instance_id")
                fields["process"] = identity
            return fields

        resource = {**subject, "can_remember": self.persist is not None and not force_once, **operation_fields()}
        if isinstance(result, TaskRuleResult):
            grant_object = {"file": "file", "url": "domain"}.get(subject["kind"])
            if not result.grants or any(g["object"] != grant_object for g in result.grants):
                resource["allowed_scopes"] = ["exact"]
            resource["can_persist"] = resource["can_remember"] and (
                len(result.grants) == 1 or callable(self.persist_batch)
            )
        answer = await self.approvals.prompt(
            request_id, self.context, resource, self.emit, self.approval_timeout, result,
        )
        if not answer.approved:
            return False
        snapshot = await self._recheck_approval(subject, version, result, approved_transport=approved_transport)
        if snapshot is None:
            return False
        engine, version = snapshot
        if isinstance(result, TaskRuleResult):
            try:
                grants = result.selected_grants(subject, answer.authorization_scope)
            except (TypeError, ValueError):
                return False
            if not answer.auto_confirm or not grants:
                if answer.authorization_scope not in (None, "exact"):
                    self._scoped_task_grants.update((g.id, g) for g in load_grants(grants))
                return True
            if answer.wants_permanent_persist():
                try:
                    if len(grants) == 1:
                        saved = self.persist(self.context.session_id, engine.config,
                                             deepcopy(grants[0]), permanent=True)
                    else:
                        saved = callable(self.persist_batch) and self.persist_batch(deepcopy(grants)) is not False
                except (OSError, RuntimeError, ValueError):
                    saved = False
                if self.notify:
                    await self.notify({
                        "kind": "authorization_saved", "persisted": saved, **operation_fields(),
                        "scope": "permanent",
                        "session_id": self.context.session_id,
                        "execution_id": self.context.execution_id,
                        "tool_call_id": self.context.tool_call_id,
                    })
                rechecked = await self._recheck_approval(
                    subject, version, result, added_grants=grants if saved else (),
                    approved_transport=approved_transport,
                )
                if rechecked is None:
                    return False
                if not saved:
                    return True
                engine, version = rechecked
            engine.task_rules.remember(self.task_id, grants)
            return True
        if force_once and answer.authorization_scope not in (None, "exact"):
            return False
        if force_once:
            answer = replace(
                answer,
                auto_confirm=False,
                persist_allow=None,
                authorization_mode="allow",
                authorization_scope="exact",
            )
        else:
            answer = normalize_confirmation_scope(answer, subject)
        if (answer.auto_confirm or answer.persist_allow) and self.persist is None:
            return False
        if answer.persist_allow and not answer.auto_confirm:
            return False
        try:
            grant = resource_grant(
                subject, answer, source_tool=self.source_tool, source_shell=self.source_shell
            )
        except (ValueError, TypeError, KeyError):
            return False
        if answer.auto_confirm:
            try:
                saved = bool(
                    self.persist(
                        self.context.session_id,
                        engine.config,
                        deepcopy(grant),
                        permanent=answer.wants_permanent_persist(),
                    )
                )
            except (OSError, RuntimeError, ValueError):
                saved = False
            snapshot = await self._recheck_approval(subject, version, result, added_grants=[grant] if saved else ())
            if snapshot is None:
                return False
            engine, version = snapshot
            if self.notify is not None:
                await self.notify(
                    {
                        "kind": "authorization_saved", "persisted": saved, **operation_fields(),
                        "session_id": self.context.session_id,
                        "tool_call_id": self.context.tool_call_id,
                        "execution_id": self.context.execution_id,
                        "scope": "permanent" if answer.wants_permanent_persist() else "session",
                    }
                )
                snapshot = await self._recheck_approval(subject, version, result)
                if snapshot is None:
                    return False
                engine, version = snapshot
            if not saved:
                return True
            if self.session_grants is not None and not remembered_resource(engine.config, subject):
                self.session_grants.remember(grant, version)
        if subject["kind"] == "file" and subject.get("bulk"):
            return True
        if "del_guard" in (result.matched_rule or ""):
            # Remember the command the user just approved and its literal
            # shell continuations for this execution and policy version.
            approved = {key: subject[key] for key in ("kind", "exe", "argv", "cwd")}
            args = program_tool_args(subject, self.source_tool, self.source_shell)
            operation = {
                "kind": "command",
                "command": args["command"],
                "shell_type": args["shell_type"],
                "cwd": subject["cwd"],
            }
            programs = [approved]
            if literal_shell_words(args["command"], args["shell_type"]):
                launch_plan = approved_programs(operation)
                if approved in launch_plan:
                    programs = launch_plan[launch_plan.index(approved):]
            if self.approved_programs_version != version:
                self.approved_programs.clear()
            self.approved_programs.extend(p for p in programs if p not in self.approved_programs)
            self.approved_programs_version = version
            return True
        self.context.remember(resource_source(subject), grant, policy_version=version)
        domain = url_domain_subject(subject)
        if domain is not None:
            self._remember_resource(domain, version)
        return True

    async def close(self, *, tree_finished=False):
        async with self.close_lock:
            if self.closed:
                return
            await self._close(tree_finished=tree_finished)
            self.closed = True

    async def _close(self, *, tree_finished=False):
        self.context.finish()
        self._scoped_task_grants.clear()
        self._process_identities.clear()
        for operation_id, (pid, path, approved) in self._delete_requests.items():
            if operation_id not in self._finished_deletes:
                self._delete_event(
                    operation_id, kind="result", status="unknown" if approved else "not_executed",
                    disposition="unknown" if approved else None, os_error=995, path=path, pid=pid,
                )
        self.delete_ledger["reserved"] -= len(self._delete_requests)
        self._delete_requests.clear()
        self._finished_deletes.clear()
        self._delete_versions.clear()
        self._delete_subjects.clear()
        self._operation_processes.clear()
        self._operation_stages.clear()
        if self._cache is not None:
            self.cache_engine.detach_native_cache(self._cache)
            self._cache.close()
            self._cache = None
        if callable(self._unsubscribe_policy_changes):
            unsubscribe, self._unsubscribe_policy_changes = self._unsubscribe_policy_changes, None
            try:
                unsubscribe()
            except Exception:
                logging.getLogger(__name__).exception("Failed to unsubscribe Guard policy listener")
        self.approvals.cancel_execution(self.context.execution_id)
        for task in self.pending.values():
            task.cancel()
        if self.pending:
            await asyncio.gather(*self.pending.values(), return_exceptions=True)
        self.pending.clear()
        self._approval_operations.clear()
        for connection in list(self.connections):
            connection.transport.close()
        tasks = [connection.task for connection in self.connections if connection.task is not None]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        for server in self.servers:
            server.close()
        self.servers.clear()
        if self.job is not None:
            self.job.close()
        try:
            for process in self.processes:
                # After natural job completion the caller still owns unread stdout/stderr.
                if tree_finished:
                    continue
                if process.returncode is None:
                    try:
                        process.kill()
                    except ProcessLookupError:
                        pass
                # Drain pipes as well: wait() can deadlock after a full stdout pipe.
                try:
                    await asyncio.wait_for(process.communicate(), 5)
                except RuntimeError:
                    # The original Shell/Code consumer may still own stdout.
                    try:
                        await asyncio.wait_for(process.wait(), 5)
                    except OSError:
                        pass
                except OSError:
                    pass
        finally:
            try:
                if self.ready and self.job is not None:
                    self.job.close_handle(self.ready)
                    self.ready = None
            finally:
                self._bundle_handles.close()

    async def __aexit__(self, *_exc):
        await self.close()
