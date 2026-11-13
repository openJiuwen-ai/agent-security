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
from contextlib import ExitStack
from copy import deepcopy
from ctypes import wintypes as wt
from dataclasses import is_dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agent_shield.tool_permission.runtime.command_identity import (
    bind_native_command,
    literal_shell_words,
    native_command_identity,
)
from agent_shield.tool_permission.runtime.confirmation import normalize_confirmation_scope
from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import (
    PermissionConfirmResponse,
    PermissionLevel,
    PermissionResult,
)

from .context import RuntimeGuardContext
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
)
from .launcher import start_guarded_factory
from .policy import (
    canonical_domain,
    evaluate_resource,
    program_tool_args,
    remembered_resource,
    resource_grant,
    resource_grant_matches,
    resource_source,
    url_domain_subject,
)
from .shell_launch import approved_programs

if TYPE_CHECKING:
    from .pipe import GuardPipeServer
    from .windows import WindowsJob


_REQUEST = struct.Struct("<5I")
_REPLY = struct.Struct("<3I")
_MAX_REQUEST_BYTES = 128 * 1024  # Matches GUARD_MAX_REQUEST_BYTES in guard.c.


class RuntimeApprovalRequests:
    """Correlate answers with pending operations in the owning session."""

    def __init__(self) -> None:
        self._pending: dict[str, tuple[str, str, asyncio.Future]] = {}
        self._session_locks: dict[str, tuple[asyncio.Lock, int]] = {}
        self._channels: dict[str, str | None] = {}

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
        if not context.active:
            raise RuntimeError("Guard execution has ended")
        if emit is None:
            raise RuntimeError("Runtime approval requires a host emit callback")
        request_id = "dll-runtime:" + secrets.token_urlsafe(24)
        future = asyncio.get_running_loop().create_future()
        self._pending[request_id] = (context.session_id, context.execution_id, future)
        self._channels[request_id] = channel
        lock, users = self._session_locks.get(context.session_id, (asyncio.Lock(), 0))
        self._session_locks[context.session_id] = (lock, users + 1)
        try:
            async with lock:
                async with asyncio.timeout(timeout):
                    if not context.active or future.cancelled():
                        raise asyncio.CancelledError
                    await emit(
                        {
                            "request_id": request_id,
                            "tool_call_id": context.tool_call_id,
                            "execution_id": context.execution_id,
                            "session_id": context.session_id,
                            "resource": deepcopy(resource),
                            "reason": result.reason if result else None,
                            "matched_rule": result.matched_rule if result else None,
                        }
                    )
                    return await future
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
        session, _execution, future = pending
        if session != session_id or future.done():
            return False
        future.set_result(answer)
        return True

    def cancel_execution(self, execution_id: str) -> None:
        for _session, execution, future in list(self._pending.values()):
            if execution == execution_id and not future.done():
                future.cancel()

    def cancel_channel(self, channel: str) -> None:
        for request_id, (_session, _execution, future) in list(self._pending.items()):
            if self._channels.get(request_id) == channel and not future.done():
                future.cancel()


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
            cache_request = cache_ready and self.owner.fixed_engine.permission_checks_enabled
            if action == 41:
                if not cache_request and resource == "cache" and self.owner.has_native_cache():
                    wait_handle = self.owner.duplicate_cache_wait(self.pid)
            elif action in (16, 17):
                paths = resource.split("\0")
                if len(paths) == 2:
                    allowed = await self.owner.check_file_batch(
                        self.pid, [(paths[0], 8 if action == 16 else 2), (paths[1], 2)]
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
                            "cwd": str(self.owner.file_path(cwd)),
                        },
                    )
            else:
                allowed = await self.owner.check_access(self.pid, resource, action)
                read_ready = cache_request and action == 1 and allowed
                cacheable = read_ready and self.owner.uniform_native_reads()
        except (ValueError, OSError, RuntimeError, asyncio.CancelledError):
            pass
        finally:
            if self.transport is not None and not self.transport.is_closing():
                answer = wait_handle if action == 41 else (2 if cacheable else int(allowed))
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
        policy_revision: PolicyRevision | None = None,
        notify: Callable[[RuntimePersistenceEvent], Awaitable[None]] | None = None,
        session_grants=None,
        root_command_approved=False,
        channel=None,
        program_decision: Callable[[dict, PermissionResult], Awaitable[PermissionResult | None]]
        | None = None,
        source_tool=None,
        source_shell=None,
        native_command=None,
    ):
        self.context = RuntimeGuardContext(session_id, tool_call_id, "initial")
        self.dll_source = Path(dll).resolve()
        self._fixed_engine = engine if isinstance(engine, PermissionEngine) else None
        self.engine = (lambda: engine) if self._fixed_engine is not None else engine
        self.emit, self.approvals = emit, approvals
        self._cache = None
        self.approval_timeout = approval_timeout
        self.persist, self.policy_revision, self.notify = persist, policy_revision, notify
        self.session_grants = session_grants
        self.root_command_approved = root_command_approved
        self.channel = channel
        self.program_decision = program_decision
        self.source_tool = source_tool
        self.source_shell = source_shell
        self.native_command = native_command
        self.approved_programs: list[dict] = []
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
            self.job = WindowsJob()
            nonce = secrets.token_hex(16)
            pipe = os.path.join("\\\\.\\pipe", "jiuwen-guard-" + nonce)
            self.pipe_name = pipe
            event = "Local\\jiuwen-guard-ready-" + nonce
            if self._fixed_engine is not None and self.policy_revision is None:
                from .windows import CacheRevocation

                cache = CacheRevocation(self.job)
                if self.fixed_engine.register_native_cache(cache):
                    event += "-cache"
                    self._cache = cache
                    self.context.bind_cache_revoker(cache.revoke)
                else:
                    cache.close()
            create = self.job.api(
                "CreateEventW", wt.HANDLE, ct.c_void_p, wt.BOOL, wt.BOOL, wt.LPCWSTR
            )
            self.ready = self.job.check_result(create(None, True, False, event), "CreateEventW")
            config = struct.pack("<I", 0x44474333)
            for value in (pipe, event):
                config += (value + "\0").encode("utf-16-le").ljust(512, b"\0")
            self.bootstrap = config
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
        process = await start_guarded_factory(factory, *args, **kwargs)
        self.processes.append(process)
        try:
            try:
                self.job.attach(process.pid)
                executable = self.job.process_image(process.pid)
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
            if process.returncode not in (None, 0):
                raise GuardStartupError(
                    f"Protected process exited during startup (code {process.returncode:#x})"
                )
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

    def _refresh_policy(self, *, added_grant=None):
        """Return the live snapshot and the prior version compatible with this save."""
        engine = self.engine()
        state = {
            "config": engine.config,
            "trusted_dirs": engine.trusted_dirs,
            "permission_checks_enabled": engine.permission_checks_enabled,
            "host_revision": self.policy_revision() if self.policy_revision else None,
        }
        previous_version = self._policy_version
        preserve = False
        if state != self._policy_state:
            revision = hashlib.sha256(
                json.dumps(state, sort_keys=True, default=str).encode()
            ).hexdigest()
            preserve = added_grant is not None and self._only_added_grant(state, added_grant)
            self.context.update_policy_version(revision, preserve_grants=preserve)
            if preserve and self.approved_programs_version == previous_version:
                self.approved_programs_version = revision
            self._policy_state = deepcopy(state)
            self._policy_version = revision
        return engine, self._policy_version, previous_version if preserve else None

    def has_native_cache(self) -> bool:
        return self._cache is not None

    @property
    def fixed_engine(self):
        return self._fixed_engine

    def uniform_native_reads(self) -> bool:
        engine = self._fixed_engine
        return engine is not None and engine.uniform_native_reads

    def duplicate_cache_wait(self, pid: int) -> int:
        if self._cache is None:
            return 0
        return self._cache.duplicate_wait_handle(pid)

    def cacheable_endpoint(self, address, port):
        if self._cache is None or not self._fixed_engine.permission_checks_enabled:
            return False
        return self._fixed_engine.check_network_access(f"{address}:{port}").is_allowed

    def _only_added_grant(self, state, grant):
        """Preserve old approvals only for the exact delta this execution just saved.

        Concurrent rule/host changes, removed approvals and changed scopes invalidate
        everything as before. A compose revision bump alone is metadata for this save.
        """
        if self._policy_state is None or grant.get("action") != "allow":
            return False
        old, new = deepcopy(self._policy_state), deepcopy(state)
        if (new["config"].get("approval_overrides") or []).count(grant) != 1:
            return False
        if grant in (old["config"].get("approval_overrides") or []):
            return False
        for item in (old, new):
            config = item["config"]
            grants = config.pop("approval_overrides", []) or []
            config["approval_overrides"] = [entry for entry in grants if entry != grant]
            if isinstance(config.get("composition"), dict):
                config["composition"].pop("revision", None)
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
        self.context.remember(resource_source(subject), grant, policy_version=version)

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
            self._remember_resource(operation, version)
            if confirmed_grant is not None:
                self.context.remember(
                    resource_source(operation), confirmed_grant, policy_version=version
                )
            elif operation["kind"] == "file":
                # Older hosts hand off the selected file scope in the grants alone.
                for grant in approval.get("grants", []):
                    if resource_grant_matches(grant, operation):
                        self.context.remember(grant["tools"][0], grant, policy_version=version)
        elif operation.get("kind") == "command":
            for grant in approval.get("grants", []):
                if (
                    grant.get("tools") == ["file_resource"]
                    and json.loads(grant["pattern"]).get("scope") == "exact"
                ):
                    self.context.remember("file_resource", grant, policy_version=version)
        self.approved_programs = approved_programs(operation)
        self.approved_programs_version = version

    def _remember_resource(self, subject, version):
        grant = resource_grant(subject, PermissionConfirmResponse(approved=True))
        self.context.remember(resource_source(subject), grant, policy_version=version)
        domain = url_domain_subject(subject)
        if domain is not None:
            grant = resource_grant(domain, PermissionConfirmResponse(approved=True))
            self.context.remember(resource_source(domain), grant, policy_version=version)

    async def _evaluate_resource(self, engine, subject):
        version = self.context.policy_version
        # Host startup metadata is not part of exe/argv/cwd program identity.
        identity = {key: value for key, value in subject.items() if key != "root_command_approved"}
        from .policy import approved_program_matches

        approved = self.approved_programs_version == self.context.policy_version and (
            identity in self.approved_programs
            or approved_program_matches(
                self.approved_programs, identity, self.source_tool, self.source_shell
            )
        )
        local = await evaluate_resource(
            engine,
            subject,
            command_approved=approved,
            source_tool=self.source_tool,
            source_shell=self.source_shell,
        )
        result = local
        if subject["kind"] == "program" and local.is_undetermined:
            result = await self._host_program_decision(subject, local)
            if result is not None and not isinstance(result, PermissionResult):
                try:
                    result = PermissionResult(
                        PermissionLevel(result.permission),
                        result.matched_rule,
                        result.reason,
                        external_paths=result.external_paths,
                    )
                except (AttributeError, TypeError, ValueError):
                    result = None
            if not isinstance(result, PermissionResult) or result.is_undetermined:
                result = PermissionResult(
                    PermissionLevel.ASK,
                    local.matched_rule,
                    "Runtime program has no effective host permission decision",
                )
        # A host/cloud callback can suspend while the live policy or execution
        # changes. Never resume the native operation with that stale result.
        # File/network evaluation is synchronous (the coroutine does not yield).
        # Only program evaluation can suspend in the SDK or a host/cloud callback.
        current_version = self._policy()[1] if subject["kind"] == "program" else version
        if not self.context.active or version != current_version:
            result = PermissionResult(
                PermissionLevel.DENY, reason="Runtime permission decision became stale"
            )
        if subject["kind"] == "program" and local.is_undetermined:
            logging.getLogger(__name__).info(
                "DLL Guard program decision session=%s tool_call=%s execution=%s exe=%s "
                "local=%s matched_rule=%s decision=%s reason=%s",
                self.context.session_id,
                self.context.tool_call_id,
                self.context.execution_id,
                subject["exe"],
                local.permission.value,
                local.matched_rule,
                result.permission.value,
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

    async def check_access(self, pid: int, raw_path: str, action: int) -> bool:
        return await self.check_file_batch(pid, [(raw_path, action)])

    async def check_file_batch(self, pid: int, resources) -> bool:
        if not self.context.active or self.job is None or not self.job.contains(pid):
            return False
        accesses: list[tuple[Path, str]] = []
        for raw_path, action in resources:
            if action not in range(1, 16):
                return False
            path = self.file_path(raw_path)
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
        allowed = await self.check_resource(pid, subject)
        # Approval may take minutes. Do not apply an answer to a link that was
        # replaced while waiting. The short kernel-open TOCTOU remains a stated
        # user-mode limitation, not a claim of filesystem isolation.
        current = []
        for raw, mask in resources:
            for bit, name in ((1, "read"), (2, "write"), (4, "exec"), (8, "delete")):
                if mask & bit:
                    current.append((self.file_path(raw), name))
        current = sorted(set(current))
        return allowed and current == accesses

    async def check_transport_resource(self, pid, subject):
        """An authorized WinHTTP URL covers transport defaults, never explicit rules."""
        return await self.check_resource(pid, subject, _transport=True)

    async def check_resource(self, pid, subject, *, _transport=False):
        if not self.context.active or not self.job.contains(pid):
            return False
        engine, version = self._policy()
        result = await self._evaluate_resource(engine, subject)
        if not self.context.active or not self.job.contains(pid):
            return False
        if _transport and result.matched_rule == "net_guard:defaults":
            return True
        if result.is_denied:
            return False
        if result.is_allowed:
            return True
        deletion_ask = "del_guard" in (result.matched_rule or "")
        force_once = result.matched_rule == "immutable_project_execution_config" or deletion_ask
        matching_subject = subject
        if subject["kind"] == "file":
            # ALLOW axes need no receipt. A delete receipt can cover an open
            # requesting read metadata + delete, without also granting writes.
            pending = []
            for path, action in subject["accesses"]:
                checked = "write" if action == "delete" else action
                decision = engine.check_file_accesses([(Path(path), checked)])
                if decision.needs_approval:
                    pending.append((path, action))
            matching_subject = {"kind": "file", "accesses": pending}
        if not force_once and remembered_resource(engine.config, matching_subject):
            self._remember_resource(subject, version)
            return True
        if (
            not force_once
            and self.session_grants is not None
            and self.session_grants.matches(matching_subject, version)
        ):
            self._remember_resource(subject, version)
            return True
        if not deletion_ask and self.context.matches(
            matching_subject,
            execution_id=self.context.execution_id,
            policy_version=version,
            exact_only=force_once,
        ):
            return True
        key = json.dumps([version, subject], sort_keys=True)
        if key not in self.pending:
            self.pending[key] = asyncio.create_task(
                self._approve(subject, version, force_once, result)
            )
        task = self.pending[key]
        try:
            return await asyncio.shield(task)
        finally:
            if task.done():
                self.pending.pop(key, None)

    async def _recheck_approval(self, subject, version, result, *, added_grant=None):
        """Validate one pending decision after a host callback, before recording grants."""
        if not self.context.active:
            return None
        engine, current, compatible = self._refresh_policy(added_grant=added_grant)
        if version != current and version != compatible:
            return None
        decision = await self._evaluate_resource(engine, subject)
        if decision.is_denied:
            return None
        # A dynamic program decision may change its approval restrictions without
        # changing the host revision. A different ASK needs its own confirmation.
        if decision.needs_approval and decision.matched_rule != result.matched_rule:
            return None
        return engine, current

    async def _approve(self, subject, version, force_once, result):
        answer = await self.approvals.request(
            self.context,
            {**subject, "can_remember": self.persist is not None and not force_once},
            self.emit,
            self.approval_timeout,
            channel=self.channel,
            result=result,
        )
        if not answer.approved:
            return False
        snapshot = await self._recheck_approval(subject, version, result)
        if snapshot is None:
            return False
        engine, version = snapshot
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
            snapshot = await self._recheck_approval(subject, version, result, added_grant=grant)
            if snapshot is None:
                return False
            engine, version = snapshot
            if self.notify is not None:
                await self.notify(
                    {
                        "persisted": saved,
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
            if self.session_grants is not None and not remembered_resource(engine.config, subject):
                self.session_grants.remember(grant, version)
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

    async def close(self):
        async with self.close_lock:
            if self.closed:
                return
            await self._close()
            self.closed = True

    async def _close(self):
        self.context.finish()
        if self._cache is not None:
            self._fixed_engine.detach_native_cache(self._cache)
            self._cache.close()
            self._cache = None
        self.approvals.cancel_execution(self.context.execution_id)
        for task in self.pending.values():
            task.cancel()
        if self.pending:
            await asyncio.gather(*self.pending.values(), return_exceptions=True)
        self.pending.clear()
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
