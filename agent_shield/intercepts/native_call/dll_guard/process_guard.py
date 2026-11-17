"""Session-scoped Process Guard SDK for Windows."""

from __future__ import annotations

import asyncio
import os
from collections.abc import Mapping
from copy import deepcopy

from agent_shield.tool_permission.runtime.engine import PermissionEngine
from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse

from .bridge import RuntimeApprovalRequests, WindowsGuardExecution
from .bundle import validate_guard_platform
from .errors import GuardError
from .policy import SessionResourceGrants
from .task_rules import TaskRules


class GuardedProcess:
    def __init__(self, process, execution):
        self._process = process
        self._execution = execution
        self._timed_out = False

    @property
    def execution_id(self):
        return self._execution.context.execution_id

    @property
    def pid(self):
        return self._process.pid

    @property
    def returncode(self):
        return self._process.returncode

    @property
    def stdin(self):
        return self._process.stdin

    @property
    def stdout(self):
        return self._process.stdout

    @property
    def stderr(self):
        return self._process.stderr

    async def wait(self):
        result = await self._process.wait()
        self._check_timeout()
        return result

    async def communicate(self, stdin_data=None):
        result = await self._process.communicate(stdin_data)
        self._check_timeout()
        return result

    def _check_timeout(self):
        if self._timed_out:
            raise GuardError("execution_timeout")

    async def cancel(self):
        await self._execution.close()


class ProcessGuard:
    """The host supplies policy_snapshot(), confirm(request), save_grant(grant) and audit(event)."""

    def __init__(self, *, session_id, host, delete_mode="recover", approval_timeout_s=120):
        if not isinstance(session_id, str) or not session_id.strip():
            raise GuardError("invalid_session_id")
        if delete_mode not in {"recover", "permanent"} or approval_timeout_s <= 0:
            raise GuardError("invalid_configuration")
        self.session_id = session_id
        self.host = host
        self.delete_mode = delete_mode
        self.approval_timeout_s = approval_timeout_s
        self._approvals = RuntimeApprovalRequests()
        self._result_files = {}
        self._grants = SessionResourceGrants()
        self._active = set()
        self._task_deletes = {}
        self._watchers = set()
        self._dll = None
        self._revision = None
        self._engine = None

    def _policy(self):
        snapshot = self.host.policy_snapshot()
        config = snapshot.get("config") if isinstance(snapshot, Mapping) else None
        missing_revision = not isinstance(snapshot, Mapping) or "revision" not in snapshot
        if missing_revision or not isinstance(config, Mapping):
            raise GuardError("invalid_policy_snapshot")
        revision = snapshot["revision"]
        if type(revision) not in (str, int):
            raise GuardError("invalid_policy_snapshot")
        if self._engine is None or self._revision != revision:
            engine = PermissionEngine(
                deepcopy(snapshot["config"]), workspace_root=snapshot.get("workspace_root"),
                trusted_dirs=snapshot.get("trusted_dirs"),
                immutable_control_roots=snapshot.get("immutable_control_roots"),
            )
            if "ruleset" in snapshot or "tasks" in snapshot:
                try:
                    engine.task_rules = TaskRules(deepcopy(snapshot), self.session_id)
                except (KeyError, TypeError, ValueError, AttributeError) as exc:
                    raise GuardError("invalid_policy_snapshot") from exc
            self._engine = engine
            self._revision = revision
        return self._engine

    def _receipt_matches(self, approval_receipt, task_id, tool_call_id, tool_name):
        if not isinstance(approval_receipt, Mapping):
            return False
        expected = {
            "session_id": self.session_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "revision": self._revision,
        }
        for key, value in expected.items():
            if approval_receipt.get(key) != value:
                return False
        return True

    async def __aenter__(self):
        if self._dll is not None or self._active:
            raise GuardError("session_already_open")
        self._policy()
        self._dll = validate_guard_platform()
        return self

    async def spawn(self, argv, *, task_id, tool_call_id, tool_name, cwd=None, env=None,
                    stdio=None, channel=None, timeout_s=None, approval_receipt=None):
        if self._dll is None:
            raise GuardError("session_closed")
        arguments_ok = isinstance(argv, (list, tuple)) and bool(argv)
        if arguments_ok:
            arguments_ok = all(isinstance(arg, (str, os.PathLike)) for arg in argv)
        labels = (task_id, tool_call_id, tool_name)
        labels_ok = all(isinstance(value, str) and value.strip() for value in labels)
        if not arguments_ok or not labels_ok:
            raise GuardError("invalid_command")
        if timeout_s is not None and timeout_s <= 0:
            raise GuardError("invalid_timeout")
        streams = {} if stdio is None else dict(stdio)
        if not streams.keys() <= {"stdin", "stdout", "stderr"}:
            raise GuardError("invalid_stdio")
        effective_env = dict(os.environ if env is None else env)
        if self.delete_mode == "permanent" and (
            os.environ.get("JIUWENBOX_SOFT_DELETE") == "1"
            or any(k.upper() == "JIUWENBOX_SOFT_DELETE" and v == "1" for k, v in effective_env.items())
        ):
            raise GuardError("delete_mode_conflict")
        if os.environ.get("JIUWENBOX_SOFT_DELETE") == "1":
            for key in ("JIUWENBOX_SOFT_DELETE", "JIUWENBOX_SOFT_DELETE_ARCHIVE",
                        "JIUWENBOX_SOFT_DELETE_RECYCLE_PORT", "JIUWENBOX_SOFT_DELETE_RECYCLE_TOKEN",
                        "JIUWENBOX_SOFT_DELETE_RESULTS"):
                for alias in tuple(effective_env):
                    if alias.upper() == key:
                        effective_env.pop(alias)
                if key in os.environ:
                    effective_env[key] = os.environ[key]
        engine = self._policy()
        if engine.task_rules is not None:
            engine.task_rules.require_task(task_id)
        if approval_receipt is not None and not self._receipt_matches(
            approval_receipt, task_id, tool_call_id, tool_name
        ):
            raise GuardError("invalid_approval_receipt")

        async def confirm(request):
            answer = await self.host.confirm({**request, "task_id": task_id, "tool_name": tool_name})
            choice = answer["action"]
            if choice not in {"allow_once", "allow_session", "allow_permanent", "deny"}:
                raise GuardError("invalid_approval")
            decision = PermissionConfirmResponse(
                approved=choice != "deny", auto_confirm=choice in {"allow_session", "allow_permanent"},
                persist_allow=choice == "allow_permanent", authorization_scope=answer.get("scope"),
            )
            if not self._approvals.resolve(self.session_id, request["request_id"], decision):
                raise GuardError("invalid_approval")

        def persist(_session, _config, grant, *, permanent):
            return self.host.save_grant(grant) is not False if permanent else True

        async def audit(event):
            self.host.audit({**event, "task_id": task_id, "tool_name": tool_name})

        program_decision = getattr(self.host, "program_decision", None)

        async def decide_program(subject, local):
            return await program_decision(
                {**subject, "source_tool": tool_name, "source_shell": execution.source_shell},
                local, session=self.session_id, tool_call_id=tool_call_id,
                execution_id=execution.context.execution_id,
            )

        result_dir = None
        try:
            if effective_env.get("JIUWENBOX_SOFT_DELETE") == "1" and not effective_env.get(
                "JIUWENBOX_SOFT_DELETE_RESULTS"
            ):
                import tempfile
                result_dir = tempfile.TemporaryDirectory(prefix="jiuwenbox-softdelete-")
                result_path = os.path.join(result_dir.name, "results.jsonl")
                descriptor = os.open(result_path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
                os.close(descriptor)
                effective_env["JIUWENBOX_SOFT_DELETE_RESULTS"] = result_path
            execution = WindowsGuardExecution(
                session_id=self.session_id, tool_call_id=tool_call_id, dll=self._dll,
                engine=self._policy, emit=confirm, approvals=self._approvals, channel=channel,
                approval_timeout=self.approval_timeout_s, source_tool=tool_name, notify=audit,
                policy_revision=lambda: self._revision,
                program_decision=decide_program if program_decision is not None else None,
                subscribe_policy_changes=getattr(self.host, "subscribe_policy_changes", None),
                persist=persist,
                persist_batch=getattr(self.host, "save_grants", None),
                session_grants=self._grants,
                delete_mode=self.delete_mode,
                task_id=task_id, audit=self.host.audit,
                delete_ledger=self._task_deletes.setdefault(task_id, {"success": 0, "reserved": 0}),
            )
        except BaseException:
            if result_dir is not None:
                try:
                    result_dir.cleanup()
                except OSError:
                    pass
            raise
        if result_dir is not None:
            self._result_files[execution] = result_dir
        self._active.add(execution)
        loop = asyncio.get_running_loop()
        deadline = None if timeout_s is None else loop.time() + timeout_s
        try:
            async with asyncio.timeout_at(deadline):
                await execution.__aenter__()
                if approval_receipt is not None:
                    execution.seed_approved_operation(approval_receipt)
                    # Seeding reads the live policy again. A host publication
                    # during setup must not bind an old receipt to the new revision.
                    if not self._receipt_matches(approval_receipt, task_id, tool_call_id, tool_name):
                        raise GuardError("invalid_approval_receipt")
                process = await execution.launch(asyncio.create_subprocess_exec, *argv, cwd=cwd,
                                                 env=effective_env, **streams)
            guarded = GuardedProcess(process, execution)
            watcher = asyncio.create_task(self._watch(guarded, deadline))
            self._watchers.add(watcher)
            watcher.add_done_callback(self._watchers.discard)
            return guarded
        except BaseException as exc:
            await execution.close()
            self._release_result_file(execution)
            self._active.discard(execution)
            if isinstance(exc, FileNotFoundError) and not isinstance(exc, GuardError):
                raise GuardError("command_not_found") from exc
            if isinstance(exc, TimeoutError):
                raise GuardError("execution_timeout") from exc
            raise

    async def _watch(self, process, deadline):
        execution = getattr(process, "_execution")
        try:
            async with asyncio.timeout_at(deadline):
                while execution.context.active and execution.job.active_processes():
                    await asyncio.sleep(0.05)
        except TimeoutError:
            setattr(process, "_timed_out", True)
        finally:
            timed_out = getattr(process, "_timed_out")
            await execution.close(tree_finished=not timed_out and execution.context.active)
            self._release_result_file(execution)
            self._active.discard(execution)

    @property
    def approvals(self):
        return self._approvals

    @property
    def active_executions(self):
        return self._active

    def _release_result_file(self, execution):
        result_dir = self._result_files.pop(execution, None)
        if result_dir is None:
            return
        try:
            result_dir.cleanup()
        except OSError:
            self._result_files[execution] = result_dir

    def cancel_pending(self, *, channel):
        self._approvals.cancel_channel(channel)

    async def __aexit__(self, *_):
        self._dll = None

        async def release(execution):
            await execution.close()
            self._active.discard(execution)

        # Keep ownership of a Job whose cleanup failed so closing can be retried.
        results = await asyncio.gather(
            *(release(e) for e in tuple(self._active)), *tuple(self._watchers),
            return_exceptions=True,
        )
        errors = [result for result in results if isinstance(result, BaseException)]
        if errors:
            raise BaseExceptionGroup("Process Guard session cleanup failed", errors)
        self._task_deletes.clear()
        self._grants.clear()
        self._engine = None
        self._revision = None
