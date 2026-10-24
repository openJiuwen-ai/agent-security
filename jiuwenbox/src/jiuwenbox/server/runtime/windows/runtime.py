# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""WindowsRuntime adapter.

This module is the registry entry point for the Windows sandbox backend. It
is intentionally importable on any platform (so the registry can probe for
availability), but every concrete method fails closed with
``RuntimeUnavailableError`` on a non-Windows host (see ``supported_platforms``
and ``_ensure_platform``).

The Windows security surface is staged across phases 4-5 of the unification
plan. This file implements the complete phase-4 surface:

- Filesystem DACL enforcement         (``supervisor.win_acl``)
- Job Object process-tree containment (``supervisor.win_job``)
- WFP + loopback proxy egress filter  (``supervisor.win_wfp`` / ``win_proxy``)
- Restricted-token two-hop exec       (``supervisor.win_exec`` / ``win_setup``)

Phase 5 soft-delete (``jiuwen_softdelete.dll``, recycle broker injection) is
intentionally excluded: its capabilities are ``False`` and no soft-delete
module is ever imported.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jiuwenbox.logging_config import configure_logging
from jiuwenbox.models.sandbox import (
    BackgroundExecResult,
    BackgroundJobStatus,
    BackgroundJobSummary,
    ExecResult,
    KillBackgroundJobResult,
)
from jiuwenbox.server.runtime.base import (
    BackgroundJobNotFoundError,
    RuntimeAdapter,
    RuntimeBackgroundExecRequest,
    RuntimeExecRequest,
    RuntimeFileOpResult,
    RuntimeInstance,
)
from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities
from jiuwenbox.server.runtime.errors import RuntimeUnavailableError
from jiuwenbox.server.workspace import WIN_SANDBOX_WORKSPACE_ROOT

configure_logging()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TCP / IPC timing constants (mirror the Linux daemon-IPC envelope, tuned for
# the two-hop runner which resumes -> binds -> listen()s on its control port
# *after* the box-server spawns it suspended).
# ---------------------------------------------------------------------------
DAEMON_CONNECT_TIMEOUT_SECONDS = 2.0
DAEMON_SHUTDOWN_TIMEOUT_SECONDS = 3.0
DAEMON_MAX_RESPONSE_BYTES = 256 * 1024 * 1024
DAEMON_FILE_OP_TIMEOUT_SECONDS = 30.0
WIN_RUNNER_READY_TIMEOUT_SECONDS = 30.0
WIN_RUNNER_READY_PROBE_INTERVAL = 0.1

from jiuwenbox.supervisor.daemon_ipc import (  # noqa: E402
    MAX_FILE_BYTES,
    MAX_HEADER_BYTES,
    LOG_FIELD_LEVEL,
    LOG_FIELD_MESSAGE,
    LOG_FIELD_TRACEBACK,
    REQUEST_TYPE_EXEC,
    REQUEST_TYPE_LIST_DIR,
    REQUEST_TYPE_READ_FILE,
    REQUEST_TYPE_SHUTDOWN,
    REQUEST_TYPE_SUBSCRIBE_LOG,
    REQUEST_TYPE_WRITE_FILE,
    encode_request,
    recv_frame,
    send_frame,
)


def _alloc_loopback_port() -> int:
    """Allocate a free TCP loopback port for the runner control channel."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


@dataclass
class BackgroundJob:
    job_id: str
    sandbox_id: str
    command: list[str]
    pid: int | None
    workdir: str | None
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    exit_code: int | None = None


def _bounded_acl_roots(workspace, read_write, bind_mounts) -> list[str]:
    """Collect non-empty ACL roots from the workspace and policy paths."""

    candidates = [workspace]
    if read_write:
        candidates.extend(read_write)
    for mount in bind_mounts or []:
        candidates.append(mount.sandbox_path)
    roots = []
    for path in candidates:
        if path:
            roots.append(path)
    return roots


def _summarize_command(command: list[str], max_length: int = 180) -> str:
    text = json.dumps(command, ensure_ascii=False)
    if len(text) <= max_length:
        return text
    return f"{text[:max_length]}... ({len(text)} chars)"


class WindowsRuntime(RuntimeAdapter):
    """Windows sandbox backend (ACL / Job Object / WFP / restricted token).

    Soft delete is intentionally excluded (phase 5 has systemic issues and is
    not shipped), so ``capabilities().soft_delete`` is ``False``.
    """

    runtime_name = "windows"
    supported_platforms = ("win32",)

    def __init__(self) -> None:
        # Runner state keyed by sandbox_id.
        self._win_runners: dict[str, dict] = {}
        self._win_job_handles: dict[str, int] = {}
        self._win_acl_paths: dict[str, list[str]] = {}
        self._win_sandbox_sids: dict[str, str | None] = {}
        self._win_policies: dict[str, Any] = {}
        # Per-sandbox stop serialization and ACL mutation serialization.
        self._win_stop_locks: dict[str, asyncio.Lock] = {}
        self._win_stop_users: dict[str, int] = {}
        self._win_acl_lock = asyncio.Lock()
        # exec admission-control semaphore (lazy, bound to the live loop).
        self._exec_concurrency_limit: int = int(
            os.environ.get("JIUWENBOX_EXEC_CONCURRENCY", "8")
        )
        self._win_exec_sem: asyncio.Semaphore | None = None
        # Runner log long-connection reader threads + stop signals.
        self._win_log_threads: dict[str, threading.Thread] = {}
        self._win_log_stops: dict[str, threading.Event] = {}
        # Background jobs (exec_background downgrades to sync exec on Windows).
        self._background_jobs: dict[str, dict[str, BackgroundJob]] = {}

    def capabilities(self) -> RuntimeCapabilities:
        return RuntimeCapabilities(
            runtime_name=self.runtime_name,
            local_pid=True,
            background_jobs=True,
            fast_file_io=True,
            recursive_search=True,
            network_identity=False,
            filesystem_acl=True,
            process_tree_containment=True,
            egress_filter=True,
            soft_delete=False,
            notes=(
                "restricted token + Job Object + WFP + ACL (phase 4); "
                "soft delete intentionally excluded (phase 5 has systemic "
                "issues and is not shipped)",
            ),
        )

    def _ensure_platform(self) -> None:
        if sys.platform != "win32":
            raise RuntimeUnavailableError(
                "WindowsRuntime requires a Windows host; "
                f"current platform is {sys.platform!r}"
            )

    def ensure_platform(self) -> None:
        """Reject hosts that cannot run the Windows sandbox runtime."""

        self._ensure_platform()

    def bind_exec_state(self, runners: dict) -> None:
        """Install an in-memory runner table for exec tests."""

        self._background_jobs = {}
        self._win_runners = runners
        self._exec_concurrency_limit = 8
        self._win_exec_sem = None

        def skip_platform_check() -> None:
            return None

        self._ensure_platform = skip_platform_check

    def background_job(self, sandbox_id: str, job_id: str) -> BackgroundJob:
        """Return one tracked background job."""

        return self._background_jobs[sandbox_id][job_id]

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _load_policy(policy_path: Path) -> Any:
        import yaml
        from jiuwenbox.models.policy import SecurityPolicy
        raw = Path(policy_path).read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("gb18030", errors="replace")
        return SecurityPolicy.model_validate(yaml.safe_load(text))

    @staticmethod
    def _win_workspace_for(sandbox_id: str) -> str:
        """Real workspace path on disk: ~/.jiuwenbox/workspace/<id>."""
        return str(WIN_SANDBOX_WORKSPACE_ROOT / sandbox_id)

    def _ensure_win_exec_semaphore(self) -> asyncio.Semaphore:
        sem = self._win_exec_sem
        if sem is None:
            sem = asyncio.Semaphore(self._exec_concurrency_limit)
            self._win_exec_sem = sem
        return sem

    async def _run_windows_acl(self, operation, *, sandbox_id: str | None = None):
        """Serialize ACL mutations off the loop, including cancelled requests."""
        queued = time.perf_counter()
        async with self._win_acl_lock:
            started = time.perf_counter()
            logger.info("[SandboxWin] %s ACL queue_wait=%.3fs", sandbox_id, started - queued)
            task = asyncio.create_task(asyncio.to_thread(operation))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                try:
                    await task
                finally:
                    raise
            finally:
                logger.info(
                    "[SandboxWin] %s ACL execution=%.3fs",
                    sandbox_id, time.perf_counter() - started,
                )

    @staticmethod
    def file_op_unavailable(sandbox_id: str) -> RuntimeFileOpResult:
        """Report that the runner IPC channel is not available."""

        return WindowsRuntime._file_op_unavailable(sandbox_id)

    @staticmethod
    def _file_op_unavailable(sandbox_id: str) -> RuntimeFileOpResult:
        return RuntimeFileOpResult(
            ok=False,
            error="daemon_unavailable",
            detail=(
                f"sandbox {sandbox_id!r} runner IPC channel unavailable; "
                "the runner is not running or its control port is gone"
            ),
        )

    @staticmethod
    def file_op_result_from_response(response: dict[str, Any]) -> RuntimeFileOpResult:
        """Translate one runner file-operation response."""

        return WindowsRuntime._file_op_result_from_response(response)

    @staticmethod
    def _file_op_result_from_response(response: dict[str, Any]) -> RuntimeFileOpResult:
        if response.get("ok"):
            return RuntimeFileOpResult(ok=True)
        return RuntimeFileOpResult(
            ok=False,
            error=str(response.get("error") or "io_error"),
            errno=int(response["errno"]) if isinstance(response.get("errno"), int) else None,
            detail=str(response.get("stderr") or response.get("detail") or ""),
        )

    # ------------------------------------------------------------------
    # create
    # ------------------------------------------------------------------
    async def create(
        self,
        sandbox_id: str,
        policy_path: Path,
        env: dict[str, str] | None = None,
    ) -> RuntimeInstance:
        self._ensure_platform()
        from jiuwenbox.supervisor import (
            win_acl, win_exec, win_job, win_setup, win_constants as const,
        )

        policy = self._load_policy(policy_path)
        self._win_policies[sandbox_id] = policy
        workspace = self._win_workspace_for(sandbox_id)
        try:
            os.makedirs(workspace, exist_ok=True)
        except OSError as exc:
            logger.warning(
                "[SandboxWin] %s 创建 workspace 目录失败 %s: %s",
                sandbox_id, workspace, exc,
            )

        def _expand_ws(path: str) -> str:
            return path.replace("{{ workspace }}", workspace)

        allow_read_paths = [_expand_ws(p) for p in (policy.windows.filesystem.allow_read or [])]
        allow_write_paths = [_expand_ws(p) for p in (policy.windows.filesystem.allow_write or [])]
        deny_write_paths = [_expand_ws(p) for p in (policy.windows.filesystem.deny_write or [])]
        deny_read_paths = [_expand_ws(p) for p in (policy.windows.filesystem.deny_read or [])]
        for _ro in (policy.filesystem_policy.read_only or []):
            if _ro and _ro not in deny_write_paths:
                deny_write_paths.append(_ro)
        bundled_python = (os.environ.get("JIUWENBOX_BUNDLED_PYTHON") or "").strip()
        if bundled_python:
            allow_read_paths.append(bundled_python)
        venv_dir = (os.environ.get("JIUWENBOX_VENV_DIR") or "").strip()
        if venv_dir:
            allow_write_paths.append(venv_dir)
        for _rw in (policy.filesystem_policy.read_write or []):
            if _rw and _rw not in allow_write_paths:
                allow_write_paths.append(_rw)
            if _rw and _rw not in allow_read_paths:
                allow_read_paths.append(_rw)
        for _mount in (policy.filesystem_policy.bind_mounts or []):
            _sp = getattr(_mount, "sandbox_path", None)
            if not _sp:
                continue
            _mode = str(getattr(_mount, "mode", "ro") or "ro").strip().lower()
            if _mode != "rw":
                if _sp not in allow_read_paths:
                    allow_read_paths.append(_sp)
                if _sp not in deny_write_paths:
                    deny_write_paths.append(_sp)
                continue
            if _sp not in allow_write_paths:
                allow_write_paths.append(_sp)
            if _sp not in allow_read_paths:
                allow_read_paths.append(_sp)
        for _p in allow_write_paths:
            if _p in (policy.filesystem_policy.read_write or []):
                try:
                    os.makedirs(_p, exist_ok=True)
                except OSError as _e:
                    logger.warning(
                        "[SandboxWin] %s 创建产物目录失败 %s: %s",
                        sandbox_id, _p, _e,
                    )

        # Tool paths -> runner PATH prefix (read ACL is preinstalled at setup).
        tool_paths = policy.windows.filesystem.tool_paths
        win_tool_dirs: list[str] = []
        for _dir_attr, _name in (
            (tool_paths.git_dir, "git_dir"),
            (tool_paths.node_dir, "node_dir"),
            (tool_paths.python_dir, "python_dir"),
        ):
            _d = (_dir_attr or "").strip()
            if not _d:
                continue
            win_tool_dirs.append(_d)
            if _name == "git_dir":
                win_tool_dirs.append(os.path.join(_d, "usr", "bin"))
                win_tool_dirs.append(os.path.join(_d, "bin"))
        _bash_path = (tool_paths.bash_path or "").strip()
        env = dict(env) if env else {}
        if win_tool_dirs:
            existing_path = env.get("PATH", os.environ.get("PATH", ""))
            extra = os.pathsep.join(win_tool_dirs)
            env["PATH"] = f"{extra}{os.pathsep}{existing_path}" if existing_path else extra
            env.setdefault("SystemRoot", os.environ.get("SystemRoot", ""))
        if _bash_path:
            env.setdefault("JIUWENBOX_BASH_PATH", _bash_path)

        # Sandbox-writable temp under the jbx-sandbox profile.
        under_profile = (env.get("USERPROFILE") or "").strip() or os.path.join(
            os.environ.get("SystemDrive", r"C:").rstrip("\\") + "\\",
            "Users", "jbx-sandbox",
        )
        win_tmp_dir = os.path.join(
            under_profile, "AppData", "Local", "Temp", "jiuwenbox", sandbox_id,
        )
        env.setdefault("TEMP", win_tmp_dir)
        env.setdefault("TMP", win_tmp_dir)
        env.setdefault("TMPDIR", win_tmp_dir)
        env.setdefault("USERPROFILE", under_profile)
        env.setdefault("HOME", under_profile)
        env.setdefault("LOCALAPPDATA", os.path.join(under_profile, "AppData", "Local"))
        env.setdefault("APPDATA", os.path.join(under_profile, "AppData", "Roaming"))
        from jiuwenbox.server.environment import inherited_environment
        for _k, _v in inherited_environment(for_runner=True).items():
            env.setdefault(_k, _v)

        def _apply_acl():
            sandbox_user_sid = win_setup.get_sandbox_user_sid()
            _runner_py = (
                (os.environ.get("JIUWENBOX_RUNNER_PYTHON") or "").strip()
                or sys.executable
            )
            if sandbox_user_sid and _runner_py:
                try:
                    win_acl.grant_parent_traverse(_runner_py, sandbox_user_sid)
                except Exception:  # noqa: BLE001
                    logger.warning(
                        "[SandboxWin] %s grant_parent_traverse 失败 python=%s",
                        sandbox_id, _runner_py, exc_info=True,
                    )
            _preinstalled = win_setup.get_preinstalled_read_paths()
            _all_acl_paths = list(dict.fromkeys(
                [p for p in allow_read_paths if os.path.expandvars(p).rstrip("\\/").lower() not in _preinstalled]
                + deny_read_paths + allow_write_paths + deny_write_paths
            ))
            win_setup.ensure_acl_policy_paths_authorized(
                _all_acl_paths,
                proxy_port_start=policy.windows.proxy.port_range_start,
                proxy_port_end=policy.windows.proxy.port_range_end,
                policy_path=str(policy_path),
                allow_elevation=False,
            )
            acl_paths = win_acl.apply_sandbox_acl(
                workspace,
                list(allow_write_paths),
                deny_write_paths,
                allow_read=list(allow_read_paths),
                deny_read=deny_read_paths,
                sandbox_user_sid=sandbox_user_sid,
                preinstalled_read_paths=_preinstalled,
                bounded_roots=_bounded_acl_roots(
                    workspace,
                    policy.filesystem_policy.read_write,
                    policy.filesystem_policy.bind_mounts,
                ),
            )
            if sandbox_user_sid:
                _traverse_targets: list[str] = [workspace, *allow_write_paths]
                _seen_traverse: set[str] = set()
                for _tp in _traverse_targets:
                    if not _tp:
                        continue
                    _tk = os.path.normcase(os.path.abspath(_tp))
                    if _tk in _seen_traverse:
                        continue
                    _seen_traverse.add(_tk)
                    try:
                        win_acl.grant_parent_traverse(_tp, sandbox_user_sid)
                        win_acl.grant_parent_traverse(
                            _tp, win_acl.get_synthetic_write_sid(),
                        )
                    except Exception:  # noqa: BLE001
                        logger.warning(
                            "[SandboxWin] %s grant_parent_traverse 失败 path=%s",
                            sandbox_id, _tp, exc_info=True,
                        )
            self._win_acl_paths[sandbox_id] = acl_paths or [workspace]
            self._win_sandbox_sids[sandbox_id] = sandbox_user_sid
            try:
                win_setup.record_applied_acl_paths(acl_paths or [], workspace)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "record_applied_acl_paths 失败 sandbox=%s",
                    sandbox_id, exc_info=True,
                )
            return acl_paths or [workspace], sandbox_user_sid

        try:
            await self._run_windows_acl(_apply_acl, sandbox_id=sandbox_id)
        except asyncio.CancelledError:
            await self._stop_windows(sandbox_id)
            raise

        # Two-hop spawn.
        user = const.SANDBOX_USER_NAME
        password = await asyncio.to_thread(win_setup.get_sandbox_user_password)
        if not password:
            raise RuntimeError(
                "无法读取 jbx-sandbox 用户密码; 请重新运行安装包, 或管理员执行 "
                "jiuwenbox-win-setup --install --force --recreate-user"
            )
        await asyncio.to_thread(win_setup.ensure_sandbox_user_can_logon)
        proxy_start = policy.windows.proxy.port_range_start
        proxy_end = policy.windows.proxy.port_range_end
        control_port = _alloc_loopback_port()
        control_token = secrets.token_urlsafe(32)

        # Job = owner-death safety net. Resource limits come from policy.
        res = policy.windows.resource
        try:
            job_handle = win_job.create_job(
                memory_max=res.memory_max,
                cpu_rate=res.cpu_rate,
                max_processes=res.max_processes,
            )
            self._win_job_handles[sandbox_id] = job_handle
        except Exception:
            await self._stop_windows(sandbox_id)
            raise

        def remember_runner(pid, handle):
            self._win_runners[sandbox_id] = {
                "pid": pid, "process_handle": handle, "control_port": control_port,
                "control_token": control_token, "workspace": workspace,
            }

        spawn_task = asyncio.create_task(asyncio.to_thread(
            win_exec.two_hop_spawn_and_authorize,
            sandbox_id,
            sandbox_user=user,
            sandbox_password=password,
            workspace=workspace,
            proxy_port_start=proxy_start,
            proxy_port_end=proxy_end,
            control_port=control_port,
            env=env,
            control_token=control_token,
            job_handle=job_handle,
        ))
        try:
            runner_pid, proc_handle = await asyncio.shield(spawn_task)
        except asyncio.CancelledError:
            try:
                pid, handle = await spawn_task
                remember_runner(pid, handle)
            except Exception:  # noqa: BLE001
                logger.warning(
                    "取消后 runner 启动失败 sandbox=%s", sandbox_id, exc_info=True,
                )
            await self._stop_windows(sandbox_id)
            raise
        except Exception:  # noqa: BLE001
            await self._stop_windows(sandbox_id)
            raise
        logger.info(
            "[SandboxWin] %s runner spawned (two-hop): pid=%s, workspace=%s, "
            "proxy_port=%s-%s, control_port=%s, state=RUNNING",
            sandbox_id, runner_pid, workspace, proxy_start, proxy_end, control_port,
        )
        remember_runner(runner_pid, proc_handle)

        stop_evt = threading.Event()
        log_thread = threading.Thread(
            target=self._win_log_reader_blocking,
            args=(sandbox_id, control_port, stop_evt, control_token),
            name=f"win-runner-log-{sandbox_id}",
            daemon=True,
        )
        self._win_log_stops[sandbox_id] = stop_evt
        self._win_log_threads[sandbox_id] = log_thread
        log_thread.start()

        try:
            await self._wait_win_runner_ready(sandbox_id)
        except (Exception, asyncio.CancelledError) as exc:  # noqa: BLE001
            logger.error(
                "Windows runner 启动就绪检查失败, 清理半启动沙箱 (sandbox=%s): %s",
                sandbox_id, exc,
            )
            try:
                await self._stop_windows(sandbox_id)
            except Exception:  # noqa: BLE001
                logger.debug(
                    "半启动沙箱清理异常 sandbox=%s", sandbox_id, exc_info=True,
                )
            raise

        logger.info("Windows 沙箱已创建: %s runner_pid=%d", sandbox_id, runner_pid)
        return RuntimeInstance(
            runtime_name=self.runtime_name,
            instance_id=sandbox_id,
            pid=runner_pid,
        )

    async def _wait_win_runner_ready(self, sandbox_id: str) -> None:
        import time as _t
        from jiuwenbox.supervisor import win_exec

        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            raise RuntimeError(
                f"Windows runner 就绪检查失败: runner 已不在 _win_runners (sandbox={sandbox_id})"
            )
        control_port = runner["control_port"]
        process_handle = runner["process_handle"]
        loop = asyncio.get_running_loop()
        deadline = _t.perf_counter() + WIN_RUNNER_READY_TIMEOUT_SECONDS
        while True:
            alive = await loop.run_in_executor(None, win_exec.is_runner_alive, process_handle)
            if not alive:
                raise RuntimeError(
                    f"Windows runner 启动期退出 (sandbox={sandbox_id}, pid={runner['pid']})"
                )
            listening = await loop.run_in_executor(
                None, win_exec.probe_runner_listen, control_port,
            )
            if listening:
                logger.info(
                    "Windows runner 已就绪 (listen 确认): sandbox=%s control_port=%d pid=%d",
                    sandbox_id, control_port, runner["pid"],
                )
                return
            if _t.perf_counter() >= deadline:
                raise RuntimeError(
                    f"Windows runner 就绪超时: {WIN_RUNNER_READY_TIMEOUT_SECONDS}s "
                    f"内 control_port={control_port} 未进入 listen (sandbox={sandbox_id})"
                )
            await asyncio.sleep(WIN_RUNNER_READY_PROBE_INTERVAL)

    # ------------------------------------------------------------------
    # stop / is_running / cleanup
    # ------------------------------------------------------------------
    async def stop(self, sandbox_id: str, timeout: float = 10.0) -> None:
        self._ensure_platform()
        lock = self._win_stop_locks.setdefault(sandbox_id, asyncio.Lock())
        self._win_stop_users[sandbox_id] = self._win_stop_users.get(sandbox_id, 0) + 1
        try:
            async with lock:
                await self._stop_windows(sandbox_id, timeout)
        finally:
            remaining = self._win_stop_users[sandbox_id] - 1
            if remaining:
                self._win_stop_users[sandbox_id] = remaining
            else:
                self._win_stop_users.pop(sandbox_id)
                self._win_stop_locks.pop(sandbox_id)

    async def _stop_windows(self, sandbox_id: str, timeout: float = 10.0) -> None:
        from jiuwenbox.supervisor import win_acl, win_exec, win_job

        runner = self._win_runners.get(sandbox_id)
        if runner is not None:
            logger.info(
                "[SandboxWin] delete sandbox=%s runner_pid=%s control_port=%s",
                sandbox_id, runner["pid"], runner["control_port"],
            )
            await self._send_runner_shutdown(sandbox_id, runner)
            stop_evt = self._win_log_stops.pop(sandbox_id, None)
            log_thread = self._win_log_threads.pop(sandbox_id, None)
            if stop_evt is not None:
                stop_evt.set()
            if log_thread is not None:
                await asyncio.to_thread(log_thread.join, 2.0)
            try:
                await asyncio.shield(asyncio.to_thread(
                    win_exec.stop_runner, runner["pid"], runner["process_handle"],
                ))
            except Exception:  # noqa: BLE001
                logger.warning(
                    "停止 runner 失败 sandbox=%s", sandbox_id, exc_info=True,
                )
            self._win_runners.pop(sandbox_id, None)
            job = self._win_job_handles.pop(sandbox_id, None)
            if job is not None:
                win_job.teardown(job)
        else:
            job = self._win_job_handles.pop(sandbox_id, None)
            if job is not None:
                win_job.teardown(job)

        acl_paths = self._win_acl_paths.get(sandbox_id)
        sandbox_user_sid = self._win_sandbox_sids.get(sandbox_id)
        if acl_paths:
            try:
                await self._run_windows_acl(
                    lambda: win_acl.revoke_sandbox_acl(
                        acl_paths, sandbox_user_sid=sandbox_user_sid,
                    ),
                    sandbox_id=sandbox_id,
                )
            except Exception:  # noqa: BLE001
                logger.warning("撤销 ACL 失败 sandbox=%s", sandbox_id, exc_info=True)
        self._win_acl_paths.pop(sandbox_id, None)
        self._win_sandbox_sids.pop(sandbox_id, None)

    async def is_running(self, sandbox_id: str) -> bool:
        self._ensure_platform()
        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            return False
        from jiuwenbox.supervisor import win_exec
        try:
            return await asyncio.to_thread(
                win_exec.is_runner_alive, runner["process_handle"],
            )
        except Exception:  # noqa: BLE001
            return False

    async def cleanup(self, sandbox_id: str) -> None:
        self._ensure_platform()
        await self.stop(sandbox_id)
        self._win_runners.pop(sandbox_id, None)
        self._win_policies.pop(sandbox_id, None)
        self._win_acl_paths.pop(sandbox_id, None)
        self._win_sandbox_sids.pop(sandbox_id, None)
        self._background_jobs.pop(sandbox_id, None)

    # ------------------------------------------------------------------
    # exec / IPC roundtrip
    # ------------------------------------------------------------------
    async def exec(
        self,
        sandbox_id: str,
        request: RuntimeExecRequest,
    ) -> ExecResult:
        self._ensure_platform()
        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            return ExecResult(
                exit_code=1,
                stderr=f"sandbox {sandbox_id!r} runner 不可用; 沙箱未运行或已停止",
            )
        async with self._ensure_win_exec_semaphore():
            payload: dict[str, Any] = {
                "command": list(request.command),
                "stdin_size": len(request.stdin_data or b""),
            }
            if request.env:
                payload["env"] = dict(request.env)
            if request.workdir:
                payload["workdir"] = request.workdir
            if request.timeout is not None:
                payload["timeout"] = request.timeout
            response = await self._win_runner_roundtrip(
                sandbox_id, runner, REQUEST_TYPE_EXEC, payload, request.stdin_data,
                read_timeout=float(request.timeout) if request.timeout is not None else None,
            )
            if response is None:
                return ExecResult(
                    exit_code=1,
                    stderr=f"sandbox {sandbox_id!r} runner IPC 失败",
                )
            return ExecResult(
                exit_code=int(response.get("exit_code", 1)),
                stdout=str(response.get("stdout", "")),
                stderr=str(response.get("stderr", "")),
            )

    @staticmethod
    def _win_roundtrip_blocking(  # pylint: disable=too-many-arguments
        control_port: int,
        request_type: str,
        payload: dict[str, Any],
        body_bytes: bytes | None,
        want_body: bool,
        read_timeout: float | None = None,
        control_token: str | None = None,
    ) -> "tuple[dict[str, Any] | None, bytes]":
        import socket
        if control_token:
            payload = {**payload, "token": control_token}
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(DAEMON_CONNECT_TIMEOUT_SECONDS)
            sock.connect(("127.0.0.1", control_port))
            if request_type == REQUEST_TYPE_EXEC:
                _exec_read_timeout = 130.0
                if read_timeout is not None:
                    _exec_read_timeout = max(_exec_read_timeout, float(read_timeout) + 10.0)
                sock.settimeout(_exec_read_timeout)
            else:
                sock.settimeout(DAEMON_FILE_OP_TIMEOUT_SECONDS)
            send_frame(sock, encode_request(request_type=request_type, payload=payload))
            if body_bytes:
                send_frame(sock, body_bytes)
            blob = recv_frame(sock, DAEMON_MAX_RESPONSE_BYTES)
            response = json.loads(blob.decode("utf-8"))
            body = b""
            if want_body and response.get("ok"):
                size = int(response.get("content_size") or 0)
                if size > 0:
                    body = recv_frame(sock, MAX_FILE_BYTES)
            return response, body
        finally:
            sock.close()

    async def _win_runner_roundtrip(  # pylint: disable=too-many-arguments
        self,
        sandbox_id: str,
        runner: dict,
        request_type: str,
        payload: dict[str, Any],
        body_bytes: bytes | None,
        read_timeout: float | None = None,
    ) -> dict[str, Any] | None:
        loop = asyncio.get_running_loop()
        try:
            response, _ = await loop.run_in_executor(
                None,
                lambda: self._win_roundtrip_blocking(
                    runner["control_port"],
                    request_type, payload, body_bytes, False,
                    read_timeout=read_timeout,
                    control_token=runner.get("control_token"),
                ),
            )
            return response
        except (OSError, ValueError) as exc:
            logger.warning(
                "Windows runner IPC 失败 (sandbox=%s): %s", sandbox_id, exc,
            )
            return None

    async def _win_runner_roundtrip_with_body(
        self,
        sandbox_id: str,
        runner: dict,
        request_type: str,
        payload: dict[str, Any],
    ) -> "tuple[dict[str, Any] | None, bytes]":
        loop = asyncio.get_running_loop()
        try:
            response, content = await loop.run_in_executor(
                None,
                lambda: self._win_roundtrip_blocking(
                    runner["control_port"],
                    request_type, payload, None, True,
                    control_token=runner.get("control_token"),
                ),
            )
            return response, content
        except (OSError, ValueError) as exc:
            logger.warning(
                "Windows runner IPC 失败 (sandbox=%s): %s", sandbox_id, exc,
            )
            return None, b""

    # ------------------------------------------------------------------
    # fast file IO (write_file / read_file / list_dir)
    # ------------------------------------------------------------------
    async def write_file(
        self,
        sandbox_id: str,
        sandbox_path: str,
        content: bytes,
        *,
        mkdir_parents: bool = True,
        mode: int | None = None,
    ) -> RuntimeFileOpResult:
        self._ensure_platform()
        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            return self._file_op_unavailable(sandbox_id)
        payload: dict[str, Any] = {
            "path": sandbox_path,
            "content_size": len(content),
            "mkdir_parents": mkdir_parents,
        }
        if mode is not None:
            payload["mode"] = mode
        response = await self._win_runner_roundtrip(
            sandbox_id, runner, REQUEST_TYPE_WRITE_FILE, payload, content,
        )
        if response is None:
            return self._file_op_unavailable(sandbox_id)
        return self._file_op_result_from_response(response)

    async def read_file(
        self,
        sandbox_id: str,
        sandbox_path: str,
    ) -> RuntimeFileOpResult:
        self._ensure_platform()
        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            return self._file_op_unavailable(sandbox_id)
        response, content = await self._win_runner_roundtrip_with_body(
            sandbox_id, runner, REQUEST_TYPE_READ_FILE, {"path": sandbox_path},
        )
        if response is None:
            return self._file_op_unavailable(sandbox_id)
        if response.get("ok"):
            return RuntimeFileOpResult(ok=True, content=content or b"")
        return self._file_op_result_from_response(response)

    async def list_dir(
        self,
        sandbox_id: str,
        sandbox_path: str,
        *,
        recursive: bool = False,
        max_depth: int | None = None,
        include_files: bool = True,
        include_dirs: bool = True,
    ) -> RuntimeFileOpResult:
        self._ensure_platform()
        runner = self._win_runners.get(sandbox_id)
        if runner is None:
            return self._file_op_unavailable(sandbox_id)
        payload: dict[str, Any] = {
            "path": sandbox_path,
            "recursive": recursive,
            "include_files": include_files,
            "include_dirs": include_dirs,
        }
        if max_depth is not None:
            payload["max_depth"] = max_depth
        response = await self._win_runner_roundtrip(
            sandbox_id, runner, REQUEST_TYPE_LIST_DIR, payload, None,
        )
        if response is None:
            return self._file_op_unavailable(sandbox_id)
        if response.get("ok"):
            items = response.get("items")
            if not isinstance(items, list):
                items = []
            return RuntimeFileOpResult(ok=True, items=items)
        return self._file_op_result_from_response(response)

    # ------------------------------------------------------------------
    # background jobs
    # ------------------------------------------------------------------
    def _background_jobs_for_sandbox(self, sandbox_id: str) -> dict[str, BackgroundJob]:
        return self._background_jobs.setdefault(sandbox_id, {})

    def _get_background_job_record(self, sandbox_id: str, job_id: str) -> BackgroundJob:
        job = self._background_jobs_for_sandbox(sandbox_id).get(job_id)
        if job is None:
            raise BackgroundJobNotFoundError(
                f"Background job {job_id!r} not found in sandbox {sandbox_id!r}"
            )
        return job

    @staticmethod
    def job_status(job: BackgroundJob) -> BackgroundJobStatus:
        """Return the public status view of one background job."""

        return WindowsRuntime._job_status(job)

    @staticmethod
    def _job_status(job: BackgroundJob) -> BackgroundJobStatus:
        return BackgroundJobStatus(
            job_id=job.job_id,
            sandbox_id=job.sandbox_id,
            command=list(job.command),
            pid=job.pid,
            running=job.exit_code is None,
            exit_code=job.exit_code,
            started_at=job.started_at,
            finished_at=job.finished_at,
            workdir=job.workdir,
        )

    @staticmethod
    def _job_summary(job: BackgroundJob) -> BackgroundJobSummary:
        return BackgroundJobSummary(
            job_id=job.job_id,
            pid=job.pid,
            command=list(job.command),
            running=job.exit_code is None,
            exit_code=job.exit_code,
            started_at=job.started_at,
            finished_at=job.finished_at,
        )

    async def exec_background(
        self,
        sandbox_id: str,
        request: RuntimeBackgroundExecRequest,
    ) -> BackgroundExecResult:
        self._ensure_platform()
        # Windows backend runs the command synchronously and records the
        # finished job: the runner has no detached-process fast path.
        logger.warning(
            "Windows exec_background 降级为同步 exec (sandbox=%s)", sandbox_id,
        )
        result = await self.exec(
            sandbox_id,
            RuntimeExecRequest(
                command=request.command,
                workdir=request.workdir,
                env=request.env,
                stdin_data=request.stdin_data,
            ),
        )
        job = BackgroundJob(
            job_id=request.job_id,
            sandbox_id=sandbox_id,
            command=list(request.command),
            pid=None,
            workdir=request.workdir,
            finished_at=datetime.now(timezone.utc),
            exit_code=result.exit_code,
        )
        self._background_jobs_for_sandbox(sandbox_id)[request.job_id] = job
        return BackgroundExecResult(
            started=True,
            job_id=request.job_id,
            pid=None,
            command=list(request.command),
            running=False,
            exit_code=result.exit_code,
        )

    async def get_background_job(
        self, sandbox_id: str, job_id: str,
    ) -> BackgroundJobStatus:
        self._ensure_platform()
        job = self._get_background_job_record(sandbox_id, job_id)
        return self._job_status(job)

    async def list_background_jobs(
        self, sandbox_id: str, *, running_only: bool = False,
    ) -> list[BackgroundJobSummary]:
        self._ensure_platform()
        jobs = list(self._background_jobs_for_sandbox(sandbox_id).values())
        summaries = [self._job_summary(job) for job in jobs]
        if running_only:
            summaries = [item for item in summaries if item.running]
        summaries.sort(key=lambda item: item.started_at, reverse=True)
        return summaries

    async def kill_background_job(
        self, sandbox_id: str, job_id: str, signum: int = 15,
    ) -> KillBackgroundJobResult:
        self._ensure_platform()
        job = self._get_background_job_record(sandbox_id, job_id)
        if job.exit_code is not None:
            return KillBackgroundJobResult(
                job_id=job_id,
                killed=False,
                reason="already_exited",
                exit_code=job.exit_code,
            )
        return KillBackgroundJobResult(
            job_id=job_id,
            killed=False,
            reason="unsupported",
            exit_code=job.exit_code,
        )

    # ------------------------------------------------------------------
    # runner shutdown / log reader
    # ------------------------------------------------------------------
    async def _send_runner_shutdown(self, sandbox_id: str, runner: dict) -> None:
        loop = asyncio.get_running_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, self._send_runner_shutdown_blocking, runner),
                timeout=DAEMON_SHUTDOWN_TIMEOUT_SECONDS,
            )
        except OSError as exc:
            logger.debug("Windows runner shutdown 失败 %s: %s", sandbox_id, exc)

    @staticmethod
    def _send_runner_shutdown_blocking(runner: dict) -> None:
        import socket
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(DAEMON_SHUTDOWN_TIMEOUT_SECONDS)
            try:
                sock.connect(("127.0.0.1", runner["control_port"]))
                payload: dict[str, Any] = {}
                _ct = runner.get("control_token")
                if _ct:
                    payload["token"] = _ct
                send_frame(
                    sock, encode_request(request_type=REQUEST_TYPE_SHUTDOWN, payload=payload),
                )
                try:
                    recv_frame(sock, DAEMON_MAX_RESPONSE_BYTES)
                except (OSError, ValueError):
                    pass
            finally:
                sock.close()
        except Exception:  # noqa: BLE001
            logger.debug("runner shutdown 发送异常", exc_info=True)

    @staticmethod
    def _win_log_reader_blocking(
        sandbox_id: str, control_port: int, stop_evt: threading.Event,
        control_token: str | None = None,
    ) -> None:
        import socket
        prefix = f"[win-runner][sandbox={sandbox_id}]"
        _sub_payload: dict[str, Any] = {}
        if control_token:
            _sub_payload["token"] = control_token
        sock: socket.socket | None = None
        for _attempt in range(50):
            if stop_evt.is_set():
                return
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(DAEMON_CONNECT_TIMEOUT_SECONDS)
                sock.connect(("127.0.0.1", control_port))
                send_frame(
                    sock,
                    encode_request(request_type=REQUEST_TYPE_SUBSCRIBE_LOG, payload=_sub_payload),
                )
                sock.settimeout(None)
                break
            except OSError:
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
                    sock = None
                stop_evt.wait(0.1)
        else:
            logger.warning(
                "%s 日志长连握手失败 (control_port=%d): runner 未在重试窗口内就绪",
                prefix, control_port,
            )
            return
        logger.info("%s 日志长连已建立, 开始接收 runner 上报", prefix)
        try:
            while not stop_evt.is_set():
                try:
                    blob = recv_frame(sock, MAX_HEADER_BYTES)
                except (OSError, ValueError):
                    break
                try:
                    entry = json.loads(blob.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError):
                    logger.warning("%s 收到非 JSON log 帧, 原始=%r", prefix, blob[:128])
                    continue
                level = str(entry.get(LOG_FIELD_LEVEL, "INFO")).upper()
                msg = str(entry.get(LOG_FIELD_MESSAGE, ""))
                tb = entry.get(LOG_FIELD_TRACEBACK)
                if len(msg) > 2000:
                    msg = msg[:2000] + "...(truncated)"
                line = f"{prefix} {msg}"
                if tb:
                    tb_text = str(tb)
                    if len(tb_text) > 4000:
                        tb_text = tb_text[:4000] + "...(truncated)"
                    line = f"{line}\n{tb_text}"
                if level == "ERROR":
                    logger.error("%s", line)
                elif level == "WARNING":
                    logger.warning("%s", line)
                elif level == "DEBUG":
                    logger.debug("%s", line)
                else:
                    logger.info("%s", line)
        finally:
            try:
                sock.close()
            except OSError:
                pass
            logger.debug("%s 日志读取线程退出", prefix)