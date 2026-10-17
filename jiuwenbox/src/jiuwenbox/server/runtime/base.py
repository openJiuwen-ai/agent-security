# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.
"""Abstract base class for sandbox runtime adapters."""

from __future__ import annotations

import abc
import asyncio
import logging
from dataclasses import dataclass, field
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
from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities

configure_logging()
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RuntimeExecRequest:
    command: list[str]
    workdir: str | None = None
    env: dict[str, str] | None = None
    stdin_data: bytes | None = None
    timeout: float | None = None


@dataclass(frozen=True)
class RuntimeBackgroundExecRequest:
    command: list[str]
    job_id: str
    workdir: str | None = None
    env: dict[str, str] | None = None
    stdin_data: bytes | None = None


@dataclass(frozen=True)
class RuntimeFileOpResult:
    """Result of an in-sandbox file op routed via the daemon fast path.

    ``ok`` indicates whether the op completed successfully. When ``ok`` is
    ``False`` callers can branch on ``error`` (a stable string code such
    as ``"not_found"``, ``"is_directory"``, ``"is_symlink"``, etc.) and
    optionally on ``errno`` to translate into HTTP semantics. ``content``
    and ``items`` are populated by the read/list paths respectively.
    """

    ok: bool
    error: str | None = None
    errno: int | None = None
    detail: str | None = None
    content: bytes | None = None
    items: list[dict[str, Any]] | None = None


@dataclass(frozen=True)
class RuntimeInstance:
    """A unified handle for a created sandbox (design doc section 5.2).

    ``create()`` returns this object so local-PID runtimes and remote
    runtimes (e.g. Conch) share one API surface. ``pid`` is ``None`` for
    runtimes that have no local process; ``ip_address`` is ``None`` unless
    the runtime discovered a network identity. ``metadata`` carries
    backend-specific opaque fields.
    """

    runtime_name: str
    instance_id: str
    pid: int | None = None
    ip_address: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class BackgroundJobNotFoundError(Exception):
    """Raised when a background job id is unknown for a sandbox.

    Lives in the runtime contract layer (rather than a platform-specific
    adapter module) so the manager and route layer can reference it without
    importing the Linux-only bubblewrap adapter.
    """


class RuntimeAdapter(abc.ABC):
    """Interface for sandbox runtime backends (process, docker, etc.)."""

    @property
    @abc.abstractmethod
    def runtime_name(self) -> str:
        """Stable name of this runtime (e.g. ``"bubblewrap"``)."""
        ...

    def capabilities(self) -> RuntimeCapabilities:
        """Declare what this runtime backend can enforce.

        Subclasses must override this to advertise their real capability
        set; the default is empty (everything ``False``) which is the
        fail-closed baseline. See ``jiuwenbox.server.runtime.capabilities``.
        """
        return RuntimeCapabilities(runtime_name=self.runtime_name)

    @abc.abstractmethod
    async def create(
        self,
        sandbox_id: str,
        policy_path: Path,
        env: dict[str, str] | None = None,
    ) -> RuntimeInstance:
        """Create and start a sandbox.  Returns a :class:`RuntimeInstance`."""
        ...

    @abc.abstractmethod
    async def stop(self, sandbox_id: str, timeout: float = 10.0) -> None:
        """Gracefully stop a sandbox."""
        ...

    @abc.abstractmethod
    async def is_running(self, sandbox_id: str) -> bool:
        """Check if the sandbox process is still alive."""
        ...

    @abc.abstractmethod
    async def exec(
        self,
        sandbox_id: str,
        request: RuntimeExecRequest,
    ) -> ExecResult:
        """Execute a one-shot command inside a running sandbox."""
        ...

    @abc.abstractmethod
    async def exec_background(
        self,
        sandbox_id: str,
        request: RuntimeBackgroundExecRequest,
    ) -> BackgroundExecResult:
        """Start a background command inside a running sandbox."""
        ...

    @abc.abstractmethod
    async def get_background_job(
        self,
        sandbox_id: str,
        job_id: str,
    ) -> BackgroundJobStatus:
        ...

    @abc.abstractmethod
    async def list_background_jobs(
        self,
        sandbox_id: str,
        *,
        running_only: bool = False,
    ) -> list[BackgroundJobSummary]:
        ...

    @abc.abstractmethod
    async def kill_background_job(
        self,
        sandbox_id: str,
        job_id: str,
        signum: int = 15,
    ) -> KillBackgroundJobResult:
        ...

    @abc.abstractmethod
    async def cleanup(self, sandbox_id: str) -> None:
        """Release all resources for a sandbox."""
        ...

    async def get_sandbox_ip_address(self, sandbox_id: str) -> str | None:
        """Return the sandbox's network identity, if any (default: none)."""
        return None

    async def apply_policy(
        self,
        sandbox_id: str,
        policy_path: Path,
    ) -> None:
        """Hot-apply a new policy to a running sandbox.

        Default is a no-op: runtimes without ``live_policy_update`` must not
        attempt to apply policies and should rely on restart semantics. A
        runtime that advertises ``live_policy_update`` must override this.
        """
        logger.debug(
            "runtime %s does not support live policy update; "
            "skipping apply_policy for %s",
            self.runtime_name,
            sandbox_id,
        )

    async def search_files(
        self,
        sandbox_id: str,
        sandbox_path: str,
        pattern: str,
        exclude_patterns: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Search files under a sandbox path (default: unsupported)."""
        return []

    async def write_file(
        self,
        sandbox_id: str,
        sandbox_path: str,
        content: bytes,
        *,
        mkdir_parents: bool = True,
        mode: int | None = None,
    ) -> RuntimeFileOpResult:
        """Write ``content`` to ``sandbox_path`` inside the sandbox.

        Default implementation indicates the runtime does not provide a
        fast path and the caller should fall back to ``exec``. Subclasses
        with a daemon IPC channel (``ProcessRuntime``) override this to
        avoid the fork+exec roundtrip.
        """
        return RuntimeFileOpResult(
            ok=False,
            error="unsupported",
            detail="runtime adapter does not implement write_file fast path",
        )

    async def read_file(
        self,
        sandbox_id: str,
        sandbox_path: str,
    ) -> RuntimeFileOpResult:
        """Read ``sandbox_path`` from the sandbox via the daemon fast path."""
        return RuntimeFileOpResult(
            ok=False,
            error="unsupported",
            detail="runtime adapter does not implement read_file fast path",
        )

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
        """List directory entries under ``sandbox_path``."""
        return RuntimeFileOpResult(
            ok=False,
            error="unsupported",
            detail="runtime adapter does not implement list_dir fast path",
        )


# Backwards-compatibility alias: the historical single local-process
# runtime. New code favours the explicit runtime names registered in
# ``jiuwenbox.server.runtime.registry``.
BACKWARD_COMPAT_RUNTIME_ALIASES: dict[str, str] = {
    "process": "bubblewrap",
    "linux": "bubblewrap",
}


def capabilities_for_runtime(adapter: RuntimeAdapter) -> RuntimeCapabilities:
    """Return the capabilities declared by ``adapter`` (with defaults)."""
    caps = adapter.capabilities()
    if caps.runtime_name != adapter.runtime_name:
        logger.warning(
            "runtime %s declared capabilities for %s; mismatch ignored",
            adapter.runtime_name,
            caps.runtime_name,
        )
    return caps


def run_in_executor(loop: asyncio.AbstractEventLoop | None, fn, *args) -> Any:
    """Small helper so runtime adapters can offload blocking calls uniformly."""
    run_loop = loop or asyncio.get_event_loop()
    return run_loop.run_in_executor(None, fn, *args)