# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Runtime registry and selection (design doc sections 5.2 & 5.4).

The registry maps a runtime *name* to a loadable adapter class, and
``resolve_runtime`` applies the selection precedence required by the
design doc:

    1. explicit ``sandbox_runtime`` request field (highest priority);
    2. ``JIUWENBOX_RUNTIME_PROFILE`` service default;
    3. platform default:
       - Windows            -> ``windows``
       - Linux (ordinary)   -> ``bubblewrap``
       - AgentOS            -> ``conch`` (must be set explicitly)

Runtime classes are imported lazily so that importing a platform-specific
adapter (e.g. the Linux-only ``bubblewrap``, which imports ``pwd``/``grp``)
never happens on a platform that cannot load it.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys

from jiuwenbox.logging_config import configure_logging
from jiuwenbox.server.runtime.base import (
    BACKWARD_COMPAT_RUNTIME_ALIASES,
    RuntimeAdapter,
)

configure_logging()
logger = logging.getLogger(__name__)

RUNTIME_PROFILE_ENV = "JIUWENBOX_RUNTIME_PROFILE"

#: Canonical name -> import path of the concrete adapter class.
_RUNTIME_IMPORTS: dict[str, str] = {
    "bubblewrap": "jiuwenbox.server.runtime.process:BubblewrapRuntime",
    "windows": "jiuwenbox.server.runtime.windows.runtime:WindowsRuntime",
    # Reserved for the AgentOS cloud backend. Not yet registered on purpose:
    # configuring Conch without its SDK must fail (not silently fall back),
    # which matches the fail-closed rule in the design doc.
    "conch": "jiuwenbox.server.runtime.conch.runtime:ConchRuntime",
}

#: Optional attribute on the class holding a ``supported_platforms`` tuple.
_SUPPORTED_PLATFORMS_ATTR = "supported_platforms"

_instances: dict[str, RuntimeAdapter] = {}


class RuntimeResolutionError(RuntimeError):
    """Raised when a requested runtime cannot be resolved or loaded."""


def available_runtime_names() -> tuple[str, ...]:
    """Return the runtime names that are *importable* on this host.

    Importation is not attempted eagerly: a name is "available" only if the
    named module can currently be imported. Callers use this to report the
    supported set on ``/health`` / ``/capabilities``.
    """
    result: list[str] = []
    for name, import_path in _RUNTIME_IMPORTS.items():
        module_name = import_path.partition(":")[0]
        try:
            importlib.import_module(module_name)
        except Exception:  # noqa: BLE001
            continue
        result.append(name)
    return tuple(result)


def platform_default_runtime() -> str:
    """Return the runtime name that is the platform default.

    Linux -> ``bubblewrap``; Windows -> ``windows``. AgentOS deployments
    must set ``JIUWENBOX_RUNTIME_PROFILE=conch`` explicitly; we never
    infer Conch from the environment.
    """
    if sys.platform == "win32":
        return "windows"
    return "bubblewrap"


def _canonicalize(name: str) -> str:
    return BACKWARD_COMPAT_RUNTIME_ALIASES.get(name.lower(), name.lower())


def _import_class(import_path: str) -> type[RuntimeAdapter]:
    module_name, _, attr = import_path.partition(":")
    try:
        module = importlib.import_module(module_name)
    except Exception as exc:  # noqa: BLE001
        raise RuntimeResolutionError(
            f"runtime module {module_name!r} could not be imported: {exc}"
        ) from exc
    try:
        return getattr(module, attr)
    except AttributeError as exc:
        raise RuntimeResolutionError(
            f"runtime module {module_name!r} has no {attr!r} class"
        ) from exc


def load_runtime_class(name: str) -> type[RuntimeAdapter]:
    """Import and return the concrete adapter class for ``name``."""
    canonical = _canonicalize(name)
    import_path = _RUNTIME_IMPORTS.get(canonical)
    if import_path is None:
        known = ", ".join(sorted(_RUNTIME_IMPORTS))
        raise RuntimeResolutionError(
            f"unknown sandbox runtime {name!r}; known runtimes: {known}"
        )
    cls = _import_class(import_path)

    supported = getattr(cls, _SUPPORTED_PLATFORMS_ATTR, None)
    if supported is not None and sys.platform not in supported:
        raise RuntimeResolutionError(
            f"runtime {canonical!r} does not support platform {sys.platform!r}"
        )
    return cls


def resolve_runtime_name(
    sandbox_runtime: str | None,
    *,
    env: dict[str, str] | None = None,
) -> str:
    """Resolve the runtime name using the documented precedence.

    ``env`` overrides ``os.environ`` in tests without mutating the process
    environment.
    """
    if sandbox_runtime:
        return _canonicalize(sandbox_runtime)

    environ = env if env is not None else os.environ
    profile = environ.get(RUNTIME_PROFILE_ENV)
    if profile:
        return _canonicalize(profile)

    return platform_default_runtime()


def get_runtime(
    name: str | None = None,
    *,
    env: dict[str, str] | None = None,
) -> RuntimeAdapter:
    """Return a (possibly shared) runtime adapter instance for ``name``.

    When ``name`` is ``None`` the runtime is chosen via
    :func:`resolve_runtime_name`. Instances are cached so a single server
    process shares one adapter per runtime name (matching the current
    ``ProcessRuntime`` singleton behaviour in ``SandboxManager``).
    """
    resolved = resolve_runtime_name(name, env=env)
    instance = _instances.get(resolved)
    if instance is not None:
        return instance
    cls = load_runtime_class(resolved)
    instance = cls()
    _instances[resolved] = instance
    logger.info("selected runtime %r (class %s)", resolved, cls.__name__)
    return instance


def reset_registry() -> None:
    """Clear cached instances (used by tests / restart paths)."""
    _instances.clear()


def verify_runtime_available(name: str) -> bool:
    """Return True if ``name`` resolves and loads on this host (fail-closed).

    A runtime configured but not loadable returns ``False``; callers use
    this at service startup to refuse boot or mark readiness red (rather
    than silently falling back to a local process runtime).
    """
    try:
        load_runtime_class(name)
    except RuntimeResolutionError as exc:
        logger.error("runtime %r unavailable: %s", name, exc)
        return False
    return True