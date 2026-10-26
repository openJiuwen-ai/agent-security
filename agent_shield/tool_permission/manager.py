"""Process-wide permission entry point holding one configuration per key."""

from __future__ import annotations

import logging
import threading
from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from .engine import PermissionEngine
from .models import PermissionLevel, PermissionResult

logger = logging.getLogger(__name__)

DEFAULT_KEY = "default"
DEFAULT_MAX_KEYS = 1024
ONE_OFF_LABEL = "(one-off)"


class PermissionManager:
    """Keep a table of ``key -> PermissionEngine``; each key owns a full config.

    The manager only stores, replaces and removes configurations.  Rule
    matching stays in :class:`PermissionEngine`, and merging configurations
    (base, session overlay, skill grants, ...) is up to the caller.

    * ``key=None`` means :data:`DEFAULT_KEY`, which always exists, does not
      count against ``max_keys`` and cannot be removed.
    * Deciding with a key that has not been registered raises ``KeyError``;
      there is no fallback to the default configuration.
    * A decision can instead carry its own ``config``: a throw-away engine is
      built for that call only and nothing is registered.  When ``config`` is
      given it takes precedence and ``key`` is ignored.
    * Writes (update/remove) take a lock; reads do not.  A replacement swaps
      the whole engine object, so a reader sees either the old engine or the
      new one, and a decision already running keeps the engine it started with.
    """

    def __init__(self, max_keys: int = DEFAULT_MAX_KEYS) -> None:
        if isinstance(max_keys, bool) or not isinstance(max_keys, int):
            raise TypeError("max_keys must be an int")
        if max_keys < 0:
            raise ValueError("max_keys must not be negative")
        self._max_keys = max_keys
        self._lock = threading.Lock()
        self._engines: dict[str, PermissionEngine] = {
            DEFAULT_KEY: PermissionEngine({}, label=DEFAULT_KEY)
        }

    @staticmethod
    def _resolve_key(key: str | None) -> str:
        if key is None:
            return DEFAULT_KEY
        if not isinstance(key, str):
            raise TypeError("key must be a string")
        if not key.strip():
            raise ValueError("key must not be empty")
        return key

    def _engine(self, key: str | None) -> PermissionEngine:
        resolved = self._resolve_key(key)
        engine = self._engines.get(resolved)
        if engine is None:
            logger.warning("permission.manager.unregistered_key key=%s", resolved)
            raise KeyError(f"no permission config registered for key {resolved!r}")
        return engine

    def _engine_for(self, key: str | None, config: Mapping[str, Any] | None) -> PermissionEngine:
        if config is None:
            return self._engine(key)
        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        return PermissionEngine(config, label=ONE_OFF_LABEL)

    def update_config(self, config: Mapping[str, Any], key: str | None = None) -> None:
        """Register or wholly replace the configuration of ``key``.

        The new engine is built first (validation and deep copy happen there),
        so an invalid config raises and leaves the table untouched.
        """

        resolved = self._resolve_key(key)
        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        engine = PermissionEngine(config, label=resolved)
        with self._lock:
            if resolved not in self._engines and len(self._engines) - 1 >= self._max_keys:
                raise RuntimeError(
                    f"permission config limit reached ({self._max_keys}); "
                    f"cannot register key {resolved!r}"
                )
            replaced = resolved in self._engines
            self._engines[resolved] = engine
        logger.info("permission.manager.update key=%s replaced=%s", resolved, replaced)

    def remove_config(self, key: str) -> bool:
        """Remove ``key``; return whether it was registered.  ``default`` cannot be removed."""

        resolved = self._resolve_key(key)
        if resolved == DEFAULT_KEY:
            raise ValueError("the default config cannot be removed")
        with self._lock:
            removed = self._engines.pop(resolved, None) is not None
        logger.info("permission.manager.remove key=%s removed=%s", resolved, removed)
        return removed

    async def check_permission(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        key: str | None = None,
        *,
        config: Mapping[str, Any] | None = None,
    ) -> PermissionResult:
        """Evaluate one tool call with the config under ``key`` or a one-off ``config``."""

        return await self._engine_for(key, config).check_permission(tool_name, tool_args)

    async def evaluate_global_policy_directly(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        key: str | None = None,
        *,
        config: Mapping[str, Any] | None = None,
    ) -> tuple[PermissionLevel | None, str | None]:
        """Return the raw ``(permission, matched_rule)`` under ``key`` or a one-off ``config``."""

        return await self._engine_for(key, config).evaluate_global_policy_directly(
            tool_name, tool_args
        )

    def get_config(self, key: str | None = None) -> Mapping[str, Any]:
        """Return the configuration registered under ``key`` as a read-only view."""

        return MappingProxyType(self._engine(key).config)  # type: ignore[arg-type]

    def has_config(self, key: str | None = None) -> bool:
        return self._resolve_key(key) in self._engines

    def keys(self) -> tuple[str, ...]:
        """Return the registered keys, ``default`` included."""

        with self._lock:
            return tuple(self._engines)


_instance: PermissionManager | None = None
_instance_lock = threading.Lock()


def get_permission_manager() -> PermissionManager:
    """Return the process-wide :class:`PermissionManager`, creating it on first use."""

    global _instance
    if _instance is None:
        with _instance_lock:
            if _instance is None:
                _instance = PermissionManager()
    return _instance
