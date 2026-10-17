"""Unified security permission entry point."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from .component import PermissionComponent
from .models import PermissionLevel, PermissionResult


class PermissionEngine:
    """Own component lifecycle and aggregate security decisions.

    Concrete security components are added by later requirements.  The engine
    deliberately keeps component construction private so registering a
    component is not an additional public API contract.
    """

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        *,
        workspace_root: str | None = None,
        trusted_dirs: Iterable[str] | None = None,
    ) -> None:
        self.workspace_root = workspace_root
        self._trusted_dirs = tuple(trusted_dirs or ())
        self._components = self._build_components()
        self._config: dict[str, Any] = {}
        self._configure_components(config or {})

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        """Create the engine-owned components.

        The first requirement establishes the registration point.  Concrete
        components are intentionally added by their own later requirements.
        """

        return ()

    def _configure_components(self, config: Mapping[str, Any]) -> None:
        """Configure every component before making the config current."""

        for component in self._components:
            component.configure(config)
        self._config = dict(config)

    async def check_permission(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> PermissionResult:
        """Evaluate one tool call through all registered components."""

        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(tool_args, Mapping):
            raise TypeError("tool_args must be a mapping")

        results: list[PermissionResult] = []
        for component in self._components:
            result = await component.evaluate(tool_name, tool_args)
            if result is not None:
                results.append(result)

        return self._merge_results(results)

    def update_config(self, config: Mapping[str, Any]) -> None:
        """Reconfigure all components using one complete configuration."""

        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        self._configure_components(config)

    def update_trusted_dirs(self, dirs: Iterable[str]) -> None:
        """Update the engine-owned trusted directory state."""

        self._trusted_dirs = tuple(dirs)

    @property
    def trusted_dirs(self) -> tuple[str, ...]:
        """Return the currently configured trusted directories."""

        return self._trusted_dirs

    @property
    def config(self) -> Mapping[str, Any]:
        """Return the current engine configuration as a read-only view."""

        return self._config

    @staticmethod
    def _merge_results(results: list[PermissionResult]) -> PermissionResult:
        """Merge component results without allowing a missing result to allow."""

        if not results:
            return PermissionResult(
                permission=PermissionLevel.ASK,
                reason="No permission component is configured",
            )

        permission_results = [
            result for result in results if result.permission is not None
        ]
        strongest = max(
            permission_results,
            key=lambda result: PermissionEngine._permission_rank(result.permission),
            default=None,
        )

        warnings = [warning for result in results for warning in result.warnings]
        external_paths = [
            path for result in results for path in result.external_paths
        ]

        return PermissionResult(
            permission=(
                strongest.permission
                if strongest is not None and strongest.permission is not None
                else PermissionLevel.ASK
            ),
            matched_rule=strongest.matched_rule if strongest is not None else None,
            reason=strongest.reason if strongest is not None else None,
            warnings=warnings,
            external_paths=external_paths,
        )

    @staticmethod
    def _permission_rank(permission: PermissionLevel | None) -> int:
        """Return the strictness rank used by the initial result aggregator."""

        ranks = {
            PermissionLevel.ALLOW: 0,
            PermissionLevel.ASK: 1,
            PermissionLevel.UNDETERMINED: 2,
            PermissionLevel.DENY: 3,
        }
        return ranks[permission] if permission is not None else -1
