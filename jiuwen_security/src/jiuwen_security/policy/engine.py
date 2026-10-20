"""Unified security permission entry point."""

from __future__ import annotations

from collections.abc import Mapping
import copy
import inspect
from typing import Any

from .component import PermissionComponent
from .models import PermissionLevel, PermissionResult
from .routing import RouteContext, resolve_route, route_matches
from .toolguard.command_allowlist import CommandAllowlistComponent
from .toolguard.destructive_warning import DestructiveWarningComponent
from .toolguard.injection import InjectionComponent
from .toolguard.tiered import TieredPolicyComponent


class PermissionEngine:
    """Own component lifecycle and aggregate security decisions.

    Concrete security components are added by later requirements.  The engine
    deliberately keeps component construction private so registering a
    component is not an additional public API contract.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        self._components: tuple[PermissionComponent, ...] = ()
        self._config: dict[str, Any] = {}
        self._install(config or {})

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        """Create the engine-owned components.

        The first requirement establishes the registration point.  Concrete
        components are intentionally added by their own later requirements.
        """

        return (
            InjectionComponent(),
            CommandAllowlistComponent(),
            DestructiveWarningComponent(),
            TieredPolicyComponent(),
        )

    def _install(self, config: Mapping[str, Any]) -> None:
        """Build and configure a fresh component set, then swap it in.

        Nothing current is touched until every new component is configured, so
        a failure leaves the old components and config fully in force.  Calls
        already running keep the component tuple they started with.
        """

        snapshot = copy.deepcopy(dict(config))
        components = self._build_components()
        for component in components:
            component.configure(snapshot)
        self._components = components
        self._config = snapshot

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

        route = resolve_route(tool_name, tool_args)
        components = self._components
        results: list[PermissionResult] = []
        for component in components:
            if not route_matches(route, getattr(component, "interests", None)):
                continue
            result = await self._evaluate_component(component, tool_name, tool_args, route)
            if result is not None:
                results.append(result)

        return self._merge_results(results)

    async def evaluate_global_policy_directly(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> tuple[PermissionLevel | None, str | None]:
        """Return the raw ``(permission, matched_rule)`` of one tool call.

        Runs exactly the same checks as :meth:`check_permission`; only the
        result shape differs, for hosts that merge it with their own decisions.
        """

        result = await self.check_permission(tool_name, tool_args)
        return result.permission, result.matched_rule

    @staticmethod
    async def _evaluate_component(
        component: PermissionComponent,
        tool_name: str,
        tool_args: Mapping[str, Any],
        route: RouteContext,
    ) -> PermissionResult | None:
        """Call new route-aware components and retain old two-argument ones."""

        evaluate = component.evaluate
        parameters = inspect.signature(evaluate).parameters
        accepts_route = "route" in parameters or any(
            parameter.kind is inspect.Parameter.VAR_KEYWORD
            for parameter in parameters.values()
        )
        if accepts_route:
            return await evaluate(tool_name, tool_args, route=route)
        return await evaluate(tool_name, tool_args)

    def update_config(self, config: Mapping[str, Any]) -> None:
        """Replace the configuration; on any error the old one stays active."""

        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        self._install(config)

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
            PermissionLevel.UNDETERMINED: 1,
            PermissionLevel.ASK: 2,
            PermissionLevel.DENY: 3,
        }
        return ranks[permission] if permission is not None else -1
