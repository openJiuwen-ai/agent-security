"""Unified security permission entry point."""

from __future__ import annotations

import copy
import inspect
from collections.abc import Iterable, Mapping
from typing import Any

from .component import PermissionComponent
from .models import PermissionLevel, PermissionResult
from .netguard import NetGuardComponent
from .routing import RouteContext, resolve_route, route_matches
from .toolguard.command_allowlist import CommandAllowlistComponent
from .toolguard.destructive_warning import DestructiveWarningComponent
from .toolguard.injection import InjectionComponent
from .toolguard.tiered import TieredPolicyComponent, _package_rules_enabled


class PermissionEngine:
    """Own component lifecycle and aggregate security decisions.

    Component construction stays private. Applications use this facade for
    execution decisions, raw policy queries and atomic configuration updates.
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
        self._components: tuple[PermissionComponent, ...] = ()
        self._config: dict[str, Any] = {}
        self._install(config or {})

    def _build_components(self) -> tuple[PermissionComponent, ...]:
        """Create the engine-owned components.

        Keep command policy intact. NetGuard owns network tool baselines, URL
        policy and connection checks behind one NETWORK subscription.
        """

        return (
            InjectionComponent(),
            CommandAllowlistComponent(),
            DestructiveWarningComponent(),
            TieredPolicyComponent(),
            NetGuardComponent(),
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
            component_config = snapshot
            if isinstance(component, NetGuardComponent):
                # This switch is shared with W1a. Normalize through its existing
                # parser before passing W3 its strict boolean component config.
                component_config = {
                    **snapshot,
                    "package_builtin_rules": _package_rules_enabled(
                        snapshot.get("package_builtin_rules")
                    ),
                }
            component.configure(component_config)
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

        if self._config.get("enabled", True) is False:
            return PermissionResult(PermissionLevel.ALLOW, reason="Permission system is disabled")

        results = await self._evaluate_components(tool_name, tool_args)
        return self._merge_results(results)

    async def evaluate_global_policy_directly(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        *,
        include_external_directory: bool = True,
    ) -> tuple[PermissionLevel | None, str | None]:
        """Query A/C policy without the execution switch or an ASK fallback.

        Unlike the former synchronous API, this uses the current async
        component pipeline. ``include_external_directory`` is retained for
        FileGuard integration; no Pipeline B component is registered yet.
        Injection, command allowlisting and display warnings are execution
        checks, not part of this raw policy query.
        """
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(tool_args, Mapping):
            raise TypeError("tool_args must be a mapping")
        if not isinstance(include_external_directory, bool):
            raise TypeError("include_external_directory must be boolean")
        results = await self._evaluate_components(tool_name, tool_args, raw_query=True)
        result = self._merge_results(results, default_permission=None)
        return result.permission, result.matched_rule

    async def _evaluate_components(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
        *,
        raw_query: bool = False,
    ) -> list[PermissionResult]:

        route = resolve_route(tool_name, tool_args)
        components = self._components
        results: list[PermissionResult] = []
        for component in components:
            # This host-only action checks an already-authorized connection,
            # not the original tool again. Its name alone does not make args trusted.
            if tool_name.strip() == "network_connect" and not isinstance(
                component, NetGuardComponent
            ):
                continue
            if not route_matches(route, getattr(component, "interests", None)):
                continue
            if raw_query:
                if isinstance(component, NetGuardComponent):
                    result = await component.evaluate_global_policy(
                        tool_name, tool_args, route=route
                    )
                elif isinstance(component, TieredPolicyComponent):
                    result = await self._evaluate_component(component, tool_name, tool_args, route)
                    if (
                        result is not None
                        and result.matched_rule == "tiered_policy:fallback(no_config)"
                    ):
                        result = None
                else:
                    continue
            else:
                result = await self._evaluate_component(component, tool_name, tool_args, route)
            if result is not None:
                results.append(result)

        return results

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
            parameter.kind is inspect.Parameter.VAR_KEYWORD for parameter in parameters.values()
        )
        if accepts_route:
            return await evaluate(tool_name, tool_args, route=route)
        return await evaluate(tool_name, tool_args)

    def update_config(self, config: Mapping[str, Any]) -> None:
        """Replace the configuration; on any error the old one stays active."""

        if not isinstance(config, Mapping):
            raise TypeError("config must be a mapping")
        self._install(config)

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
    def _merge_results(
        results: list[PermissionResult],
        *,
        default_permission: PermissionLevel | None = PermissionLevel.ASK,
    ) -> PermissionResult:
        """Merge component results without allowing a missing result to allow."""

        if not results:
            return PermissionResult(
                permission=default_permission,
                reason="No permission component is configured",
            )

        permission_results = [result for result in results if result.permission is not None]
        strongest = max(
            permission_results,
            key=lambda result: PermissionEngine._permission_rank(result.permission),
            default=None,
        )

        warnings = [warning for result in results for warning in result.warnings]
        external_paths = [path for result in results for path in result.external_paths]

        return PermissionResult(
            permission=(
                strongest.permission
                if strongest is not None and strongest.permission is not None
                else default_permission
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
