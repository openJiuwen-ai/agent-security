# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Unified security permission entry point."""

from __future__ import annotations

import copy
import inspect
import logging
from collections.abc import Mapping
from typing import Any

from .component import PermissionComponent
from .delguard.component import DeletionGuardComponent
from .fileguard.component import FileGuardComponent, ImmutableControlPlaneComponent
from .hostguard import HostGuardComponent
from .models import PermissionLevel, PermissionResult
from .netguard import NetGuardComponent
from .routing import (
    CandidateKind,
    CommandDialect,
    RouteContext,
    is_shell_tool,
    resolve_dialect,
)
from .toolguard.builtin_rules import SHELL_TOOLS
from .toolguard.command_allowlist import CommandAllowlistComponent
from .toolguard.command_canonicalize import canonicalize_shell_command_for_permission
from .toolguard.destructive_warning import DestructiveWarningComponent
from .toolguard.injection import InjectionComponent
from .toolguard.shell_ast import parse_shell_for_permission
from .toolguard.tiered import TieredPolicyComponent

logger = logging.getLogger(__name__)

_COMPONENT_BY_NAME: dict[str, type[Any]] = {
    "host_guard": HostGuardComponent,
    "file_guard": FileGuardComponent,
    "deletion_guard": DeletionGuardComponent,
}


# Same set Tiered used before candidate expansion moved to the engine.
_SHELL_PARSE_TOOLS = frozenset(SHELL_TOOLS)


def _level_text(result: PermissionResult, *, with_rule: bool = True) -> str:
    level = result.permission.value if result.permission is not None else "none"
    if with_rule and result.matched_rule:
        return f"{level}({result.matched_rule})"
    return level


def _command_text(args: Mapping[str, Any]) -> str:
    return str(args.get("command", "") or args.get("cmd", "") or "").strip()


def _with_command(tool_args: Mapping[str, Any], command: str) -> dict[str, Any]:
    sub_args = dict(tool_args)
    if "command" in sub_args or "cmd" not in sub_args:
        sub_args["command"] = command
    if "cmd" in sub_args:
        sub_args["cmd"] = command
    return sub_args


class PermissionEngine:
    """Own component lifecycle and aggregate security decisions.

    Component construction stays private. Applications use this facade for
    execution decisions, raw policy queries and atomic configuration updates.
    """

    def __init__(self, config: Mapping[str, Any] | None = None, *, label: str = "") -> None:
        """Build the engine; ``label`` only tags this engine's log lines (e.g. its config key)."""

        self._label = label
        self._components: tuple[PermissionComponent, ...] = ()
        self._config: dict[str, Any] = {}
        self._enabled = True
        self._tiered: TieredPolicyComponent | None = None
        self._install(config or {})

    @staticmethod
    def _build_components() -> tuple[PermissionComponent, ...]:
        """Create the engine-owned components."""

        components = [
            InjectionComponent(),
            CommandAllowlistComponent(),
            DestructiveWarningComponent(),
            TieredPolicyComponent(),
            HostGuardComponent(),
            FileGuardComponent(),
            DeletionGuardComponent(),
            ImmutableControlPlaneComponent(),
            NetGuardComponent(),
        ]
        return tuple(components)

    def _install(self, config: Mapping[str, Any]) -> None:
        """Build and configure a fresh component set, then swap it in.

        Nothing current is touched until every new component is configured, so
        a failure leaves the old components and config fully in force.  Calls
        already running keep the component tuple they started with.
        """

        snapshot = copy.deepcopy(dict(config))
        enabled = snapshot.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("config 'enabled' must be a boolean")  # noqa: TRY004
        components = self._build_components()
        for component in components:
            component.configure(snapshot)
        tiered = next(
            (c for c in components if isinstance(c, TieredPolicyComponent)),
            None,
        )
        self._components = components
        self._tiered = tiered
        self._config = snapshot
        self._enabled = enabled

    async def check_permission(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> PermissionResult:
        """Evaluate one tool call; allow it without checks when disabled."""

        self._validate_call(tool_name, tool_args)
        if not self._enabled:
            return PermissionResult(
                permission=PermissionLevel.ALLOW,
                reason="Permission system is disabled",
            )
        return await self._evaluate(tool_name, tool_args)

    async def evaluate_global_policy_directly(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> tuple[PermissionLevel | None, str | None]:
        """Return the raw ``(permission, matched_rule)`` of one tool call.

        Runs the same checks as :meth:`check_permission` but is not
        short-circuited by the ``enabled`` switch.
        """

        self._validate_call(tool_name, tool_args)
        result = await self._evaluate(tool_name, tool_args)
        return result.permission, result.matched_rule

    def evaluate_component(
        self,
        name: str,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> PermissionResult | None:
        """Run one configured component and ignore every other component.

        ``check_permission`` still merges injection, allowlist, tiered policy,
        host guard, file guard, deletion guard, and net guard. Callers that
        own only one of those decisions use this method so the other
        components cannot vote.
        """

        component = self._named_component(name)
        self._validate_call(tool_name, tool_args)
        # Isolation API: ORIGINAL candidate only (no interests filtering).
        route, cand_args = self._build_candidates(tool_name, tool_args)[0]
        outcome = self._evaluate_component(component, tool_name, cand_args, route)
        try:
            outcome.send(None)
        except StopIteration as stop:
            return stop.value
        outcome.close()
        raise RuntimeError(f"{name} evaluate suspended; use check_permission")

    def component_active(self, name: str) -> bool:
        """Whether configure left the named component with work to do."""

        component = self._named_component(name)
        active = getattr(component, "active", None)
        if callable(active):
            return bool(active())
        return True

    def collect_file_guard_ask_accesses(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> list[tuple[str, str]]:
        """ASK paths from FileGuardComponent. Other components are not asked."""

        component = self._named_component("file_guard")
        collect = getattr(component, "collect_ask_accesses", None)
        if not callable(collect):
            return []
        return [(path, action) for path, action in collect(tool_name, tool_args)]

    def _named_component(self, name: str) -> PermissionComponent:
        component_type = _COMPONENT_BY_NAME.get(name)
        if component_type is None:
            raise ValueError(f"unknown permission component: {name}")
        for component in self._components:
            if isinstance(component, component_type):
                return component
        raise RuntimeError(f"permission component is not installed: {name}")

    @staticmethod
    def _validate_call(tool_name: str, tool_args: Mapping[str, Any]) -> None:
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise ValueError("tool_name must be a non-empty string")
        if not isinstance(tool_args, Mapping):
            raise TypeError("tool_args must be a mapping")

    @staticmethod
    def _build_candidates(
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> list[tuple[RouteContext, Mapping[str, Any]]]:
        """Expand one call into (route, args) candidates."""

        dialect = resolve_dialect(tool_name, tool_args)
        shell = dialect is not None or is_shell_tool(tool_name)
        if not shell:
            route = RouteContext(kind=CandidateKind.ORIGINAL, is_shell=False)
            return [(route, tool_args)]

        dialect = dialect or CommandDialect.UNKNOWN
        original = _command_text(tool_args)
        candidates: list[tuple[RouteContext, Mapping[str, Any]]] = [
            (
                RouteContext(
                    kind=CandidateKind.ORIGINAL,
                    command_dialect=dialect,
                    is_shell=True,
                ),
                tool_args,
            )
        ]
        canonical = canonicalize_shell_command_for_permission(original)
        if canonical != original:
            candidates.append(
                (
                    RouteContext(
                        kind=CandidateKind.UNWRAPPED,
                        command_dialect=dialect,
                        is_shell=True,
                    ),
                    _with_command(tool_args, canonical),
                )
            )

        # Subcommands come from the permission view (peeled when available).
        parse_text = canonical
        base = tool_name.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
        if base in _SHELL_PARSE_TOOLS or tool_name in _SHELL_PARSE_TOOLS:
            parse = parse_shell_for_permission(parse_text)
            if parse is not None and parse.kind == "simple" and any(s.text for s in parse.subcommands):
                # Multi-leaf only: a single leaf identical to the whole view is redundant.
                texts = [s.text for s in parse.subcommands if s.text]
                if len(texts) > 1 or (len(texts) == 1 and texts[0] != parse_text):
                    for text in texts:
                        candidates.append(
                            (
                                RouteContext(
                                    kind=CandidateKind.SUBCOMMAND,
                                    command_dialect=dialect,
                                    is_shell=True,
                                ),
                                _with_command(tool_args, text),
                            )
                        )
        return candidates

    async def _evaluate(
        self,
        tool_name: str,
        tool_args: Mapping[str, Any],
    ) -> PermissionResult:
        """Expand candidates, honour approval short-circuit, merge strictest."""

        candidates = self._build_candidates(tool_name, tool_args)
        tiered = self._tiered

        # Whole-call short-circuit: original or unwrapped hits approval.
        if tiered is not None:
            for route, cand_args in candidates:
                if route.kind not in (CandidateKind.ORIGINAL, CandidateKind.UNWRAPPED):
                    continue
                approval = tiered.match_approval(tool_name, _command_text(cand_args))
                if approval is not None:
                    self._log_decision(
                        tool_name,
                        route,
                        approval,
                        [(type(tiered).__name__, approval)],
                        [(type(tiered).__name__, approval)],
                    )
                    return approval

        candidate_verdicts: list[PermissionResult] = []
        all_subscribed: list[tuple[str, PermissionResult | None]] = []
        last_route = candidates[0][0]

        for route, cand_args in candidates:
            last_route = route
            # Subcommand approval: that candidate alone is ALLOW (highest).
            if (
                tiered is not None
                and route.kind is CandidateKind.SUBCOMMAND
            ):
                approval = tiered.match_approval(tool_name, _command_text(cand_args))
                if approval is not None:
                    candidate_verdicts.append(approval)
                    all_subscribed.append((type(tiered).__name__, approval))
                    continue

            subscribed: list[tuple[str, PermissionResult | None]] = []
            for component in self._components:
                name = type(component).__name__
                try:
                    result = await self._evaluate_component(
                        component, tool_name, cand_args, route
                    )
                except Exception:
                    logger.exception(
                        "permission.engine.component_failed key=%s tool=%s kind=%s component=%s",
                        self._label,
                        tool_name,
                        route.kind.value,
                        name,
                    )
                    raise
                subscribed.append((name, result))
                all_subscribed.append((name, result))

            verdicts = [result for _, result in subscribed if result is not None]
            candidate_verdicts.append(self._merge_results(verdicts))

        merged = self._merge_results(candidate_verdicts)
        final_verdicts = [
            (name, result) for name, result in all_subscribed if result is not None
        ]
        self._log_decision(tool_name, last_route, merged, all_subscribed, final_verdicts)
        return merged

    def _log_decision(
        self,
        tool_name: str,
        route: RouteContext,
        merged: PermissionResult,
        subscribed: list[tuple[str, PermissionResult | None]],
        verdicts: list[tuple[str, PermissionResult]],
    ) -> None:
        """Log one line per decision: who was asked, what each said, who won.

        Tool arguments are deliberately not logged; they may carry secrets.
        """

        if not subscribed:
            basis, winner = "no_subscriber", "-"
        elif not verdicts:
            basis, winner = "no_verdict", "-"
        else:
            basis = "component"
            winner = "-"
            for name, result in verdicts:
                if (
                    result.permission == merged.permission
                    and result.matched_rule == merged.matched_rule
                ):
                    winner = name
                    break
        components = ",".join(
            f"{name}={'none' if result is None else _level_text(result)}"
            for name, result in subscribed
        )
        logger.info(
            "permission.engine.decision key=%s tool=%s kind=%s shell=%s decision=%s "
            "matched_rule=%s winner=%s basis=%s components=[%s]",
            self._label,
            tool_name,
            route.kind.value,
            route.is_shell,
            _level_text(merged, with_rule=False),
            merged.matched_rule,
            winner,
            basis,
            components,
        )

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

    @property
    def config(self) -> Mapping[str, Any]:
        """Return the current engine configuration as a read-only view."""

        return self._config

    @property
    def components(self) -> tuple[PermissionComponent, ...]:
        """Return the component set used by the current configuration."""

        return self._components

    @staticmethod
    def merge_results(results: list[PermissionResult]) -> PermissionResult:
        """Merge component results for callers outside the engine."""

        return PermissionEngine._merge_results(results)

    @staticmethod
    def _merge_results(results: list[PermissionResult]) -> PermissionResult:
        """Merge component results without allowing a missing result to allow."""

        if not results:
            return PermissionResult(
                permission=PermissionLevel.ASK,
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
        return ranks.get(permission, -1)
