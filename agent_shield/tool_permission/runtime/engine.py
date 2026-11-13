# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Thin runtime adapter to agent-security's existing permission components."""

import logging
from copy import deepcopy
from dataclasses import replace
from functools import lru_cache, partial
from pathlib import Path
from threading import RLock
from weakref import WeakSet

from ..delguard.component import DeletionGuardComponent
from ..engine import PermissionEngine as SDKEngine
from ..fileguard.component import _permissions_for_file_guard
from ..fileguard.file_guard import build_file_guard_checker
from ..fileguard.immutable_control_plane import (
    ImmutableControlPlaneGuard,
)
from ..netguard.component import NetGuardComponent
from ..routing import CandidateKind, RouteContext, resolve_dialect
from ..shell_structure import ShellStructureOutcome
from ..toolguard.tiered import TieredPolicyComponent
from .config import effective_runtime_config, is_ip_literal, network_pattern
from .models import PermissionLevel, PermissionResult


def _runtime_result(result):
    if result is None:
        return PermissionResult(PermissionLevel.ALLOW)
    return PermissionResult(
        permission=result.permission,
        matched_rule=result.matched_rule,
        reason=result.reason,
        external_paths=result.external_paths.copy() if result.external_paths is not None else None,
        warnings=result.warnings.copy() if result.warnings is not None else None,
        ask_accesses=result.ask_accesses.copy() if result.ask_accesses is not None else None,
    )


def _network_action(value):
    if isinstance(value, dict):
        value = value.get("action", value.get("fetch"))
    return value.strip().lower() if isinstance(value, str) else value


def _read_rule(files, path):
    # The read axis matches the supplied path spelling against compiled rules.
    return files.evaluate_accesses([(Path(path), "read")]) if files is not None else None


def _network_rule(dns, network, resource):
    authority = (
        "[" + resource.strip("[]") + "]"
        if ":" in resource and is_ip_literal(resource)
        else resource
    )
    url = resource if "://" in resource else "https://" + authority + "/"
    checker = dns if ":" not in resource else network
    return checker.evaluate_url_policy("mcp_fetch_webpage", {"url": url})


class _NativeToolPolicy(TieredPolicyComponent):
    """Apply runtime receipts to ToolGuard alone, before other guards merge."""

    def configure(self, config):
        super().configure(config)
        self.runtime_config = config

    def match_approval(self, tool, command):
        from .command_identity import is_bound_native_command

        return None if is_bound_native_command(tool) else super().match_approval(tool, command)

    def _approval(self, tool, command):
        from .command_identity import is_bound_native_command

        return None if is_bound_native_command(tool) else super()._approval(tool, command)

    async def evaluate(self, tool, args, *, route=None):
        result = await super().evaluate(tool, args, route=route)
        from .command_identity import (
            bound_native_context,
            native_command_approved,
            restriction_command_views,
        )

        native = bound_native_context(tool, args) is not None
        if native:
            for command in restriction_command_views(tool, args):
                view = await super().evaluate(tool, {**args, "command": command}, route=route)
                if view is not None and view.permission in {
                    PermissionLevel.DENY,
                    PermissionLevel.ASK,
                }:
                    result = view if result is None else SDKEngine.merge_results([result, view])
        if result is None or result.permission == PermissionLevel.DENY:
            return result
        # Approval lifts ASK, including an ASK produced by a restriction view.
        # DENY has already been returned above and is not overridden.
        if native_command_approved(tool, args):
            return PermissionResult(PermissionLevel.ALLOW, "runtime:approved_command")
        if result.permission == PermissionLevel.ASK:
            from .grants import has_operation_grant

            workspace = self.runtime_config.get("runtime", {}).get("workspace_root")
            legacy = (
                super().match_approval(tool, args.get("command") or args.get("cmd") or "")
                if native
                else None
            )
            if legacy is not None or has_operation_grant(
                self.runtime_config, tool, args, workspace
            ):
                return PermissionResult(PermissionLevel.ALLOW, "runtime:operation_grant")
        if self.runtime_config.get("defer_unmatched") is True and result.matched_rule in {
            "tiered_policy:fallback(no_config)",
            "tiered_policy:defaults.*",
            "defaults.*",
        }:
            return PermissionResult(
                PermissionLevel.UNDETERMINED, result.matched_rule, result.reason
            )
        return result


class _NativeDeletionPolicy(DeletionGuardComponent):
    async def evaluate(self, tool, args, *, route=None):
        from .command_identity import native_batch_delete_approved

        result = await super().evaluate(tool, args, route=route)
        batch_ask = (
            result is not None
            and result.permission == PermissionLevel.ASK
            and result.matched_rule == "del_guard:batch_delete"
        )
        if batch_ask and native_batch_delete_approved(tool, args):
            return None
        return result


class _RuntimeEngine(SDKEngine):
    @staticmethod
    def _merge_results(results):
        merged = SDKEngine._merge_results(results)
        if merged.permission == PermissionLevel.ASK:
            # Show the batch on the same card even when a command ASK won the tie.
            for vote in results:
                if (
                    vote.permission == PermissionLevel.ASK
                    and vote.matched_rule == "del_guard:batch_delete"
                ):
                    return replace(merged, matched_rule=vote.matched_rule, reason=vote.reason)
        return merged

    @staticmethod
    def _expand(tool_name, tool_args, *, analyze=None):
        from .command_identity import bound_native_context

        if bound_native_context(tool_name, tool_args) is not None:
            # CreateProcess has already selected the executable and literal
            # argv. Peeling an interpreter here invents another shell call.
            # Retain every normal Guard on this original program candidate.
            return [
                (
                    RouteContext(
                        kind=CandidateKind.ORIGINAL,
                        command_dialect=resolve_dialect(tool_name, tool_args),
                        is_shell=True,
                    ),
                    tool_args,
                )
            ], []
        return SDKEngine._expand(tool_name, tool_args, analyze=analyze)

    def _analyze(self, tool_name, command, *, dialect, is_shell):
        from .command_identity import is_bound_native_command

        if is_bound_native_command(tool_name, command):
            return ShellStructureOutcome((), None)
        return super()._analyze(tool_name, command, dialect=dialect, is_shell=is_shell)

    @staticmethod
    def _build_components():
        replacements = {
            TieredPolicyComponent: _NativeToolPolicy,
            DeletionGuardComponent: _NativeDeletionPolicy,
        }
        return tuple(
            replacements[type(component)]() if type(component) in replacements else component
            for component in SDKEngine._build_components()
        )


class PermissionEngine:
    """Convenience adapter; hosts may instead supply their existing policy object.

    The optional DLL profile uses its packaged defaults;
    matching still uses the existing SDK components. Old SDK callers and
    existing host engines keep their own configuration semantics.
    """

    def __init__(
        self, config=None, *, workspace_root=None, trusted_dirs=None, immutable_control_roots=None
    ):
        self.workspace_root = Path(workspace_root) if workspace_root is not None else None
        self.trusted_dirs = list(trusted_dirs or [])
        self.immutable_control_roots = list(immutable_control_roots or [])
        self._active = None
        self._native_cache_lock = RLock()
        self._native_caches = WeakSet()
        self.config = {}
        self._files = None
        self._immutable = None
        self._network = None
        self._dns = None
        self._engine = None
        self._read_decision = None
        self._uniform_native_reads = False
        self._network_decision = None
        self.update_config(config or {})

    def update_config(self, config):
        candidate = object.__new__(type(self))
        candidate.workspace_root = self.workspace_root
        candidate.trusted_dirs = self.trusted_dirs
        candidate.immutable_control_roots = self.immutable_control_roots
        candidate.configure(config)
        with self._native_cache_lock:
            self._invalidate_native_caches()
            self.__dict__.update(candidate.__dict__)

    def _invalidate_native_caches(self):
        for cache in list(self._native_caches):
            cache.revoke()
        self._native_caches.clear()

    def _register_native_cache(self, cache):
        with self._native_cache_lock:
            if self._active is not None or not self.permission_checks_enabled:
                return False
            self._native_caches.add(cache)
            return True

    def configure(self, config):
        self.config = effective_runtime_config(config)
        runtime = self.config.setdefault("runtime", {})
        if self.workspace_root is not None:
            runtime["workspace_root"] = str(self.workspace_root)
        runtime["trusted_dirs"] = [str(p) for p in self.trusted_dirs]
        if self.immutable_control_roots:
            runtime["immutable_control_roots"] = [str(p) for p in self.immutable_control_roots]
        execution_policy = deepcopy(self.config)
        # Native programs have an authenticated absolute image; the legacy
        # executor's textual prefix allowlist is not an executable policy.
        # Preserve an explicit host setting, while leaving the existing SDK
        # engine's own defaults untouched for all old callers.
        execution_policy.setdefault("shell_allowlist", None)
        self._files = build_file_guard_checker(
            _permissions_for_file_guard(self.config),
            workspace_root=self.workspace_root,
            trusted_dirs=self.trusted_dirs,
        )
        self._immutable = ImmutableControlPlaneGuard(
            [Path(p) for p in runtime.get("immutable_control_roots", [])],
            workspace_root=self.workspace_root,
            permission_config=self.config,
        )
        self._network = NetGuardComponent()
        network_config = deepcopy(self.config)
        urls = network_config.get("net_guard", {}).get("urls", {})
        if isinstance(urls, dict):
            network_config.setdefault("net_guard", {})["urls"] = {
                network_pattern(key): _network_action(value) for key, value in urls.items()
            }
        self._network.configure(network_config)
        dns_config = deepcopy(self.config)
        if isinstance(urls, dict):
            dns_config.setdefault("net_guard", {})["urls"] = {
                key: _network_action(value)
                for key, value in urls.items()
                if "://" not in key and (":" not in key or is_ip_literal(key))
            }
        self._dns = NetGuardComponent()
        self._dns.configure(dns_config)
        execution_policy["net_guard"] = deepcopy(network_config.get("net_guard", {}))
        self._engine = _RuntimeEngine(execution_policy)
        # Each successful configuration owns its compiled rules and both LRUs.
        # An in-flight lookup on an old snapshot can only populate its old cache.
        self._read_decision = lru_cache(maxsize=512)(partial(_read_rule, self._files))
        self._uniform_native_reads = self._files is None or self._files.all_reads_allowed
        self._network_decision = lru_cache(maxsize=512)(
            partial(_network_rule, self._dns, self._network)
        )

    @property
    def permission_checks_enabled(self):
        return self.config.get("enabled", True) is not False and (
            self._active is None or bool(self._active())
        )

    def set_permission_checks_active(self, callback):
        with self._native_cache_lock:
            self._invalidate_native_caches()
            self._active = callback

    def check_file_accesses(self, accesses):
        if not self.permission_checks_enabled:
            return PermissionResult(PermissionLevel.ALLOW)
        results = [self._immutable.evaluate_accesses(accesses)]
        if self._files is not None:
            single_read = isinstance(accesses, (list, tuple)) and len(accesses) == 1
            path = str(accesses[0][0]) if single_read else ""
            if single_read and accesses[0][1] == "read" and len(path) <= 2048:
                decision = self._read_decision(path)
            else:
                decision = self._files.evaluate_accesses(accesses)
            results.append(decision)
        present = [r for r in results if r is not None]
        return (
            _runtime_result(SDKEngine.merge_results(present)) if present else _runtime_result(None)
        )

    def check_network_access(self, resource):
        if not self.permission_checks_enabled:
            return _runtime_result(None)
        # Cache bare DNS names and numeric endpoints. Keep URLs and credentials
        # out of the cache; proxy and URL policy still run on every request.
        if len(resource) <= 259 and not any(char in resource for char in "/?#@\\"):
            return _runtime_result(self._network_decision(resource))
        return _runtime_result(_network_rule(self._dns, self._network, resource))

    async def check_permission(self, tool, args, *, file_accesses=None):
        if not self.permission_checks_enabled:
            return _runtime_result(None)
        from contextlib import nullcontext

        from ..fileguard.native_context import bind_native_accesses
        from ..fileguard.path_extract import _interpreter_operands
        from .command_identity import bound_native_context

        observed = list(file_accesses) if file_accesses is not None else None
        bound = bound_native_context(tool, args)
        if observed is not None and bound is not None and bound[3]:
            cwd = Path(args.get("workdir") or self.workspace_root or Path.cwd())
            observed.extend(
                ((cwd / Path(path)).resolve(), "exec")
                for path in _interpreter_operands(list(bound[3]))
            )
        if self.permission_checks_enabled:
            immutable = (
                self._immutable.evaluate_accesses(observed)
                if observed is not None and bound is not None
                else self._immutable.evaluate(tool, args)
            )
            if immutable is not None and immutable.permission == PermissionLevel.DENY:
                return _runtime_result(immutable)
        with (
            bind_native_accesses(observed)
            if observed is not None and bound is not None
            else nullcontext()
        ):
            result = _runtime_result(await self._engine.check_permission(tool, args))
        if result.is_denied:
            logging.getLogger(__name__).warning(
                "Native command denied tool=%s rule=%s", tool, result.matched_rule
            )
        matched = result.matched_rule or ""
        if result.is_denied and "immutable_control_plane" in matched:
            return PermissionResult(PermissionLevel.DENY, "immutable_control_plane", result.reason)
        if file_accesses:
            result = _runtime_result(
                SDKEngine.merge_results([result, self.check_file_accesses(file_accesses)])
            )
        return result


class HostPolicyAdapter:
    """Use an existing host engine and its native-command binding unchanged.

    The optional binding function is supplied by the host; importing this SDK
    never imports a framework or its command evaluator.
    """

    def __init__(self, engine, *, native_command=None):
        self.engine = engine
        self.native_command = native_command

    def __getattr__(self, name):
        # Preserve the host engine's management API. Runtime evaluation alone
        # needs adaptation; a policy update must still reach that same engine.
        return getattr(self.engine, name)

    @property
    def config(self):
        return self.engine.config

    @property
    def trusted_dirs(self):
        return self.engine.trusted_dirs

    @property
    def permission_checks_enabled(self):
        return self.engine.permission_checks_enabled

    def check_file_accesses(self, accesses):
        return self.engine.check_file_accesses(accesses)

    def check_network_access(self, resource):
        return self.engine.check_network_access(resource)

    async def check_permission(self, tool, args, **kwargs):
        from contextlib import nullcontext

        from .command_identity import (
            bound_native_context,
            native_batch_delete_approved,
            native_command_approved,
        )

        bound = bound_native_context(tool, args)
        scope = (
            self.native_command(tool, args, bound[2], words=list(bound[3]) if bound[3] else None)
            if bound is not None and self.native_command is not None
            else nullcontext()
        )
        with scope:
            result = await self.engine.check_permission(tool, args, **kwargs)
        # The host reports independent guard votes in a compound rule. Only
        # consume an already approved, identifiable command-only ASK.
        if result.needs_approval:
            rules = (result.matched_rule or "").split("|")
            if native_command_approved(tool, args) and all(
                rule in {"default", "defaults.*", f"tools.{tool}", f"tools.{tool}.*"}
                or rule.startswith("tiered_policy:")
                or (rule == "del_guard:batch_delete" and native_batch_delete_approved(tool, args))
                for rule in rules
            ):
                return PermissionResult(PermissionLevel.ALLOW, "runtime:approved_command")
        return result
