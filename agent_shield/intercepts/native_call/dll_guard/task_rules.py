"""Evaluate the host's task-scoped behavior rules on observed runtime operations."""

import hashlib
import json
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import PureWindowsPath
from urllib.parse import urlsplit

from agent_shield.policy_engine.builtin.rules import load_builtin_ruleset
from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.policy_engine.core.grants import accept_grant
from agent_shield.policy_engine.core.ruleset import load_grants, load_ruleset, load_user_rules
from agent_shield.tool_permission.runtime.models import PermissionLevel, PermissionResult
from agent_shield.tool_permission.runtime.grants import build_operation_grant, scope_options

from .events import operation_to_event
from .errors import GuardError


@dataclass
class TaskRuleResult(PermissionResult):
    grants: list = field(default_factory=list)
    runtime_ask: PermissionResult | None = None

    def selected_grants(self, subject, scope):
        if scope in (None, "exact"):
            return self.grants
        if not self.grants or scope not in {option["value"] for option in scope_options(subject)}:
            raise ValueError("Scope unavailable for this task approval")
        scoped = {}
        for original in self.grants:
            grant = {**original, "scope": scope}
            if scope == "parent" and grant["object"] == "file":
                grant["path"] = PureWindowsPath(grant["path"]).parent.as_posix()
            elif scope == "domain" and grant["object"] == "domain":
                resource = build_operation_grant("mcp_fetch_webpage", {"url": subject["url"]}, {},
                                                 mode="allow_with_scope", scope=scope)
                url = json.loads(resource["pattern"])["subject"]
                grant.update(hosts=[url["domain"]], url_scheme=url["scheme"], url_port=url["port"])
            else:
                raise ValueError("Scope does not cover the task rule")
            grant["id"] = _grant_id(grant)
            scoped[grant["id"]] = grant
        return list(scoped.values())


def _grant_id(grant):
    identity = {k: v for k, v in grant.items() if k not in {"id", "provenance"}}
    return "operation_" + hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


class TaskRules:
    def __init__(self, snapshot, session_id):
        # Keep the declarative inputs for comparing two published policy revisions.
        self.policy_document = {key: snapshot[key] for key in ("ruleset", "tasks", "unmatched") if key in snapshot}
        base = load_builtin_ruleset()
        self.ruleset = load_ruleset(
            snapshot["ruleset"],
            baseline=base.behaviors,
            catalogs=base.catalogs,
            unmatched=snapshot.get("unmatched", "none"),
        )
        self.workspace = {
            "root": str(snapshot.get("workspace_root") or ""),
            "trusted_dirs": [str(path) for path in snapshot.get("trusted_dirs", [])],
            "os": "windows",
        }
        self.session_id = session_id
        self.tasks = {}
        for task_id, task in snapshot["tasks"].items():
            if (
                not isinstance(task, Mapping)
                or not isinstance(task.get("subject_id"), str)
                or not task["subject_id"]
            ):
                raise ValueError("Missing task subject")
            if not isinstance(task.get("host_capabilities", {}), Mapping) or not isinstance(
                task.get("source", {}), Mapping
            ):
                raise TypeError("Invalid task context")
            if not isinstance(task.get("grants", []), list) or not isinstance(
                task.get("user_rules", []), list
            ):
                raise TypeError("Invalid rules or grants")
            subject = task["subject_id"]
            rules = load_user_rules(
                {"spec": "agent-user-rules/v1", "rules": task.get("user_rules", [])}
            )
            grants = load_grants(
                [g for g in task.get("grants", []) if accept_grant(g, subject_id=subject)]
            )
            self.tasks[task_id] = (task, rules, grants)
        self.session_grants = {}

    def require_task(self, task_id):
        if task_id not in self.tasks:
            raise GuardError("unknown_task")

    def check(self, subject, task_id, tool_call_id, tool_name, execution_grants=()):
        if subject.get("operation", {}).get("kind") == "hardlink_source_open":
            # This private metadata handle belongs to CreateHardLink. The
            # subsequent link operation carries both roles for the task vote.
            self.require_task(task_id)
            return TaskRuleResult(PermissionLevel.ALLOW)
        return self.check_operation(
            _operation(subject), task_id, {"name": tool_name, "tool_call_id": tool_call_id},
            cwd=subject.get("cwd"), execution_grants=execution_grants,
        )

    def check_operation(self, operation, task_id, cause, *, cwd=None, execution_grants=()):
        self.require_task(task_id)
        task, rules, grants = self.tasks[task_id]
        caps = {"hitl": True, "auto_intent": False, **task.get("host_capabilities", {})}
        context = {
            "source": {**task.get("source", {}), "session_id": self.session_id},
            "workspace": self.workspace,
            "user_intent": task.get("user_intent"),
            "host_capabilities": caps,
            "cwd": cwd,
        }
        event = operation_to_event(
            operation,
            context,
            cause=cause,
            runtime=True,
        )
        active_grants = [*grants, *self.session_grants.get(task["subject_id"], {}).values(), *execution_grants]
        result = evaluate_event(
            event,
            ruleset=self.ruleset,
            user_rules=rules,
            grants=active_grants,
            subject_id=task["subject_id"],
        )
        level = PermissionLevel(result["action"])
        if level in (PermissionLevel.UNDETERMINED, PermissionLevel.ASK):
            level = PermissionLevel.ASK if caps.get("hitl") is True else PermissionLevel.DENY
        candidates = {}
        for grant in result["grants"]:
            identifier = _grant_id(grant)
            candidates[identifier] = {**grant, "id": identifier}
        proposed = list(candidates.values())
        # A compound operation can include both grantable and one-time ASKs.
        # Only advertise remembering if the proposed grants settle all parts.
        if (
            proposed
            and evaluate_event(
                event,
                ruleset=self.ruleset,
                user_rules=rules,
                grants=[*active_grants, *load_grants(proposed)],
                subject_id=task["subject_id"],
            )["action"]
            != "allow"
        ):
            proposed = []
        return TaskRuleResult(
            level,
            result["winner_rule_id"],
            result["advice"]["user_visible"]["summary"],
            grants=proposed,
        )

    def remember(self, task_id, grants):
        task = self.tasks[task_id][0]
        compiled = self.session_grants.setdefault(task["subject_id"], {})
        for rule in load_grants(grants):
            compiled[rule.id] = rule


def _operation(subject):
    kind = subject["kind"]
    if kind == "file":
        if "operation" in subject:
            if subject["operation"]["kind"] == "hardlink":
                # Task rules judge a link by role (source read, target write).
                # The runtime file policy separately checks both paths for write.
                return subject["operation"]
            return {**subject["operation"], "accesses": subject["accesses"], "bulk": bool(subject.get("bulk"))}
        return {**subject, "kind": "file_accesses"}
    if kind == "program":
        line = subject.get("command_line") or subprocess.list2cmdline([subject["exe"], *subject["argv"]])
        return {
            "kind": "create_process",
            "resources": [{"image": subject["exe"], "command_line": line,
                           "argv": [subject["exe"], *subject["argv"]]}],
        }
    if kind in {"domain", "connection"}:
        return {
            "kind": "connect",
            "resources": [{"host": subject["hostname"], "port": subject.get("port")}],
        }
    if kind == "endpoint":
        return {
            "kind": "connect",
            "resources": [{"ip": subject["address"], "port": subject["port"]}],
        }
    if kind == "url":
        # The runtime URL check covers the full URL. The observed peer is
        # sufficient for the behavior engine's existing net.connect rules.
        url = urlsplit(subject["url"])
        port = url.port or {"http": 80, "https": 443}.get(url.scheme)
        return {"kind": "connect", "url": subject["url"], "resources": [{"host": url.hostname, "port": port}]}
    if kind == "named_pipe":
        return {
            "kind": "pipe_open",
            "access": subject["access"],
            "resources": [{"path": subject["path"]}],
        }
    raise ValueError("Unknown runtime operation")
