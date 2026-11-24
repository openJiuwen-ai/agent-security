"""Runtime resource grants use the existing permission overlay/persistence format."""

import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_shield.tool_permission.runtime.command_identity import (
    bind_native_command,
    native_command_identity,
)
from agent_shield.tool_permission.runtime.confirmation import TOOL_NAME_ALIASES
from agent_shield.tool_permission.runtime.grants import (
    GRANT_MATCH_TYPE,
    build_operation_grant,
    matches_subject,
    operation_subject,
    scope_options,
)
from agent_shield.tool_permission.runtime.models import PermissionLevel, PermissionResult

from .contracts import ApprovalGrant


def resource_source(subject):
    return "file_resource" if subject["kind"] == "file" else "dll_runtime_" + subject["kind"]


COMMAND_TOOLS = frozenset({"bash", "powershell", "pwsh", "core.powershell", "mcp_exec_command"})


def is_command_tool(tool_name):

    return TOOL_NAME_ALIASES.get(tool_name, tool_name) in COMMAND_TOOLS


def program_tool_name(subject, source_tool=None):
    """Preserve the invoking tool identity; infer it only without host context."""

    source_tool = subject.get("source_tool", source_tool)
    source_tool = TOOL_NAME_ALIASES.get(source_tool, source_tool)
    if source_tool in COMMAND_TOOLS:
        return source_tool
    stem = Path(subject["exe"]).stem.lower()
    if stem in {"powershell", "pwsh"}:
        return "powershell"
    if stem in {"bash", "sh", "dash", "zsh"}:
        return "bash"
    if stem == "cmd":
        return "mcp_exec_command"
    return "bash"


def program_tool_args(subject, source_tool=None, source_shell=None):
    """Preserve shell command text; serialize native argv for its owning shell."""
    return _program_args(subject, source_tool, source_shell, policy_text=False)


def program_policy_args(subject, source_tool=None, source_shell=None):
    """Keep native argv literal without a PowerShell operator in the Bash AST."""
    return _program_args(subject, source_tool, source_shell, policy_text=True)


def _program_args(subject, source_tool, source_shell, *, policy_text):
    tool = program_tool_name(subject, source_tool)
    argv, stem = subject["argv"], Path(subject["exe"]).stem.lower()
    shell = subject.get("source_shell") or source_shell
    if stem in {"powershell", "pwsh"}:
        shell = "powershell"
    elif stem in {"bash", "sh", "dash", "zsh"}:
        shell = "bash"
    elif stem == "cmd":
        shell = "cmd"
    shell = shell or (
        "powershell"
        if tool in {"powershell", "pwsh", "core.powershell"}
        else "cmd"
        if tool == "mcp_exec_command"
        else "bash"
    )
    command = None
    if stem in {"powershell", "pwsh", "cmd"}:
        switches = {"-command", "-c"} if stem != "cmd" else {"/c", "/k"}
        for index, arg in enumerate(argv[:-1]):
            if arg.lower() in switches:
                command = " ".join(argv[index + 1:])
                break
    elif (
        stem in {"bash", "sh", "dash", "zsh"}
        and len(argv) > 1
        and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", argv[0])
    ):
        command = argv[1]
    if command is None:
        if shell == "powershell":
            # Windows argv quoting is not PowerShell quoting. Keep every value
            # literal, including operators, variable markers and empty arguments.
            words = [subject["exe"], *argv]
            command = " ".join("'" + arg.replace("'", "''") + "'" for arg in words)
            if not policy_text:
                command = "& " + command
        else:
            command = (
                shlex.join([Path(subject["exe"]).as_posix(), *argv])
                if shell == "bash"
                else subprocess.list2cmdline([subject["exe"], *argv])
            )
    return {"command": command, "workdir": subject["cwd"], "shell_type": shell}


def approved_program_matches(approved, subject, source_tool=None, source_shell=None):
    """Reuse the SDK identity for this execution's verified literal children."""
    if subject.get("kind") != "program":
        return False
    tool = program_tool_name(subject, source_tool)
    candidate = _native_operation(subject, tool, source_shell)
    if not candidate.get("command_identity"):
        return False
    for program in approved:
        if os.path.normcase(program["exe"]) != os.path.normcase(subject["exe"]) or os.path.normcase(
            program["cwd"]
        ) != os.path.normcase(subject["cwd"]):
            continue
        operation = _native_operation(program, tool, source_shell)
        if operation.get("command_identity") and matches_subject(
            {
                "match_type": GRANT_MATCH_TYPE,
                "action": "allow",
                "pattern": json.dumps({"scope": "exact", "subject": operation}),
            },
            candidate,
        ):
            return True
    return False


def _native_operation(subject, tool, source_shell):

    args = program_policy_args(subject, tool, source_shell)
    identity = native_command_identity(
        subject["exe"], subject["argv"], subject["cwd"], args["shell_type"]
    )
    with bind_native_command(tool, args, identity, words=[subject["exe"], *subject["argv"]]):
        return operation_subject(tool, args, {})


def url_domain_subject(subject):
    """An approved URL can resolve its exact host, never authorize an IP."""
    if subject.get("kind") != "url":
        return None
    parsed = urlsplit(subject["url"])
    supported = parsed.scheme in {"http", "https"} and bool(parsed.hostname)
    if not supported or parsed.username or parsed.password:
        return None
    try:
        ipaddress.ip_address(parsed.hostname)
        return None
    except ValueError:
        return {"kind": "domain", "hostname": canonical_domain(parsed.hostname)}


def canonical_domain(name):
    """Canonical DNS identity, without inventing a URL or a socket grant."""
    if not isinstance(name, str) or not name or name != name.strip():
        raise ValueError("Invalid runtime domain")
    name = name.removesuffix(".")
    if ":" in name and "%" not in name:
        # An explicit DNS lookup may name an IPv6 address (reverse DNS).
        return str(ipaddress.IPv6Address(name))
    if any(char in name for char in "/\\:@?#[]%"):
        raise ValueError("Invalid runtime domain")
    try:
        name = name.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid runtime domain") from exc
    labels = name.split(".")
    if len(name) > 253 or any(
        not label
        or len(label) > 63
        or any(not (char.isascii() and (char.isalnum() or char in "_-")) for char in label)
        for label in labels
    ):
        raise ValueError("Invalid runtime domain")
    return name


async def evaluate_resource(
    engine,
    subject,
    *,
    command_approved=False,
    source_tool=None,
    source_shell=None,
):
    """Keep file/command/URL/transport identities distinct at the policy boundary."""

    allow = PermissionResult(PermissionLevel.ALLOW)
    kind = subject["kind"]
    if kind == "file":
        return engine.check_file_accesses(
            [
                (Path(path), "write" if action == "delete" else action)
                for path, action in subject["accesses"]
            ]
        )
    if kind == "program":
        executable = engine.check_file_accesses([(Path(subject["exe"]), "exec")])
        if executable.is_denied:
            return executable

        tool = program_tool_name(subject, source_tool)
        args = program_policy_args(subject, source_tool, source_shell)
        identity = native_command_identity(
            subject["exe"], subject["argv"], subject["cwd"], args["shell_type"]
        )
        approved = command_approved or subject.get("root_command_approved", False)
        with bind_native_command(
            tool,
            args,
            identity,
            words=[subject["exe"], *subject["argv"]],
            command_approved=approved,
            # The root tool has passed its entry policy. Only a receipt for
            # this actual command also satisfies the batch-delete prompt.
            batch_delete_approved=command_approved,
        ):
            command = await engine.check_permission(
                tool, args, file_accesses=[(Path(subject["exe"]), "exec")]
            )
        if command.is_denied or (
            command.needs_approval and "del_guard" in (command.matched_rule or "")
        ):
            return command
        if approved and command.is_undetermined:
            return executable
        if not executable.needs_approval:
            return command
        return executable
    if not engine.permission_checks_enabled:
        return allow
    if kind == "domain":
        try:
            name = canonical_domain(subject["hostname"])
        except ValueError:
            return PermissionResult(PermissionLevel.DENY, reason="Invalid runtime domain")
        return engine.check_network_access(name)
    if kind == "url":
        return engine.check_network_access(subject["url"])
    if kind == "endpoint":
        address = str(ipaddress.ip_address(subject["address"]))
        port = subject["port"]
        if (
            not isinstance(port, int)
            or not 0 < port <= 65535
            or subject["protocol"] not in {"tcp", "udp"}
        ):
            return PermissionResult(PermissionLevel.DENY)
        endpoint = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
        return engine.check_network_access(endpoint)
    return PermissionResult(PermissionLevel.DENY, reason="Unknown runtime resource")


class SessionResourceGrants:
    """Keep session authorization available when permanent storage fails."""

    def __init__(self):
        self.version = None
        self.grants = []

    def _refresh(self, version):
        if self.version != version:
            self.grants.clear()
            self.version = version

    def remember(self, grant, version):
        self._refresh(version)
        self.grants.append(deepcopy(grant))

    def matches(self, subject, version):
        self._refresh(version)
        return any(resource_grant_matches(grant, subject) for grant in self.grants)

    def clear(self):
        self.grants.clear()
        self.version = None


def resource_grant(subject: dict, answer, *, source_tool=None, source_shell=None) -> ApprovalGrant:
    """Derive scope from a host-resolved subject, never from frontend paths."""
    scope = answer.authorization_scope or "exact"
    mode = answer.authorization_mode or ("allow" if scope == "exact" else "allow_with_scope")
    if mode not in {"allow", "allow_with_scope"} or (mode == "allow" and scope != "exact"):
        raise ValueError("Invalid runtime authorization mode")
    if scope not in {item["value"] for item in scope_options(subject)}:
        raise ValueError("Invalid runtime authorization scope")
    approved = deepcopy(subject)
    if subject["kind"] == "program":
        operation = _native_operation(
            subject, program_tool_name(subject, source_tool), source_shell
        )
        if operation.get("command_identity"):
            approved["command_identity"] = operation["command_identity"]
    if scope == "parent":
        approved["accesses"] = sorted(
            {(str(Path(path).parent), action) for path, action in subject["accesses"]}
        )
    elif scope == "domain" and subject["kind"] == "url":
        grant = build_operation_grant(
            "mcp_fetch_webpage", {"url": subject["url"]}, {}, mode=mode, scope=scope
        )
        approved = json.loads(grant["pattern"])["subject"]
    elif scope != "exact":
        raise ValueError("Unsupported runtime authorization scope")
    pattern = json.dumps(
        {"scope": scope, "subject": approved},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    source = resource_source(subject)
    return {
        "id": "operation_" + hashlib.sha256((source + pattern).encode()).hexdigest()[:24],
        "tools": [source],
        "match_type": GRANT_MATCH_TYPE,
        "pattern": pattern,
        "action": "allow",
    }


def resource_grant_matches(grant: Mapping[str, Any], subject: dict, *, exact_only=False) -> bool:
    """Match scopes with one declared source, retaining file-subset matching."""
    tools = grant.get("tools")
    if not isinstance(tools, list) or len(tools) != 1 or not isinstance(tools[0], str):
        return False
    if exact_only:
        try:
            if json.loads(grant["pattern"])["scope"] != "exact":
                return False
        except (KeyError, TypeError, ValueError):
            return False
    if matches_subject(grant, subject):
        return True
    if (
        grant.get("match_type") != GRANT_MATCH_TYPE
        or grant.get("action") != "allow"
        or subject.get("kind") != "file"
    ):
        return False
    try:
        payload = json.loads(grant["pattern"])
        approved = payload["subject"]
        if payload["scope"] != "exact" or approved["kind"] != "file":
            return False
        permitted = {(os.path.normcase(path), action) for path, action in approved["accesses"]}
        return bool(subject["accesses"]) and all(
            (os.path.normcase(path), action) in permitted for path, action in subject["accesses"]
        )
    except (KeyError, TypeError, ValueError):
        return False


def remembered_resource(config: dict, subject: dict) -> bool:
    return any(
        isinstance(grant, dict) and resource_grant_matches(grant, subject)
        for grant in config.get("approval_overrides", []) or []
    )
