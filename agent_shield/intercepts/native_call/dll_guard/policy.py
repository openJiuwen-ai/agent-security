"""Runtime resource grants use the existing permission overlay/persistence format."""

import hashlib
import ipaddress
import json
import os
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from agent_shield.tool_permission.runtime.command_identity import (
    bind_native_command,
    native_command_identity,
)
from agent_shield.tool_permission.runtime.operations import (
    canonical_domain, evaluate_resource, is_command_tool, program_policy_args, program_tool_args,
    program_tool_name,
)
from agent_shield.tool_permission.runtime.grants import (
    GRANT_MATCH_TYPE,
    build_operation_grant,
    matches_subject,
    operation_subject,
    scope_options,
)

from .contracts import ApprovalGrant


def resource_source(subject):
    return "file_resource" if subject["kind"] == "file" else "dll_runtime_" + subject["kind"]


def approved_program_matches(approved, subject, source_tool=None, source_shell=None):
    """Reuse the SDK identity for this execution's verified literal children."""
    if not approved or subject.get("kind") != "program":
        return False
    # Startup metadata is not part of the approved executable/argv/cwd identity.
    identity = {k: v for k, v in subject.items() if k not in {"root_command_approved", "command_line"}}
    if identity in approved:
        return True
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


class SessionResourceGrants:
    """Keep confirmed session authorizations until the policy revision changes."""

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
