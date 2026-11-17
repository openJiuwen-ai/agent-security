"""Permission evaluation and command identities for native runtime operations."""

import ipaddress
import re
import shlex
import subprocess
from pathlib import Path

from .command_identity import bind_native_command, native_command_identity
from .confirmation import TOOL_NAME_ALIASES
from .models import PermissionLevel, PermissionResult


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
    if kind in {"named_pipe", "connection"}:
        # Behavior rules cover these handle opens. Runtime file and HTTP
        # permission checks still evaluate the actual filesystem path or URL.
        return allow
    if kind == "file":
        result = engine.check_file_accesses(
            [
                (Path(path), "write" if action == "delete" else action)
                for path, action in subject["accesses"]
            ]
        )
        if subject.get("bulk") and not result.is_denied:
            return PermissionResult(PermissionLevel.ASK, "del_guard:bulk", "Task deletion threshold reached")
        return result
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
