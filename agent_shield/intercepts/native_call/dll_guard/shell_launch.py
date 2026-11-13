"""Predict literal shell launches, including Git for Windows and MSYS forwarding."""

import os
import re
import shlex
import shutil
from pathlib import Path

from agent_shield.tool_permission.runtime.command_identity import (
    literal_command_identity,
    literal_shell_words,
)
from agent_shield.tool_permission.runtime.shell import ShellType, resolve_execution_plan
from agent_shield.tool_permission.toolguard.shell_ast import parse_literal_bash_root


def approved_programs(operation):
    """Resolve literal approved commands with the SDK's actual launcher plan.

    An unresolved interpreter, dynamic syntax or unknown shell state cannot
    grant arbitrary descendants. Full executable paths, argv and cwd are bound
    before any user code runs; a basename match is never sufficient.
    """

    if operation.get("kind") != "command" or "arguments" in operation:
        return []
    try:
        # Reuse execution semantics rather than reimplementing shell selection.
        plan, use_shell, shell = resolve_execution_plan(
            operation["command"], ShellType(operation["shell_type"])
        )
    except (KeyError, ValueError, RuntimeError):
        return []
    if use_shell or not isinstance(plan, list):
        return []
    cwd = str(Path(operation["cwd"]).resolve())
    executable = shutil.which(plan[0])
    if not executable:
        return []
    interpreters = [Path(executable).resolve()]
    # Git's bin/bash.exe launcher starts usr/bin/bash.exe with the same args.
    if shell in {"bash", "sh"} and interpreters[0].parent.name.lower() == "bin":
        sibling = interpreters[0].parent.parent / "usr/bin" / interpreters[0].name
        if sibling.is_file():
            interpreters.append(sibling.resolve())
    programs = [
        {"kind": "program", "exe": str(path), "argv": plan[1:], "cwd": cwd} for path in interpreters
    ]
    if shell == "powershell":
        words = literal_shell_words(plan[-1], shell)
        identity = literal_command_identity(operation["command"], cwd, shell)
        # A cmdlet is executed inside PowerShell, not as a separate EXE.
        if words and identity and not identity["name"]:
            programs.append(
                {"kind": "program", "exe": identity["exe"], "argv": words[1:], "cwd": cwd}
            )
        return _with_configured_launcher_targets(programs)
    if shell not in {"bash", "sh"}:
        return programs  # No Bash parser applied to PowerShell/CMD syntax.
    search = os.pathsep.join(
        [*(str(path.parent) for path in reversed(interpreters)), os.environ.get("PATH", "")]
    )
    interpreter_dirs = {path.parent for path in interpreters}
    pending = [
        (argv, directory, interpreters, plan[1:], 0)
        for argv, directory in _literal_programs(plan[-1], cwd)
    ]
    for argv, command_cwd, launchers, shell_args, depth in pending:
        command_cwd = str(Path(command_cwd).resolve())
        # MSYS implements fork by starting bash with its original argv, even
        # after cd. Bind those continuations to the script's reachable CWDs too.
        for interpreter in launchers:
            continuation = {
                "kind": "program",
                "exe": str(interpreter),
                "argv": shell_args,
                "cwd": command_cwd,
            }
            if continuation not in programs:
                programs.append(continuation)
        token = argv[0]
        if "/" in token or "\\" in token:
            candidate = Path(token)
            candidate = candidate if candidate.is_absolute() else Path(command_cwd) / candidate
            resolved = str(candidate.resolve()) if candidate.is_file() else None
        else:
            resolved = shutil.which(token, path=search)
        if resolved:
            path = Path(resolved).resolve()
            programs.append(
                {"kind": "program", "exe": str(path), "argv": argv[1:], "cwd": command_cwd}
            )
            # A literal inline script uses the same rules in its own CWD scope.
            # Only the selected Bash installation is recognized as an interpreter.
            interpreter = path.parent in interpreter_dirs and path.stem.lower() in {"bash", "sh"}
            inline = len(argv) >= 3 and re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", argv[1])
            if interpreter and inline and depth < 4:
                pending.extend(
                    (child, directory, [path], argv[1:], depth + 1)
                    for child, directory in _literal_programs(argv[2], command_cwd)
                )
    return _with_configured_launcher_targets(programs)


def _with_configured_launcher_targets(programs):
    """Expand only the host-selected Git installation's known forwarding layout.

    Like the existing bin/bash -> usr/bin/bash handoff, this is an explicit
    installation relationship, never permission for arbitrary same-name EXEs.
    Keep the exact argv/cwd and leave every target's DENY/exec checks active.
    """
    configured = (
        (os.environ.get("CLAW_GIT_EXE") or os.environ.get("AGENT_SHIELD_GIT_EXE", ""))
        .strip()
        .strip('"')
    )
    if os.name != "nt" or not configured:
        return programs
    launcher = Path(configured).resolve()
    if launcher.name.lower() != "git.exe" or launcher.parent.name.lower() not in {"cmd", "bin"}:
        return programs
    root = launcher.parent.parent
    for program in list(programs):
        if os.path.normcase(program["exe"]) != os.path.normcase(str(launcher)):
            continue
        for directory in ("mingw64", "ucrt64", "mingw32"):
            target = (root / directory / "bin/git.exe").resolve()
            if target.is_file() and target.is_relative_to(root):
                forwarded = {**program, "exe": str(target)}
                if forwarded not in programs:
                    programs.append(forwarded)
    return programs


def _literal_programs(command, cwd):
    """Bind literal Bash commands to the directories reachable in this script.

    Track cd success/failure across &&, || and sequences. Subshells, pipelines
    and background lists keep their directory changes local. Dynamic shell state
    is left to runtime approval; no shell is executed to predict its effects.
    """
    source = command.encode("utf-8")
    root = parse_literal_bash_root(source)
    if root is None:
        return []
    allowed = {
        "program",
        "list",
        "pipeline",
        "command",
        "command_name",
        "word",
        "string",
        "raw_string",
        "string_content",
        "concatenation",
        "redirected_statement",
        "file_redirect",
        "file_descriptor",
        "number",
        "subshell",
        "compound_statement",
        "comment",
    }
    stack, commands = [root], {}
    while stack:
        node = stack.pop()
        if node.is_named and node.type not in allowed:
            return []
        text = source[node.start_byte:node.end_byte].decode("utf-8")
        if node.type == "word" and re.search(r"[$*?~{}]", text):
            return []
        if node.type == "command":
            try:
                argv = shlex.split(text, posix=True)
            except ValueError:
                return []
            if not argv or argv[0].lower() in {
                "pushd",
                "popd",
                "export",
                "set",
                "unset",
                "alias",
                "unalias",
                "source",
                ".",
                "eval",
                "exec",
                "env",
                "command",
                "builtin",
                "hash",
            }:
                return []
            commands[node.id] = argv
        stack.extend(reversed(node.children))

    programs = []

    def visit(node, directories):
        if not directories:
            return set(), set()
        if node.type == "command":
            argv = commands[node.id]
            if argv[0] == "cd":
                args, physical = argv[1:], False
                while args and args[0] in {"-L", "-P", "--"}:
                    flag, args = args[0], args[1:]
                    if flag == "--":
                        break
                    physical = flag == "-P"
                if len(args) != 1 or args[0] == "-" or not args[0]:
                    raise ValueError("cd requires a literal directory")
                target = args[0]
                if os.name == "nt" and target.startswith("/"):
                    # Git Bash drive paths; other MSYS mounts need runtime resolution.
                    if not re.match(r"^/[a-zA-Z](?:/|$)", target):
                        raise ValueError("Unknown shell mount")
                    target = target[1] + ":/" + target[3:]
                destinations = {
                    os.path.abspath(os.path.join(directory, target)) for directory in directories
                }
                if physical:
                    destinations = {str(Path(directory).resolve()) for directory in destinations}
                return destinations, directories  # Failed cd leaves CWD unchanged.
            for directory in sorted(directories):
                programs.append((argv, directory))
            return directories, directories
        if node.type == "redirected_statement":
            body = node.child_by_field_name("body")
            if body is None:  # A redirection alone, e.g. >file, keeps CWD.
                return directories, directories
            success, failure = visit(body, directories)
            return success, failure | directories  # Redirection can fail before cd.
        if node.type == "list":
            left, right = [child for child in node.named_children if child.type != "comment"]
            success, failure = visit(left, directories)
            operator = next(child.type for child in node.children if not child.is_named)
            if operator == "&&":
                after_success, after_failure = visit(right, success)
                return after_success, failure | after_failure
            after_success, after_failure = visit(right, failure)
            return success | after_success, after_failure
        if node.type == "pipeline":
            for child in node.named_children:
                visit(child, directories)
            return directories, directories
        success, failure = directories, set()
        for index, child in enumerate(node.children):
            if not child.is_named or child.type == "comment":
                continue
            before = success | failure
            success, failure = visit(child, before)
            if index + 1 < len(node.children) and node.children[index + 1].type == "&":
                success, failure = before, set()
        if node.type == "subshell":
            return directories if success else set(), directories if failure else set()
        return success, failure

    try:
        visit(root, {cwd})
    except ValueError:
        return []
    return programs
