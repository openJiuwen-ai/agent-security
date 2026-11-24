"""Turn one command string into literal effects.

Extraction never executes the command. A local script is read at most one
level deep, and only when it sits in the workspace and is at most 256 KiB.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from agent_shield.policy_engine.matchers.command import command_name, command_segments, privilege_requested
from agent_shield.policy_engine.matchers.paths import is_within, normalize_path
from agent_shield.policy_engine.builtin.policy import Policy

_SECRET = re.compile(r"(AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]|api_key\s*=)", re.IGNORECASE)
_URL = re.compile(r"https?://[^\s\"'`<>|]+")
_GIT_REMOTE = re.compile(r"git@([^:\s]+):")
_DATA_FLAGS = {
    "-d",
    "--data",
    "--data-raw",
    "--data-binary",
    "--data-urlencode",
    "--form",
    "--upload-file",
}
_CURL_UPLOAD = {"-T", "-F"}
_FETCH_TOOLS = {"curl", "wget", "irm", "invoke-restmethod", "invoke-webrequest"}
_DELETE_TOOLS = {"rm", "rmdir", "unlink", "del", "erase", "remove-item"}
_SCRIPT_INTERPRETERS = {"bash", "sh", "zsh", "python", "python3", "pwsh", "powershell"}
_MAX_SCRIPT_BYTES = 256 * 1024
_STATUS_RANK = {"ok": 0, "partial": 1, "failed": 2}


def normalize_command(
    command: str,
    *,
    cwd: str,
    workspace: dict,
    policy: Policy,
    depth: int = 0,
    stamp_tokens: bool = True,
) -> tuple[list[dict], dict]:
    raw = command or ""
    warnings: list[str] = []
    obfuscated = is_obfuscated(raw)
    if obfuscated:
        warnings.append("obfuscated")
    opaque = _is_opaque_encoding(raw)
    peeled = raw if opaque or depth else _peel_one_wrapper(raw)
    scan = _scan(peeled)
    if scan.unbalanced:
        warnings.append("unbalanced_quotes")
    if scan.heredoc:
        warnings.append("heredoc")
    if scan.substitution or opaque:
        warnings.append("unexpanded")
    status = "failed" if scan.unbalanced or scan.heredoc else "partial" if scan.substitution or opaque else "ok"

    effects: list[dict] = []
    produced: list[dict] = []
    current = cwd or workspace.get("root") or ""
    os_name = workspace.get("os") or "posix"
    saw_sink = False
    pending_cwd: str | None = None
    for operator, argv in scan.segments:
        if not argv:
            continue
        if operator in {"&&", "||", ";"} and pending_cwd:
            current = pending_cwd
        pending_cwd = None
        cleaned, reads, writes = _redirects(argv)
        if not cleaned:
            continue
        if _is_cd(cleaned) and operator != "|":
            pending_cwd = _cd_target(cleaned, current, os_name)
        sink = operator == "|" and command_name(cleaned[0]) in _sinks(policy)
        saw_sink = saw_sink or sink
        privileged = privilege_requested(
            {"type": "process.exec", "argv": cleaned, "raw_command": raw},
            policy.privilege_names(),
        )
        effect = _exec_effect(
            cleaned,
            cwd=current,
            raw_command=raw,
            obfuscated=obfuscated,
            interpreter_sink=sink,
            pipe_target=operator == "|",
            privilege=privileged,
            unknown=status != "ok",
        )
        effects.append(effect)
        produced.append(effect)
        effects.extend(_network_effects(cleaned, raw))
        for path in reads:
            effects.append(_fs_effect("fs.read", _absolutize(path, current, os_name), workspace))
        for path in writes:
            effects.append(_fs_effect("fs.write", _absolutize(path, current, os_name), workspace))
        for path, force in _delete_paths(cleaned, policy):
            effect = _fs_effect("fs.delete", _absolutize(path, current, os_name), workspace)
            effect["force"] = force
            effect["bulk"] = False
            effects.append(effect)
        if depth == 0:
            nested, nested_status = _read_one_script(cleaned, current, workspace, policy, os_name)
            if nested_status != "ok":
                status = _worse(status, nested_status)
                warnings.append("script_" + nested_status)
            effects.extend(nested)

    if saw_sink:
        effects.append(
            _exec_effect(
                ["__compound__"],
                cwd=cwd,
                raw_command=raw,
                obfuscated=obfuscated,
                interpreter_sink=True,
                privilege=any((item.get("shell_meta") or {}).get("privilege") for item in effects),
                unknown=status != "ok",
            )
        )
    if not effects and (scan.unbalanced or scan.heredoc):
        warnings.append("no_literals")
    if stamp_tokens and raw.strip():
        for effect, tokens in zip(produced, command_segments(raw)):
            effect["command_tokens"] = list(tokens)
    return effects, {"status": status, "warnings": warnings}


def is_obfuscated(command: str) -> bool:
    if not command:
        return False
    lowered = command.casefold()
    if _is_opaque_encoding(command):
        return True
    decode = re.search(
        r"\bbase64\b.*(?:-d|--decode)|\bxxd\b.*\s-r\b|\bopenssl\b\s+enc\b.*\s-d\b|\bcertutil\b.*-decode",
        lowered,
    )
    sink = re.search(r"\|\s*(bash|sh|zsh|pwsh|powershell|iex|cmd)\b", lowered)
    if decode and sink:
        return True
    if re.search(r"\\x[0-9a-f]{2}", lowered) and re.search(r"\b(eval|iex)\b", lowered):
        return True
    if re.search(r"\[char\]\s*\d+", lowered) and re.search(r"\b(eval|iex)\b", lowered):
        return True
    if re.search(r"[A-Za-z]''[A-Za-z]|[A-Za-z]\"\"[A-Za-z]", command):
        return True
    if "${IFS}" in command:
        return True
    for token in re.findall(r"\S+", command):
        if ":" in token or "/" in token:
            continue
        if len(re.findall(r"[A-Za-z]\\[A-Za-z]", token)) >= 2:
            return True
    return False


class _Scan:
    def __init__(self) -> None:
        self.segments: list[tuple[str | None, list[str]]] = []
        self.heredoc = False
        self.substitution = False
        self.unbalanced = False


def _scan(command: str) -> _Scan:
    scan = _Scan()
    words: list[str] = []
    buf: list[str] = []
    in_word = False
    in_single = False
    in_double = False
    operator: str | None = None
    index = 0
    length = len(command)

    def flush_word() -> None:
        nonlocal in_word, buf
        if in_word:
            words.append("".join(buf))
            buf = []
            in_word = False

    def flush_segment(next_operator: str | None) -> None:
        nonlocal words, operator
        flush_word()
        if words:
            scan.segments.append((operator, words))
            words = []
        operator = next_operator

    while index < length:
        char = command[index]
        if in_single:
            if char == "'":
                in_single = False
            else:
                buf.append(char)
            index += 1
            continue
        if in_double:
            if char == "\\" and index + 1 < length and command[index + 1] in "$`\"\\":
                buf.append(command[index + 1])
                index += 2
                continue
            if char == '"':
                in_double = False
            else:
                buf.append(char)
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            buf.append(command[index + 1])
            in_word = True
            index += 2
            continue
        if char == "'":
            in_single = True
            in_word = True
            index += 1
            continue
        if char == '"':
            in_double = True
            in_word = True
            index += 1
            continue
        if char.isspace():
            flush_word()
            index += 1
            continue
        if command.startswith("<<", index):
            scan.heredoc = True
        if char == "`":
            scan.substitution = True
        if char == "$" and index + 1 < length:
            nxt = command[index + 1]
            if nxt in "({_" or nxt.isalpha():
                scan.substitution = True
        if command.startswith("&&", index) or command.startswith("||", index) or char in "|;":
            found = "&&" if command.startswith("&&", index) else "||" if command.startswith("||", index) else char
            flush_segment(found)
            index += len(found)
            continue
        buf.append(char)
        in_word = True
        index += 1
    if in_single or in_double:
        scan.unbalanced = True
    flush_segment(None)
    return scan


def _peel_one_wrapper(command: str) -> str:
    text = command.strip()
    match = re.match(r"(?i)^cmd(?:\.exe)?\s+/c\s+(.*)$", text)
    if match:
        return _unwrap(match.group(1).strip())
    match = re.match(r"(?i)^(pwsh|powershell)(?:\.exe)?\s+(?:-command|-c)\s+(.*)$", text)
    if match and not _is_opaque_encoding(text):
        return _unwrap(match.group(2).strip())
    return command


def _unwrap(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
        return text[1:-1]
    return text


def _is_opaque_encoding(command: str) -> bool:
    lowered = command.casefold()
    if not re.search(r"\b(powershell|pwsh)\b", lowered):
        return False
    return re.search(r"(?:^|\s)-encodedcommand(?:\s|$)|(?:^|\s)-enc(?:\s|$)", lowered) is not None


def _redirects(argv: list[str]) -> tuple[list[str], list[str], list[str]]:
    cleaned: list[str] = []
    reads: list[str] = []
    writes: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if re.fullmatch(r"\d*>&\d+", token):
            index += 1
            continue
        match = re.fullmatch(r"(\d*)(>>|<|>)(.*)", token)
        if match:
            operator, rest = match.group(2), match.group(3)
            path = rest
            if not path:
                index += 1
                if index >= len(argv):
                    break
                path = argv[index]
            (writes if operator.startswith(">") else reads).append(path)
            index += 1
            continue
        cleaned.append(token)
        index += 1
    return cleaned, reads, writes


def _is_cd(argv: list[str]) -> bool:
    return bool(argv) and command_name(argv[0]) == "cd"


def _cd_target(argv: list[str], cwd: str, os_name: str) -> str:
    args = [item for item in argv[1:] if item.casefold() not in {"/d", "-p"}]
    if not args:
        return cwd
    return _absolutize(args[0], cwd, os_name)


def _delete_paths(argv: list[str], policy: Policy) -> list[tuple[str, bool]]:
    start = _delete_start(argv, policy)
    if start is None:
        return []
    force = False
    paths: list[str] = []
    take_next: str | None = None
    end_flags = False
    for arg in start[1:]:
        lowered = arg.casefold()
        if take_next:
            paths.append(arg)
            take_next = None
            continue
        if arg == "--":
            end_flags = True
            continue
        is_flag = arg.startswith("-") or arg.startswith("/")
        if not end_flags and is_flag:
            force_flag = lowered in {"-f", "--force", "-force", "/f"}
            short_force = arg.startswith("-") and not arg.startswith("--") and "f" in lowered[1:]
            if force_flag or short_force:
                force = True
            if lowered in {"-path", "-literalpath"}:
                take_next = lowered
            continue
        paths.append(arg)
    return [(path, force) for path in paths]


def _delete_start(argv: list[str], policy: Policy) -> list[str] | None:
    names = policy.privilege_names()
    for index, token in enumerate(argv):
        if command_name(token) not in _DELETE_TOOLS:
            continue
        if index == 0 or command_name(argv[0]) in names:
            return argv[index:]
    return None


def _network_effects(argv: list[str], raw: str) -> list[dict]:
    if not argv:
        return []
    tool = command_name(argv[0])
    urls = [match.rstrip(").,;\"'") for item in argv for match in _URL.findall(item)]
    if not urls:
        urls = [match.rstrip(").,;\"'") for match in _URL.findall(raw)] if tool in _FETCH_TOOLS else []
    hosts = [match for item in argv for match in _GIT_REMOTE.findall(item)]
    secret = _SECRET.search(raw) is not None or any(_SECRET.search(item) for item in argv)
    uploads = _upload_paths(argv)
    data = _has_data(argv) or bool(uploads) or secret
    effects: list[dict] = []
    for url in urls:
        host = _host_of(url)
        if tool in _FETCH_TOOLS and not data:
            effects.append(
                {
                    "type": "net.fetch",
                    "method": "GET",
                    "url": url,
                    "host": host,
                }
            )
        elif tool in _FETCH_TOOLS or data:
            effects.append(
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": url,
                    "host": host,
                    "has_body": True,
                    "secret_like": secret,
                    "local_file_attached": bool(uploads),
                    "local_files": uploads,
                }
            )
        else:
            effects.append({"type": "net.connect", "host": host, "ip": None, "port": _port_of(url)})
    for host in hosts:
        effects.append({"type": "net.connect", "host": host, "ip": None, "port": None})
    return effects


def _has_data(argv: list[str]) -> bool:
    for item in argv:
        folded = item.casefold()
        if folded in _DATA_FLAGS or folded.startswith("--data") or item in _CURL_UPLOAD:
            return True
    return False


def _upload_paths(argv: list[str]) -> list[str]:
    found: list[str] = []
    index = 0
    while index < len(argv) - 1:
        if argv[index] in _CURL_UPLOAD or argv[index].casefold() in {"--upload-file", "--form"}:
            found.append(argv[index + 1])
        index += 1
    return found


def _host_of(url: str) -> str | None:
    match = re.match(r"https?://([^/:]+)", url, re.IGNORECASE)
    return match.group(1) if match else None


def _port_of(url: str) -> int | None:
    match = re.match(r"https?://[^/:]+:(\d+)", url, re.IGNORECASE)
    return int(match.group(1)) if match else None


def _read_one_script(
    argv: list[str],
    cwd: str,
    workspace: dict,
    policy: Policy,
    os_name: str,
) -> tuple[list[dict], str]:
    if not argv or command_name(argv[0]) not in _SCRIPT_INTERPRETERS:
        return [], "ok"
    inline = _inline_source(argv)
    if inline is not None:
        if inline == "":
            return [], "partial"
        nested, normalization = normalize_command(inline, cwd=cwd, workspace=workspace, policy=policy, depth=1)
        return nested, normalization["status"]
    script = _script_argument(argv)
    if not script:
        return [], "ok"
    path = _absolutize(script, cwd, os_name)
    if not _in_workspace(path, workspace):
        return [], "partial"
    try:
        if os.path.getsize(path) > _MAX_SCRIPT_BYTES:
            return [], "partial"
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], "partial"
    nested, normalization = normalize_command(
        text,
        cwd=str(Path(path).parent),
        workspace=workspace,
        policy=policy,
        depth=1,
    )
    return nested, normalization["status"]


def _inline_source(argv: list[str]) -> str | None:
    folded = [item.casefold() for item in argv]
    for flag in ("-encodedcommand", "-enc"):
        if flag in folded:
            return ""
    for flag in ("-c", "-command"):
        if flag in folded:
            position = folded.index(flag)
            if position + 1 < len(argv):
                return argv[position + 1]
            return ""
    return None


def _script_argument(argv: list[str]) -> str | None:
    for arg in argv[1:]:
        if arg.startswith("-") or arg.startswith("/"):
            continue
        return arg
    return None


def _exec_effect(
    argv: list[str],
    *,
    cwd: str,
    raw_command: str,
    obfuscated: bool,
    interpreter_sink: bool,
    privilege: bool,
    unknown: bool,
    pipe_target: bool = False,
) -> dict:
    rendered = list(argv)
    if rendered and rendered[0] != "__compound__":
        rendered[0] = command_name(rendered[0])
    meta = {
        "obfuscated": obfuscated,
        "unknown_structure": unknown,
        "interpreter_sink": interpreter_sink,
        "privilege": privilege,
    }
    if pipe_target:
        meta["pipe_target"] = True
    return {
        "type": "process.exec",
        "argv": rendered,
        "cwd": normalize_path(cwd) if cwd else cwd,
        "raw_command": raw_command,
        "shell_meta": meta,
    }


def _fs_effect(kind: str, path: str, workspace: dict) -> dict:
    os_name = workspace.get("os") or "posix"
    root = workspace.get("root") or ""
    trusted = [item for item in workspace.get("trusted_dirs") or [] if isinstance(item, str)]
    effect = {
        "type": kind,
        "path": path,
        "path_kind": "file",
        "device_class": None,
        "in_workspace": bool(root) and is_within(path, root, os_name=os_name),
        "in_trusted_dir": any(is_within(path, item, os_name=os_name) for item in trusted),
        "exists": None,
    }
    if kind == "fs.delete":
        effect["force"] = False
        effect["bulk"] = False
    return effect


def _absolutize(path: str, cwd: str, os_name: str) -> str:
    normalized = normalize_path(path)
    if os_name == "windows" and (re.match(r"^[A-Za-z]:/", normalized) or normalized.startswith("//")):
        return normalized
    if os_name != "windows" and normalized.startswith("/"):
        return normalized
    base = normalize_path(cwd).rstrip("/") if cwd else ""
    if not base:
        return normalized
    return normalize_path(base + "/" + normalized)


def _in_workspace(path: str, workspace: dict) -> bool:
    os_name = workspace.get("os") or "posix"
    roots = [workspace.get("root") or ""]
    roots.extend(item for item in workspace.get("trusted_dirs") or [] if isinstance(item, str))
    return any(root and is_within(path, root, os_name=os_name) for root in roots)


def _sinks(policy: Policy) -> set[str]:
    return {item.casefold() for item in policy.catalog("interpreter_sinks")}


def _worse(left: str, right: str) -> str:
    return left if _STATUS_RANK[left] >= _STATUS_RANK[right] else right
