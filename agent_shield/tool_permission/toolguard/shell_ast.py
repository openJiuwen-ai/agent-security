# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""Shell AST split for permission (tree-sitter per dialect).

Hard dependencies:
- ``tree-sitter`` + ``tree-sitter-bash`` (POSIX / unknown)
- ``tree-sitter-pwsh`` (PowerShell)
- ``tree-sitter-batch`` (CMD)

No character-level compound fallback. Split flattens through subshells/groups/
script blocks into atomic leaves plus edges (operators between adjacent chunks).
"""

from __future__ import annotations

import logging
import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Literal

from ..routing import CommandDialect
from .command_canonicalize import canonicalize_shell_command_for_permission

logger = logging.getLogger(__name__)

BackendName = Literal["bash", "powershell", "batch"]

_PARSERS: dict[BackendName, Any] = {}
# Compat with develop-era tests / callers that patch these to force bash off.
_TREE_SITTER_BASH_READY: bool | None = None
_TREE_SITTER_PARSER: Any | None = None

_PIPE_OPS = frozenset({"|", "|&"})
_LIST_OPS = frozenset({";", "&&", "||", "&", "\n"})
_STATEMENT_OPS = _PIPE_OPS | _LIST_OPS
_BASH_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "do", "done", "then", "fi", "else", "elif", "if",
    "for", "while", "until", "in", "esac", "case",
})
_PS_SKIP_TYPES = frozenset({
    "(", ")", "{", "}", "if", "elseif", "else", "switch", "foreach", "for",
    "while", "do", "until", "try", "catch", "finally", "trap", "begin",
    "process", "end", "clean", "param", "function", "filter",
})
_BATCH_SKIP_TYPES = frozenset({
    "(", ")", "@", "if", "else", "for", "do", "in",
})


@dataclass(frozen=True)
class ShellSubcommand:
    text: str
    argv: tuple[str, ...] = field(default_factory=tuple)
    redirects: tuple[str, ...] = field(default_factory=tuple)
    source_span: tuple[int, int] | None = None
    parent_operators: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class ShellAstParseResult:
    """Split result: ``kind`` + leaves + edges only.

    ``kind`` is ``ok`` (leaves usable) or ``failed`` (no trustworthy split).
    Structure features (heredoc, …) are detected by analysis functions, not here.
    """

    kind: str
    subcommands: tuple[ShellSubcommand, ...] = field(default_factory=tuple)
    edges: tuple[tuple[int, str, int], ...] = field(default_factory=tuple)
    reason: str | None = None
    backend: str = "tree-sitter-bash"


def _normalize_backend(dialect: CommandDialect | str | None) -> BackendName:
    if dialect is None:
        return "bash"
    if isinstance(dialect, CommandDialect):
        if dialect is CommandDialect.POWERSHELL:
            return "powershell"
        if dialect is CommandDialect.CMD:
            return "batch"
        return "bash"
    key = str(dialect).strip().lower()
    if key in {"powershell", "pwsh", "ps"}:
        return "powershell"
    if key in {"cmd", "batch", "dos"}:
        return "batch"
    return "bash"


def parse_shell_for_permission(
    command: str,
    *,
    dialect: CommandDialect | str | None = None,
) -> ShellAstParseResult:
    """Split a shell command into atomic leaves + edges for the given dialect.

    Does **not** peel launchers (``bash -c`` / ``pwsh -Command`` / ``cmd /c``).
    Peeling is the engine's UNWRAPPED view via
    ``canonicalize_shell_command_for_permission``; parsing the already-peeled
    text must not peel again mid-pipeline (e.g. ``curl | bash -c …``), or the
    structure layer never sees the real RHS argv.
    """
    text = (command or "").strip()
    backend = _normalize_backend(dialect)
    backend_label = f"tree-sitter-{backend}"
    if not text:
        return ShellAstParseResult(kind="ok", backend=backend_label)

    try:
        parser = _get_tree_sitter_parser(backend)
    except Exception as exc:
        logger.error("permission.shell_ast.backend_unavailable backend=%s err=%s", backend, exc)
        return ShellAstParseResult(
            kind="failed",
            reason=f"tree-sitter {backend} backend unavailable: {exc}",
            backend="none",
        )

    try:
        return _parse_with_tree_sitter(text, parser, backend=backend)
    except Exception:  # pragma: no cover
        logger.exception("permission.shell_ast.parse_failed backend=%s", backend)
        return ShellAstParseResult(
            kind="failed",
            reason=f"tree-sitter {backend} parse raised",
            backend=backend_label,
        )


def _get_tree_sitter_bash_parser() -> Any | None:
    """Return the bash parser, or None when unavailable / patched off.

    Honours module-level ``_TREE_SITTER_BASH_READY`` / ``_TREE_SITTER_PARSER`` so
    callers (and CI tests) can force the no-parser path without clearing
    ``_PARSERS``.
    """
    global _TREE_SITTER_BASH_READY, _TREE_SITTER_PARSER
    if _TREE_SITTER_BASH_READY is False:
        return None
    if _TREE_SITTER_PARSER is not None:
        return _TREE_SITTER_PARSER
    try:
        from tree_sitter import Language, Parser
        import tree_sitter_bash as lang_mod

        language = Language(lang_mod.language())
        try:
            parser = Parser(language)
        except TypeError:
            parser = Parser()
            parser.language = language
        _TREE_SITTER_PARSER = parser
        _TREE_SITTER_BASH_READY = True
        _PARSERS["bash"] = parser
        return parser
    except Exception:  # noqa: BLE001 - optional backend must allow grant fail-closed
        _TREE_SITTER_BASH_READY = False
        return None


def _get_tree_sitter_parser(backend: BackendName) -> Any:
    """Return a cached parser for ``backend``; raise if the dependency is missing."""
    if backend == "bash":
        parser = _get_tree_sitter_bash_parser()
        if parser is None:
            raise RuntimeError("tree-sitter bash backend unavailable")
        return parser

    cached = _PARSERS.get(backend)
    if cached is not None:
        return cached

    from tree_sitter import Language, Parser

    if backend == "powershell":
        import tree_sitter_pwsh as lang_mod
    else:
        import tree_sitter_batch as lang_mod

    language = Language(lang_mod.language())
    try:
        parser = Parser(language)
    except TypeError:
        parser = Parser()
        parser.language = language
    _PARSERS[backend] = parser
    return parser


def _parse_with_tree_sitter(
    command: str,
    parser: Any,
    *,
    backend: BackendName,
) -> ShellAstParseResult:
    source = command.encode("utf-8")
    tree = parser.parse(source)
    root = getattr(tree, "root_node", None)
    backend_label = f"tree-sitter-{backend}"
    if root is None:
        return ShellAstParseResult(
            kind="failed",
            reason="tree-sitter returned no root node",
            backend=backend_label,
        )

    has_error = bool(getattr(root, "has_error", False))
    leaves, edges = _extract_leaves_and_edges(root, source, backend=backend)

    # batch grammar marks ERROR liberally (even on `dir`); trust extracted leaves.
    if has_error and backend != "batch":
        return ShellAstParseResult(
            kind="failed",
            reason="tree-sitter reported parse errors",
            backend=backend_label,
        )

    if not leaves:
        return ShellAstParseResult(
            kind="failed",
            reason="tree-sitter extracted no executable command nodes",
            backend=backend_label,
        )

    pipe_ops = tuple(sorted({op for _, op, _ in edges if op in _PIPE_OPS}))
    list_ops = tuple(op for _, op, _ in edges if op not in _PIPE_OPS)
    annotated: list[ShellSubcommand] = []
    for index, leaf in enumerate(leaves):
        inbound = tuple(op for left, op, right in edges if right == index)
        annotated.append(
            ShellSubcommand(
                text=leaf.text,
                argv=leaf.argv,
                redirects=leaf.redirects,
                source_span=leaf.source_span,
                parent_operators=inbound or (pipe_ops + list_ops),
            )
        )

    return ShellAstParseResult(
        kind="ok",
        subcommands=tuple(annotated),
        edges=tuple(edges),
        backend=backend_label,
    )


def _extract_leaves_and_edges(
    node: Any,
    source: bytes,
    *,
    backend: BackendName,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    if backend == "powershell":
        return _extract_ps(node, source)
    if backend == "batch":
        return _extract_batch(node, source)
    return _extract_bash(node, source)


def _extract_bash(
    node: Any,
    source: bytes,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    node_type = str(getattr(node, "type", ""))
    if node_type == "command":
        leaf = _command_leaf(node, source, posix=True)
        return ([leaf] if leaf is not None else []), []

    if node_type == "redirected_statement":
        return _extract_redirected(node, source, backend="bash")

    if node_type == "pipeline":
        return _extract_sequence(node, source, backend="bash", default_op="|")

    if node_type in {
        "program",
        "list",
        "list_item",
        "subshell",
        "subshell_expression",
        "compound_statement",
        "brace_group",
        "do_group",
        "if_statement",
        "elif_clause",
        "else_clause",
        "for_statement",
        "while_statement",
        "until_statement",
    }:
        return _extract_sequence(node, source, backend="bash", default_op=None)

    return _extract_sequence(node, source, backend="bash", default_op=None)


def _extract_ps(
    node: Any,
    source: bytes,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    node_type = str(getattr(node, "type", ""))
    if node_type == "command":
        leaf = _command_leaf(node, source, posix=False)
        return ([leaf] if leaf is not None else []), []

    if node_type == "assignment_expression":
        leaf = _command_leaf(node, source, posix=False)
        return ([leaf] if leaf is not None else []), []

    if node_type == "pipeline_chain":
        return _extract_sequence(node, source, backend="powershell", default_op="|")

    if node_type in {
        "program",
        "statement_list",
        "statement_block",
        "pipeline",
        "if_statement",
        "elseif_clause",
        "else_clause",
        "switch_statement",
        "switch_body",
        "foreach_statement",
        "for_statement",
        "while_statement",
        "do_statement",
        "try_statement",
        "catch_clause",
        "finally_clause",
        "trap_statement",
        "function_statement",
        "named_block_list",
        "param_block",
    }:
        return _extract_sequence(node, source, backend="powershell", default_op=None)

    if node_type == "empty_statement":
        return [], []

    return _extract_sequence(node, source, backend="powershell", default_op=None)


def _extract_batch(
    node: Any,
    source: bytes,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    node_type = str(getattr(node, "type", ""))
    if node_type == "cmd":
        leaf = _command_leaf(node, source, posix=False)
        return ([leaf] if leaf is not None else []), []

    if node_type == "pipe_stmt":
        return _extract_sequence(node, source, backend="batch", default_op="|")

    if node_type in {
        "program",
        "command_sep",
        "cond_exec",
        "parenthesized",
        "if_stmt",
        "else_clause",
        "for_stmt",
    }:
        return _extract_sequence(node, source, backend="batch", default_op=None)

    # batch often wraps a bare command as ERROR(command_name).
    if node_type == "ERROR":
        for child in getattr(node, "children", []) or []:
            if child is not None and str(getattr(child, "type", "")) == "command_name":
                text = _node_text(node, source).strip()
                if text:
                    return [ShellSubcommand(
                        text=text,
                        argv=tuple(text.split()),
                        source_span=(int(node.start_byte), int(node.end_byte)),
                    )], []
        return [], []

    return _extract_sequence(node, source, backend="batch", default_op=None)


def _extract_redirected(
    node: Any,
    source: bytes,
    *,
    backend: BackendName,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    redirects = tuple(
        _node_text(child, source).strip()
        for child in getattr(node, "children", []) or []
        if child is not None and "redirect" in str(getattr(child, "type", ""))
    )
    body_leaves: list[ShellSubcommand] = []
    body_edges: list[tuple[int, str, int]] = []
    for child in getattr(node, "children", []) or []:
        if child is None:
            continue
        child_type = str(getattr(child, "type", ""))
        if "redirect" in child_type or child_type in _BASH_SKIP_TYPES:
            continue
        if child_type in _STATEMENT_OPS:
            continue
        leaves, edges = _extract_leaves_and_edges(child, source, backend=backend)
        if leaves:
            body_leaves, body_edges = leaves, edges
            break
    if not body_leaves:
        return [], []
    if not redirects:
        return body_leaves, body_edges
    last = body_leaves[-1]
    body_leaves[-1] = ShellSubcommand(
        text=last.text,
        argv=last.argv,
        redirects=last.redirects + redirects,
        source_span=last.source_span,
        parent_operators=last.parent_operators,
    )
    return body_leaves, body_edges


def _skip_types(backend: BackendName) -> frozenset[str]:
    if backend == "powershell":
        return _PS_SKIP_TYPES
    if backend == "batch":
        return _BATCH_SKIP_TYPES
    return _BASH_SKIP_TYPES


def _extract_sequence(
    node: Any,
    source: bytes,
    *,
    backend: BackendName,
    default_op: str | None,
) -> tuple[list[ShellSubcommand], list[tuple[int, str, int]]]:
    leaves: list[ShellSubcommand] = []
    edges: list[tuple[int, str, int]] = []
    pending_op: str | None = None
    prev_last: int | None = None
    skip = _skip_types(backend)

    for child in getattr(node, "children", []) or []:
        if child is None:
            continue
        child_type = str(getattr(child, "type", ""))
        if child_type in skip:
            continue
        if child_type == "empty_statement":
            pending_op = ";"
            continue
        if child_type in _STATEMENT_OPS or child_type in {"newline", "\n"}:
            pending_op = child_type if child_type in _STATEMENT_OPS else ";"
            continue

        child_leaves, child_edges = _extract_leaves_and_edges(child, source, backend=backend)
        if not child_leaves:
            continue

        base = len(leaves)
        for left, op, right in child_edges:
            edges.append((base + left, op, base + right))

        connect_op = pending_op if pending_op is not None else default_op
        if prev_last is not None and connect_op is not None:
            edges.append((prev_last, connect_op, base))

        leaves.extend(child_leaves)
        prev_last = base + len(child_leaves) - 1
        pending_op = None

    return leaves, edges


def _command_leaf(node: Any, source: bytes, *, posix: bool) -> ShellSubcommand | None:
    text = _node_text(node, source).strip()
    if not text:
        return None
    try:
        argv = tuple(shlex.split(text, posix=posix and os.name != "nt"))
    except ValueError:
        # PowerShell / CMD: fall back to whitespace split for argv0 sink checks.
        argv = tuple(text.split())
    redirects = tuple(
        _node_text(child, source).strip()
        for child in getattr(node, "children", []) or []
        if child is not None and "redirect" in str(getattr(child, "type", ""))
    )
    # Prefer grammar command_name as argv0 when shlex mangled it.
    for child in getattr(node, "children", []) or []:
        if child is None:
            continue
        if str(getattr(child, "type", "")) == "command_name":
            name = _node_text(child, source).strip()
            if name:
                rest = argv[1:] if argv else ()
                if not argv or _basename_token(argv[0]) != _basename_token(name):
                    argv = (name, *rest) if rest or not argv else (name,)
            break
    return ShellSubcommand(
        text=text,
        argv=argv,
        redirects=redirects,
        source_span=(int(node.start_byte), int(node.end_byte)),
    )


def _basename_token(token: str) -> str:
    base = token.strip("\"'").replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def _node_text(node: Any, source: bytes) -> str:
    start = int(getattr(node, "start_byte", 0))
    end = int(getattr(node, "end_byte", 0))
    return source[start:end].decode("utf-8", errors="replace")


def split_shell_for_grants(command: str) -> tuple[str, ...]:
    """Return literal reusable children only when the AST covers the whole input.

    Used by runtime grants / DLL-guard reuse: only emit children when every
    leaf is a contiguous literal span joined by ``&&`` / ``||`` / ``;`` / ``|``.
    Launcher unwrap is refused so interpreter semantics are not lost.
    """
    text = (command or "").strip()
    # Unwrapping a launcher would lose its interpreter and execution semantics.
    if not text or canonicalize_shell_command_for_permission(text) != text:
        return ()
    parsed = parse_shell_for_permission(text)
    if (
        not str(parsed.backend).startswith("tree-sitter")
        or parsed.kind != "ok"
        or not parsed.subcommands
    ):
        return ()
    source, cursor = text.encode("utf-8"), 0
    commands: list[str] = []
    for subcommand in parsed.subcommands:
        if not subcommand.text or subcommand.source_span is None:
            return ()
        start, end = subcommand.source_span
        if start < cursor or end <= start or end > len(source):
            return ()
        try:
            gap = source[cursor:start].decode("utf-8")
            literal = source[start:end].decode("utf-8")
        except UnicodeDecodeError:
            return ()
        if not re.fullmatch(r"\s*(?:(?:&&|\|\||;|\|)\s*)*", gap) or literal != subcommand.text:
            return ()
        commands.append(subcommand.text)
        cursor = end
    if source[cursor:].strip():
        return ()
    return tuple(dict.fromkeys(commands))


def parse_literal_bash_root(source: bytes) -> Any | None:
    """Return a bash AST root for the exact input, or None when it cannot grant."""
    parser = _get_tree_sitter_bash_parser()
    if parser is None:
        return None
    try:
        root = parser.parse(source).root_node
    except (OSError, RuntimeError, TypeError, ValueError):
        return None
    if root is None or bool(getattr(root, "has_error", False)):
        return None
    return root


__all__ = [
    "ShellAstParseResult",
    "ShellSubcommand",
    "parse_shell_for_permission",
    "parse_literal_bash_root",
    "split_shell_for_grants",
    "_get_tree_sitter_bash_parser",
    "_get_tree_sitter_parser",
    "_parse_with_tree_sitter",
]
