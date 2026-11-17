# agent-shield

English | [简体中文](./README.md)

An in-process security decision SDK (pure rules, no LLM calls, no network IO). It returns a deterministic allow / ask / deny before a tool call or a local access happens, and on Windows it uses a shared native DLL to intercept file, process, and network access before execution.

## Layers

| Directory | Role |
|---|---|
| `policy_engine/` | Behavior policy decision point (PDP): four rule layers, ten priority levels, `Decide` settlement, the loopback HTTP service, and the `agent-pdp` CLI |
| `intercepts/tool_call/` | Tool call → `agent-event/v1` event |
| `intercepts/native_call/` | Native system call → event; hosts the process guard and DLL guard integration |
| `intercepts/tool_output/` | Tool result text → content detection |
| `tool_permission/` | Existing action-decision components: toolguard / fileguard / netguard / hostguard / delguard, plus `runtime` grant reuse |
| `detection/` | Content detection engine for prompt injection and similar soft signals |
| `../foundation/agent-security-dll/` | Shared Windows hook and file recovery implementation for Agent Shield and JiuwenBox |

The sandbox (F2) is a separate deliverable: see `../jiuwenbox/` in this repository.

## Native guards on Windows

Import `ProcessGuard` from `agent_shield`. The host supplies `policy_snapshot`, `confirm`, `save_grant`, and `audit`. Start a protected process tree with `await guard.spawn(argv, task_id=..., tool_call_id=..., tool_name=...)` and await `proc.wait()` for the root exit code. The default `recover` mode uses the same native file recovery implementation as JiuwenBox.

Protected launch on a Windows x64 host supports x64 and x86 targets. See the [DLL build and architecture tests](../foundation/agent-security-dll/README.md).

## Directory ↔ work item

| Work item | Directory |
|---|---|
| W1a command decision engine | `tool_permission/toolguard/` |
| W2 path guard | `tool_permission/fileguard/` |
| W3 outbound guard | `tool_permission/netguard/` |
| W4 content detection | `detection/` |
| W6 entry point / facade | `tool_permission/__init__.py` and `tool_permission/manager.py` |
| W8 tests | matching subdirectories under `tests/` |
| Behavior policy engine | `policy_engine/` |
| Tool-call integration | `intercepts/tool_call/` |
| Tool-result integration | `intercepts/tool_output/` |
| W1b host process guard | `intercepts/native_call/dll_guard/process_guard.py` (`ProcessGuard.spawn()`) |
| W7 host integration | Outside this repository (jiuwenswarm / agent-core side) |
| W5 sandbox wiring | Server in `../jiuwenbox/`; SDK wiring follows W6 |

`schema/` holds the JSON Schemas for decisions, events, and audit records. `../foundation/agent-security-dll/` holds the process guard's C/C++ implementation; Microsoft Detours is a build-time external dependency (see `../foundation/agent-security-dll/third_party/NOTICE.md`), and installing or importing the Python package does not require it. Third-party rules register through the ruleset interface. See [docs/agent_shield-design.md](docs/agent_shield-design.md) for the PDP design.

## Environment

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter and its bash / pwsh / batch grammars are required dependencies. On Windows, first build and install the wheel from the [DLL source package](../foundation/agent-security-dll/README.md), then install the SDK extra:

```bash
pip install -e ".[dll-guard]"
```

## Decisions and grants

- Each decision from the behavior policy engine is an `agent-decision/v1` envelope whose `action` is `allow`, `ask`, `deny`, or `undetermined`. `undetermined` means no rule matched that part; the engine never treats it as an allow on its own.
- `unmatched` is the host-configured rewrite for unmatched parts (`none` / `allow` / `ask` / `deny`, default `none`). It only rewrites parts whose result is `undetermined`; it is not part of a DecisionRequest and cannot be changed by a ruleset update.
- `approval_overrides` belongs to `tool_permission`: it is the runtime approval matching used by `PermissionManager` and the DLL guard. The PDP's `grants` are a different mechanism: HITL approvals persisted by the host, passed in with a DecisionRequest, allow-only and limited to exact resources, and ranked at priority position 4. The formats and scopes differ, so do not mix them.

## Rules

- Import from submodule roots, for example `from agent_shield.tool_permission import get_permission_manager`. The `agent_shield` package root lazily exports `ProcessGuard`. Hosts should not depend directly on `tool_permission.runtime`; use `agent_shield.tool_permission.runtime_policy` for standalone runtime helpers.
- Permission checks: production code must use `get_permission_manager()` for the process-wide singleton. Tests or isolated instances use `new_permission_manager()`; constructing `PermissionManager()` directly raises `RuntimeError`.
- `PermissionEngine` lives in `agent_shield.tool_permission.engine` and is internal; the facade does not export it.
- `approval_overrides` take precedence over command rules and tool baselines:
  - When the original or unwrapped full command matches, the whole call is ALLOW and no other guard runs.
  - When only a subcommand matches, only that candidate is ALLOW; the other candidates and the whole-string check still take the strictest result.
  - Runtime grants additionally support `exact_operation`, parent directory, domain, and subcommand scopes.
- Use relative imports inside a submodule; across submodules, import only the other side's root. External projects such as `jiuwenbox` also import only to a submodule root (enforced by `tests/test_import_rules.py`).
- Each work-item directory owns its internal layout; do not cross-reference directories before the work items are consolidated.

## Documentation

Chinese starts at [../docs/zh/SUMMARY.md](../docs/zh/SUMMARY.md); English starts at [../docs/en/SUMMARY.md](../docs/en/SUMMARY.md). The PDP and native protocol design is in [docs/agent_shield-design.md](docs/agent_shield-design.md).
