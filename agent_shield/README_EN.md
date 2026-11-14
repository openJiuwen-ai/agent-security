# agent-shield

English | [简体中文](./README.md)

An in-process security decision SDK (pure rules, no LLM calls, no network IO). It returns a deterministic allow / ask / deny before a tool call or a local access happens, and on Windows it ships two native guards that intercept file, process, and network access before execution.

## Layers

| Directory | Role |
|---|---|
| `policy_engine/` | Behavior policy decision point (PDP): four rule layers, ten priority levels, `Decide` settlement, the loopback HTTP service, and the `agent-pdp` CLI |
| `intercepts/tool_call/` | Tool call → `agent-event/v1` event |
| `intercepts/native_call/` | Native system call → event; hosts the process guard and DLL guard integration |
| `intercepts/tool_output/` | Tool result text → content detection |
| `tool_permission/` | Existing action-decision components: toolguard / fileguard / netguard / hostguard / delguard, plus `runtime` grant reuse |
| `detection/` | Content detection engine for prompt injection and similar soft signals |
| `native/windows-process-guard/` | C/C++ implementation of `process_guard.exe` and the x64 / x86 hook DLLs |
| `native/windows-dll-guard/` | User-mode implementation of `jiuwen_runtime_guard.dll` |

The sandbox (F2) is a separate deliverable: see `../jiuwenbox/` in this repository.

## Native guards on Windows

Both options share the binaries from the `agent-security-dll` package, but they integrate differently:

| Option | Entry point | Shape |
|---|---|---|
| Process guard | `agent_shield.intercepts.native_call.wrap()` | Standalone `process_guard.exe` plus hook DLLs over a JSON `native-record/v1` pipe; supports recycle-bin deletion and x86 WOW64 children |
| DLL guard | `agent_shield.intercepts.native_call.dll_guard.RuntimeGuardManager` | A per-session manager inside the host process, injecting `jiuwen_runtime_guard.dll` with binary framing; supports in-flight approvals, grant reuse, and foreground/background process trees |

New async toolchains should prefer `RuntimeGuardManager`. It is Windows x64 only; each tool call enters `async with manager.tool_execution(...)` and starts processes with `create_process()`. When an ask is raised, the host renders the event and calls `manager.approvals.resolve(...)` with the answer. The existing `Decide` / `wrap` protocol keeps its behavior and continues to run on the process guard.

```python
from agent_shield.intercepts.native_call.dll_guard import (
    RuntimeGuardManager,
    create_process,
    locate_guard_dll,
)
```

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
| W1b host process guard | `intercepts/native_call/` (`wrap` + `process_guard.exe`) |
| DLL guard | `intercepts/native_call/dll_guard/` + `native/windows-dll-guard/` |
| W7 host integration | Outside this repository (jiuwenswarm / agent-core side) |
| W5 sandbox wiring | Server in `../jiuwenbox/`; SDK wiring follows W6 |

`schema/` holds the JSON Schemas for decisions and native records. `native/windows-process-guard/` holds the process guard's C/C++ implementation; Microsoft Detours is a build-time external dependency (see `native/windows-process-guard/third_party/NOTICE.md`), and installing or importing the Python package does not require it. Third-party rules register through the ruleset interface. See [docs/agent_shield-design.md](docs/agent_shield-design.md) for the PDP design.

## Environment

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter and its bash / pwsh / batch grammars are required dependencies. For DLL guard, install the optional pieces:

```bash
pip install -e ".[dll-guard]"
pip install agent-security-dll
# From a source checkout you can also install locally:
# pip install ./native/windows-process-guard/python
```

## Decisions and grants

- Each decision from the behavior policy engine is an `agent-decision/v1` envelope whose `action` is `allow`, `ask`, `deny`, or `undetermined`. `undetermined` means no rule matched that part; the engine never treats it as an allow on its own.
- `unmatched` is the host-configured rewrite for unmatched parts (`none` / `allow` / `ask` / `deny`, default `none`). It only rewrites parts whose result is `undetermined`; it is not part of a DecisionRequest and cannot be changed by a ruleset update.
- `approval_overrides` belongs to `tool_permission`: it is the runtime approval matching used by `PermissionManager` and the DLL guard. The PDP's `grants` are a different mechanism: HITL approvals persisted by the host, passed in with a DecisionRequest, allow-only and limited to exact resources, and ranked at priority position 4. The formats and scopes differ, so do not mix them.

## Rules

- Import from submodule roots, for example `from agent_shield.tool_permission import get_permission_manager`. The `agent_shield` package root exports nothing. Hosts should not depend directly on `tool_permission.runtime`; use `agent_shield.tool_permission.runtime_policy` for standalone runtime helpers.
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
