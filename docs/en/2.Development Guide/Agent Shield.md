# Agent Shield

agent-shield (distribution name `agent-shield`, import name `agent_shield`) is an in-process security decision SDK. It does not isolate resources and does not call a model. It answers three questions:

- May this tool call proceed?
- Should this system call be intercepted?
- Does this content, entering a model or returned from a tool, carry risk?

The first two produce a deterministic allow / ask / deny; the third produces a probabilistic risk signal. An action decision can also return `undetermined`: it means that part matched no rule and must not be treated as allow. The host uses the `unmatched` setting to rewrite it to allow, ask, or deny.

---

## 1. What problem it solves

An agent tool call usually looks like this: the tool name is `shell` and the arguments contain `command`; or the tool name is `write_file` and the arguments contain a path and content. Every framework and every tool describes these arguments differently. If each tool checks its own safety, the rules scatter across the codebase and the result is hard to explain.

agent-shield normalizes these calls into events and makes one decision:

```text
tool call / system call
        │
        ▼
  normalize into events and effects
        │
        ▼
  match four rule layers (built-in / third-party / user / grant)
        │
        ▼
  aggregate by ten priority levels
        │
        ▼
  allow / ask / deny
        │
        └── ask → host opens an approval window
```

For example, `git push --force` hits the force-push rule and returns `ask`; `rm -rf ~` hits the outside-workspace forced-delete rule and also returns `ask`. A `deny` comes from critical behaviors such as writing protected files or raw disks. The result carries the winning rule and a user-visible explanation, which the host can display or audit.

## 2. Three ways to integrate

| Integration | Entry point | Fits | Output |
| --- | --- | --- | --- |
| Tool-call decision | `agent_shield.tool_permission.get_permission_manager()` | An existing tool-call chain that only needs a decision before execution | `PermissionResult` with `permission`, `matched_rule`, and `reason` |
| Behavior policy engine | `agent_shield.policy_engine.evaluate()`, `Decide`, `agent-pdp serve` | Four rule layers, task binding, approval settlement, or a standalone loopback service | An `agent-decision/v1` envelope |
| Windows native guard | `agent_shield.intercepts.native_call.wrap()` or `agent_shield.intercepts.native_call.dll_guard.RuntimeGuardManager` | File, process, and network system calls must be intercepted | Allow or deny this API call |

The three can be used alone or together. For example, use `tool_permission` for the tool call and DLL guard for the child processes it starts.

## 3. Layers

| Directory | Role |
| --- | --- |
| `policy_engine/` | Behavior policy decision point (PDP): four rule layers, ten priority levels, `Decide` settlement, the loopback HTTP service, and the `agent-pdp` CLI |
| `intercepts/tool_call/` | Turns one tool call into an `agent-event/v1` event for the PDP |
| `intercepts/native_call/` | Turns a native system-call record into an event; hosts the process guard and DLL guard integration |
| `intercepts/tool_output/` | Passes tool result text to content detection |
| `tool_permission/` | Existing action-decision components: command, path, network, host, and deletion guards, plus runtime grants |
| `detection/` | Content detection engine for prompt injection and similar soft signals |
| `native/windows-process-guard/` | C/C++ implementation of `process_guard.exe` and the x64 / x86 hook DLLs |
| `native/windows-dll-guard/` | User-mode implementation of `jiuwen_runtime_guard.dll` |

`policy_engine/` and `tool_permission/` share a package namespace but evolve separately: the former decides whether one event may proceed, the latter holds the concrete rules for tool calls and local access.

## 4. What happens during one decision

Take a tool call as an example:

1. **Normalize.** The adapter extracts commands, paths, network endpoints, and operation types from the tool name and arguments, then splits them into one or more effects. Commands are parsed, never executed.
2. **Match rules.** Built-in, third-party, user, and grant rules all take part. Built-in rules are the security floor and cannot be deleted; third-party rules register through the ruleset interface; user rules and grants come from the host.
3. **Aggregate by priority.** Each part keeps its highest-priority match, and the parts combine as deny > ask > undetermined > allow. A deny can never be overridden by an allow, and built-in or third-party asks cannot be overridden by a broad user allow. A part that matched no rule is `undetermined`; the host's `unmatched` setting rewrites it, and the default `none` leaves it undecided.
4. **Build the result.** When the result is `ask`, the engine generates suggested grants for the parts that can be remembered. The host can open an approval window and release this call or reject it.
5. **Leave a record.** The registry, an audit file, or the caller's log records the winning rule, action, and event id for later tracing.

## 5. Native guards on Windows

Windows offers two options with different integration models:

| Option | Entry point | Shape | Fits |
| --- | --- | --- | --- |
| Process guard | `agent_shield.intercepts.native_call.wrap()` | Standalone `process_guard.exe` plus hook DLLs over a JSON `native-record/v1` pipe | Existing `Decide` / `wrap` integrations that need x86 WOW64 children and recycle-bin deletion |
| DLL guard | `agent_shield.intercepts.native_call.dll_guard.RuntimeGuardManager` | Per-session manager inside the host process, injecting `jiuwen_runtime_guard.dll` and using binary framing | Async toolchains that need in-flight approvals, grant reuse, and foreground/background process trees |

A typical DLL guard lifecycle:

1. Create one `RuntimeGuardManager` per session. `session_id`, `engine`, and `dll` are required (usually `dll=locate_guard_dll()`); also pass `emit` when the policy can produce an ask.
2. Enter `async with manager.tool_execution(...)` for each tool call and start processes with `create_process()` inside the context.
3. The first launch creates a Job object, a named pipe, and injects the DLL; file, process, network, and DNS access is checked against host policy before execution.
4. When an ask is raised, `emit` delivers an approval event and the host answers through `manager.approvals.resolve(...)`. An approval can cover one execution or be persisted.
5. When the foreground process exits, children still in the Job become background tasks that the manager keeps tracking.

DLL guard is Windows x64 only. Both guards take their binaries from the `agent-security-dll` package, and `agent_security_dll.binary_directory()` returns the binary directory: DLL guard uses `jiuwen_runtime_guard.dll`, while the process guard uses `process_guard.exe` and `process_guard_hook_x64.dll` / `_x86.dll`.

## 6. Minimal example

```python
import asyncio

from agent_shield.tool_permission import get_permission_manager


async def main():
    manager = get_permission_manager()
    result = await manager.check_permission(
        tool_name="shell",
        tool_args={"command": "git push --force"},
    )
    print(result.permission)   # allow / ask / deny / undetermined
    print(result.matched_rule)
    print(result.reason)


asyncio.run(main())
```

The default configuration loads the built-in command, path, network, and deletion guards, but not the host's own user rules or grants. Without `update_config`, remembered approvals and user-defined rules do not apply; a part that matches no built-in rule may come back as `undetermined`, and the host must decide what to do with it. In production, the host should first register its policy with `manager.update_config(config, key="session-1")` and pass the same `key` on each call. Tests that need an instance isolated from the process-wide singleton use `new_permission_manager()`. `PermissionEngine` lives in `agent_shield.tool_permission.engine` and is internal; do not construct it directly.

A real tool loop usually integrates it like this:

```python
from agent_shield.tool_permission import PermissionLevel

async def run_tool_call(name, args, manager, ask_user, execute_tool):
    result = await manager.check_permission(name, args, key="session-1")

    if result.permission == PermissionLevel.DENY:
        return "blocked"
    if result.permission == PermissionLevel.ASK and not await ask_user(result):
        return "denied"
    if result.permission == PermissionLevel.UNDETERMINED:
        return "needs-host-decision"

    return await execute_tool(name, args)
```

## 7. Install and test

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter and its bash / pwsh / batch grammars are required dependencies; command structure analysis no longer falls back to a character scanner. For DLL guard, install the optional pieces:

```bash
pip install -e ".[dll-guard]"
pip install agent-security-dll
# From a source checkout you can also install locally:
# pip install ./native/windows-process-guard/python
```

## 8. Continue here

| Goal | Document |
| --- | --- |
| Rule model, priority, protocols, and tests | [agent_shield-design.md](../../../agent_shield/docs/agent_shield-design.md) |
| DLL guard build and validation | `agent_shield/native/windows-dll-guard/README.md`, `VALIDATION.md` |
| Component responsibilities and configuration | [Agent Shield component and configuration reference](../../zh/2.开发指南/Agent%20Shield组件与配置参考.html) (Chinese) |
