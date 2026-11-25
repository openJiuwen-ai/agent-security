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
| `foundation/agent-security-dll/native/windows/` | C/C++ implementation of `process_guard.exe` and the x64 / x86 hook DLLs |
| `foundation/agent-security-dll/native/windows/guard/` | User-mode implementation of `agent_security_guard.dll` |

`policy_engine/` and `tool_permission/` share a package namespace but evolve separately: the former decides whether one event may proceed, the latter holds the concrete rules for tool calls and local access.

## 4. What happens during one decision

Take a tool call as an example:

1. **Normalize.** The adapter extracts commands, paths, network endpoints, and operation types from the tool name and arguments, then splits them into one or more effects. Commands are parsed, never executed.
2. **Match rules.** Built-in, third-party, user, and grant rules all take part. Built-in rules are the security floor and cannot be deleted; third-party rules register through the ruleset interface; user rules and grants come from the host.
3. **Aggregate by priority.** Each part keeps its highest-priority match, and the parts combine as deny > ask > undetermined > allow. A deny can never be overridden by an allow, and built-in or third-party asks cannot be overridden by a broad user allow. A part that matched no rule is `undetermined`; the host's `unmatched` setting rewrites it, and the default `none` leaves it undecided.
4. **Build the result.** When the result is `ask`, the engine generates suggested grants for the parts that can be remembered. The host can open an approval window and release this call or reject it.
5. **Leave a record.** The registry, an audit file, or the caller's log records the winning rule, action, and event id for later tracing.

**Meta-tool (forwarder) expansion.** When a tool call itself carries another tool call (e.g. jiuwenswarm's `invoke_tool(tool_name, arguments)`), the outer envelope is opaque to the components — the outer tool name is usually absent from the `tools` config and passes via `defaults`, so the inner command rides through unexamined. Hosts register their forwarding contract via `agent_shield.tool_permission.register_meta_tool(name, extractor)` (the extractor reads the inner `(tool_name, tool_args)` from the outer arguments and returns None when the shape does not match). `check_permission` then evaluates a registered forwarder on the outer call as usual, recursively judges the inner pair (depth capped at 2), and merges the two with the strictest result winning; on ties the inner `matched_rule` / reason is kept, so approval cards and logs show the rule the real command hit. Remembered approvals (`approval_overrides`) apply to the inner pair as well, so forwarded and direct calls are judged identically. `evaluate_global_policy_directly` runs the same sequence (differing only in the `enabled` short-circuit) and expands registered forwarders likewise — its return value is decision-ready, so an envelope-only judgment there would reopen the same outer-`defaults` bypass. A process with no registered forwarders behaves exactly as before. See `agent_shield/tests/tool_permission/test_permission_meta_tools.py`.

**Cross-dialect injection rules.** The Injection component picks its rule table from the routed dialect: PowerShell routes use the PS table (`iex` / `-EncodedCommand` / the `&` call operator / `ScriptBlock::Create`), POSIX routes the bash table (backticks / `$()` / `<()`). The declared dialect, however, does not change what the command text means — a PowerShell payload handed to the `bash` tool is executed as PowerShell on Windows (the execution layer sniffs the syntax and redirects to powershell.exe), and `powershell.exe -EncodedCommand …` is a legal bash line in its own right (this is the jiuwenswarm#6957 reproduction path); the `shell_type` of generic entry tools (`mcp_exec_command`) comes from model-controlled arguments and can lie about the dialect. POSIX and UNKNOWN routes therefore add a **command-position-anchored** variant of the PS table (after line start / `;` / `|` / `&`) on top of the bash table, and CMD routes apply that anchored layer too: in a non-PowerShell command, a PS construct at command position is "about to run", while the same keyword in argument position is just a string (`grep iex .`, `git commit -m "…iex…"`) and must not be hard-denied — consistent with the existing fail-closed choice of applying POSIX rules to UNKNOWN routes. The PowerShell dialect itself keeps the looser whole-word matching: PS code places commands in pipelines, script blocks and more, where command-position anchoring would be too strict. Known boundary: payloads quoted inside a nested interpreter (`powershell -Command "iex …"`) bypass this layer and are backstopped by the structure component's interpreter sink and the built-in rules (ask level). See `agent_shield/tests/tool_permission/toolguard/test_injection_cross_dialect.py`.

## 5. Native guards on Windows

Windows offers two options with different integration models:

| Option | Entry point | Shape | Fits |
| --- | --- | --- | --- |
| Process guard | `agent_shield.intercepts.native_call.wrap()` | Standalone `process_guard.exe` plus hook DLLs over a JSON `native-record/v1` pipe | Existing `Decide` / `wrap` integrations that need x86 WOW64 children and recycle-bin deletion |
| DLL guard | `agent_shield.intercepts.native_call.dll_guard.RuntimeGuardManager` | Per-session manager inside the host process, injecting `agent_security_guard.dll` and using binary framing | Async toolchains that need in-flight approvals, grant reuse, and foreground/background process trees |

A typical DLL guard lifecycle:

1. Create one `RuntimeGuardManager` per session. `session_id`, `engine`, and `dll` are required (usually `dll=locate_guard_dll()`); also pass `emit` when the policy can produce an ask.
2. Enter `async with manager.tool_execution(...)` for each tool call and start processes with `create_process()` inside the context.
3. The first launch creates a Job object, a named pipe, and injects the DLL; file, process, network, and DNS access is checked against host policy before execution.
4. When an ask is raised, `emit` delivers an approval event and the host answers through `manager.approvals.resolve(...)`. An approval can cover one execution or be persisted.
5. When the foreground process exits, children still in the Job become background tasks that the manager keeps tracking.

DLL guard runs on a Windows x64 host and protects x64 and WOW64 root and child processes. Both guards take their binaries from the `agent-security-dll` package, and `agent_security_dll.binary_directory()` returns the binary directory: DLL guard uses `agent_security_guard.dll`, while the process guard uses `process_guard.exe` and `x64/agent_security_guard.dll` / `x86/agent_security_guard.dll`.

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
# pip install agent-security-dll==0.2.0 --find-links ../foundation/agent-security-dll/build/wheels
```

## 8. Continue here

| Goal | Document |
| --- | --- |
| Rule model, priority, protocols, and tests | [agent_shield-design.md](../../../agent_shield/docs/agent_shield-design.md) |
| DLL guard build and validation | `foundation/agent-security-dll/README.md` |
| Component responsibilities and configuration | [Agent Shield component and configuration reference](../../zh/2.开发指南/Agent%20Shield组件与配置参考.html) (Chinese) |
