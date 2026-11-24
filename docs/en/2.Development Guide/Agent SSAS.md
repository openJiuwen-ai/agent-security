# Agent SSAS

Agent SSAS (package `agent-ssas`, import name `agent_ssas`) is an agent security situational awareness system. It collects agent runtime events, runs threat detection, and writes the result as OCSF logs. It is not tied to one agent framework; the current JiuwenSwarm integration is a security rail.

The component's own documentation is [agent_ssas/docs/README.md](../../../agent_ssas/docs/README.md): tutorials, how-to guides, configuration reference, and architecture notes. This page only places it inside the repository and explains the core concepts.

---

## 1. What problem it solves

An agent executing a task calls models and tools in sequence: reading files, running commands, reaching the network, changing state. Any single step may look fine, but the sequence can form a risk chain: read a sensitive file, then send it to an external endpoint; or accept a prompt injection, then run a destructive command. After the fact, a log often shows only "a call happened", not "why it was risky".

Agent SSAS collects events while the agent runs, sends them through detection modules, and produces a risk assessment and threat logs. It does not require changing the agent's business code, and it does not require one framework; the detection engine can be embedded in any Python process.

## 2. Two subsystems

| Subsystem | Package path | Role |
| --- | --- | --- |
| AgentSSASCore | `agent_ssas.core` | Detection engine: preprocessing, analysis pipeline, detection module management, storage, OCSF output |
| AgentSSASClient | `agent_ssas.backend_client` | Event collection and reporting. The openjiuwen client's main class is `AgentSSASSecurityRail` |

The detection engine can be embedded in any Python process. Only the JiuwenSwarm client depends on an agent runtime; `AgentSSASSecurityRail` subclasses agent-core's `BaseSecurityRail` and collects six lifecycle events (`invoke_start`, `llm_input`, `tool_input`, `tool_output`, `llm_output`, `invoke_end`) plus one security-derived event (`permission_interrupt_tool`).

## 3. How events flow

```text
agent runtime
    │  lifecycle events / security-derived event
    ▼
AgentSSASClient
    │  normalize, filter, report
    ▼
AgentSSASCore preprocessing
    │
    ▼
detection modules (data modeling + threat analysis)
    │  risk assessment, threat logs
    ▼
OCSF output + SQLite storage
```

A detection module declares in `module.yaml` which events it subscribes to and which plugins it uses. Modules can run asynchronously in notify mode without blocking the main flow, or synchronously in auth mode to take part in security decisions. Notify fits auditing and background detection; auth fits cases where a conclusion is needed before a tool result is returned, with a timeout fallback.

## 4. Runtime modes

| Mode | Behavior |
| --- | --- |
| `inprocess` | Default. Detection runs in the same process with no network hop |
| `http` | A standalone FastAPI service, listening on `0.0.0.0:8443` by default and shared by several agents |

The HTTP service exposes `POST /api/v1/events` and `GET /health`. Authentication is configured through `AgentSSASConfig.http_token`; when set, unauthenticated requests receive 401. When no token is set, the service runs without authentication, so do not expose it directly to the public internet.

## 5. Detection modules

Built-in modules:

- `agent_moss`: rules, behavior chains, and Agent Behavior Graph data-leakage analysis.
- `security_rail_detection`: derivative analysis of findings from other security rails, deriving confidence from the rejection scenario.
- `test_detection`: pipeline verification, off by default.

A new module is declared with `module.yaml` and does not require a framework change. Module layout, plugin naming rules, and the custom-module walkthrough are in `agent_ssas/docs/en/tutorial/05-custom-detection-module.md`.

## 6. Decision policies and failure handling

There are two decision policies:

- `observe_only`: the default. Record everything and allow every call.
- `active_protection`: block critical findings, alert on high / medium / low, and allow safe results.

A failure inside the detection engine does not stop the caller; this is fail-open. Initialization errors, malformed events, and detection timeouts do not make the main flow unavailable, which keeps security observation decoupled from business availability. Fail-open covers only failures in the detection path itself: once detection produces a critical finding, `active_protection` still blocks.

## 7. Continue here

| Goal | Document |
| --- | --- |
| Concepts | `agent_ssas/docs/en/tutorial/01-introduction.md` |
| In-process loop | `agent_ssas/docs/en/tutorial/02-quickstart.md` |
| JiuwenSwarm integration | `agent_ssas/docs/en/tutorial/03-integrate-jiuwenswarm.md` |
| Configuration fields | `agent_ssas/docs/en/reference/configuration.md` |

Examples are in `agent_ssas/examples/`. The JiuwenSwarm integration patches are in `agent_ssas/patches/`: `jiuwenswarm_ssas_local.patch` uses the local `../agent-security/agent_ssas` path, and `jiuwenswarm_ssas_online.patch` uses the `develop` branch of the `agent-security` repository.
