# JiuwenBox

JiuwenBox (package `jiuwenbox`) is a sandbox service. A FastAPI process manages sandbox creation, stop, file transfer, and command execution, and runs the commands an agent asks for inside a policy-constrained environment.

Install, startup flags, policy fields, and the full HTTP API are specified in [jiuwenbox/README.md](../../../jiuwenbox/README.md) and [jiuwenbox_server_api.md](../../../jiuwenbox/docs/jiuwenbox_server_api.md).

---

## 1. What problem it solves

By default, a command an agent runs has roughly the same privileges as the host process: it can read `~/.ssh`, write `/etc`, connect anywhere, and delete files outside the workspace. Checking command text alone is not enough, because a command can be obfuscated, chained, or wrapped in a child process.

JiuwenBox changes the execution environment instead. The command runs inside a sandbox, and a policy file decides which directories are visible, which endpoints are reachable, and whether deletion is allowed. Requests outside the policy fail instead of quietly falling back to a bare host process.

## 2. A typical sandbox workflow

1. **Start the service.** After installation, run `jiuwenbox-server`. It listens on `0.0.0.0:8321` by default, or on a Unix Domain Socket if configured.
2. **Create a sandbox.** Call `POST /api/v1/sandboxes`, optionally with `sandbox_id`, `env`, `policy`, and `sandbox_runtime`. A successful create returns a sandbox reference with `phase=ready`.
3. **Run commands or move files.** Use `POST /api/v1/sandboxes/{id}/exec` for synchronous execution or `exec_background` for background jobs; use `upload`, `download`, `files`, and `search` for files and directories.
4. **Do a conditional file replace when needed.** Use `file-snapshot` to read a file or to perform a compare-and-swap write against an expected SHA-256.
5. **Stop or delete.** Use `stop` and `restart` to control the lifecycle, and `DELETE` to remove the sandbox.

The same flow with the CLI:

```bash
jiuwenbox health
ID=$(jiuwenbox sandbox create | jq -r .id)
jiuwenbox sandbox exec "$ID" -- python3 -c 'print("hi")'
jiuwenbox sandbox upload "$ID" ./data.csv /tmp/data.csv
jiuwenbox sandbox rm "$ID" --yes
```

## 3. Layout

| Directory | Role |
| --- | --- |
| `jiuwenbox/src/jiuwenbox/server` | Service: lifetime, policy loading, audit, routes, runtime selection |
| `jiuwenbox/src/jiuwenbox/server/runtime` | Runtime adapters: `bubblewrap` and `windows`; `conch` is a reserved name |
| `jiuwenbox/src/jiuwenbox/supervisor` | Turns a policy into controls: bwrap, Landlock, seccomp, cgroup, network, and the Windows `win_*` modules |
| `jiuwenbox/src/jiuwenbox/native` | Native pieces such as the Windows soft-delete DLL |
| `jiuwenbox/src/jiuwenbox/models` | Models for policies, sandboxes, and API payloads |
| `jiuwenbox/src/jiuwenbox/proxy` | Inference privacy proxy for routing and key injection |
| `jiuwenbox/src/jiuwenbox/configs` | Policies shipped with the package |

The samples are `default-policy.yaml`, `code-agent-policy.yaml`, `enterprise-policy.yaml`, `inference-policy.yaml`, `java-policy.yaml`, and `windows-policy.yaml`. When `JIUWENBOX_POLICY_PATH` is unset, the service uses the packaged `default-policy.yaml`.

## 4. Runtime selection

| Priority | Source |
| --- | --- |
| 1 | `sandbox_runtime` in the create request |
| 2 | `JIUWENBOX_RUNTIME_PROFILE` |
| 3 | Platform default: `windows` on Windows, `bubblewrap` on Linux |

`conch` is reserved for the AgentOS cloud backend. It must be requested explicitly and needs its SDK; this repository does not ship that adapter, so requesting it fails instead of falling back.

`GET /api/v1/capabilities` reports each runtime's availability and capability set: local PID, background jobs, fast file IO, recursive search, filesystem ACL, process-tree containment, egress filter, soft delete, and so on. A caller should probe before deployment instead of assuming every runtime supports every capability.

## 5. Isolation on Linux

The Linux runtime starts sandbox processes with bubblewrap. A policy can add:

- **Filesystem**: `read_only`, `read_write`, `bind_mounts`, `directories`, `files`, and `device` decide which paths the sandbox can see.
- **Namespaces**: user, pid, ipc, cgroup, and uts can each be created or reused.
- **Landlock**: `best_effort` enables it when supported; `hard_requirement` fails startup when it is not.
- **Seccomp**: per-architecture block lists for x86_64 and arm64.
- **Network**: `isolated` mode creates a dedicated network namespace, connects it through a veth uplink, and installs egress / ingress rules inside the sandbox netns; `host` mode shares the host network and installs none of those rules.
- **Cgroups**: optional limits on memory, CPU, and process count.

Concurrent sandbox creation waits for the xtables lock, so iptables races do not fail the create. JavaScript execution needs nodejs on the host.

## 6. Isolation on Windows

The Windows runtime targets Windows x64 and needs a one-time administrator setup for accounts, WFP, and ACLs. Isolation uses several layers together:

| Layer | Role |
| --- | --- |
| Restricted token | Two-hop launch under the `jbx-sandbox` account so sandbox processes do not inherit the server's privileges |
| Job object | Caps memory, CPU rate, and process count; closing the job terminates the whole tree |
| WFP | Blocks egress by sandbox user SID and permits only the loopback proxy ports |
| Loopback proxy | HTTP CONNECT / SOCKS5 proxy that filters domains, IPs, and ports by policy |
| NTFS ACL | Grants or denies read/write for the sandbox user; policy `read_only` becomes `deny_write` |
| Soft delete | With `JIUWENBOX_SOFT_DELETE=1`, deletes go to the recycle bin; if that fails, they move to an archive directory on the same volume |

`windows-policy.yaml` uses a dedicated `windows` block: `filesystem` ACL allow/deny lists and `tool_paths`, `proxy` port range, `network.mode` (`wfp_loopback_proxy` or `disabled`), and `resource` limits for memory, CPU, and process count. The Linux-only `process`, `namespace`, `capabilities`, `landlock`, `syscall`, `cgroup`, and `network.uplink` fields are ignored on Windows.

## 7. How policy applies

The server loads a root policy at startup. When a sandbox is created, the request's `policy` can override or append according to `policy_mode`:

- `override`: replace the root policy with the request policy.
- `append`: add directories, paths, or network rules on top of the root policy.

Existing sandboxes keep the policy written at creation time, and changing the startup policy file requires a server restart. `GET /api/v1/policies/{sandbox_id}` shows the effective policy of one sandbox.

## 8. Interfaces and deployment shapes

| Entry | Notes |
| --- | --- |
| REST API | `/health`, `/api/v1/sandboxes/*`, `/api/v1/policies/*`, `/api/v1/timeout`, `/api/v1/proxies/*` |
| Capability probe | `GET /api/v1/capabilities` reports available runtimes and their capabilities |
| File snapshot | `POST /api/v1/sandboxes/{id}/file-snapshot` reads a file or performs a compare-and-swap write inside the sandbox |
| CLI | The `jiuwenbox` command wraps common endpoints and accepts `http://` or `unix:///` |
| MCP | `/mcp` (Streamable HTTP), currently exposing `sandbox_run_command` |
| Transport | TCP or Unix Domain Socket, selected by `JIUWENBOX_LISTEN` |
| Auth | Setting `JIUWENBOX_API_TOKEN` requires a Bearer token on every endpoint |
| Proxy-only mode | When the policy only configures `inference_privacy_proxies` with `listen_port > 0`, the sandbox subsystem is skipped and only the proxy is served |

`file-snapshot` has two operations. `read` returns existence, SHA-256, and size, with the route adding `content_base64`; `compare_replace` requires both `options.expected_exists` and `options.expected_content_sha256`, compares under a per-path lock, then publishes with a temporary file and atomic replace. Mismatches return `conflict`, lock waits return `lock_timeout`, and a broken write transfer returns `outcome_unknown`, which must not be replayed. Paths must be absolute and must not traverse symlinks or reparse points; the per-file limit is 256 MiB. The capability is currently implemented by the bubblewrap runtime; other runtimes return `unsupported`.

## 9. Relation to the other components

JiuwenBox is a separate service. Agent SSAS does not create sandboxes, and agent-shield does not start this service; its Windows native guards and the server-side sandbox are independent mechanisms. The caller keeps the sandbox address and manages sandboxes through the API in the README and API reference.
