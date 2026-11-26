# HyperShell

English | [简体中文](README.zh.md)

HyperShell is the managed workspace and permission governance component prepared for
[openJiuwen Agent Security](https://github.com/openJiuwen-ai/agent-security).
It translates administrator resource policies and user grants into a launch plan,
then uses JiuwenBox to run a JiuwenSwarm workspace under a dedicated Linux identity.

**Status: experimental / alpha (`0.1.0.dev0`).** Policy preview works without a sandbox.
Live execution requires an administrator-prepared Linux environment; the Web UI and
authenticated TUI launcher are demos. This is not a production multi-tenant service.

## Responsibilities

| Component | Responsibility |
| --- | --- |
| HyperShell | User grants, role templates, workspace lifecycle, policy translation and verification |
| JiuwenBox | Sandbox execution and operating-system isolation |
| Agent Shield | In-process action decisions and content detection |
| Agent SSAS | Runtime event collection and threat detection |

HyperShell currently integrates with JiuwenBox and JiuwenSwarm. Agent Shield and
Agent SSAS integration is not implemented here. Agents and skills within one user
workspace share its outer permissions; there is no per-agent kernel boundary.

## Quick start: policy preview

Requires Python 3.11–3.13. From the `agent-security` repository root, run
`cd management/hypershell` before running the commands below.

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python examples/demo/run_demo.py
```

The demo checks an allowed request, a write request against a read-only resource,
and an ungranted resource. It writes JSON to `demo-output/` and does not create
accounts, sandboxes, or model connections. Linux paths in the example are placeholders.

```bash
python -m hypershell config validate --config examples/demo/hypershell-roles.yaml
python -m hypershell grants explain --config examples/demo/hypershell-roles.yaml --user u1
python -m hypershell plan --config examples/demo/hypershell.yaml --request examples/demo/request-allowed.yaml --demo-user u1
```

`--demo-user` selects a simulated identity for preview; it does not authenticate a user.
The CLI returns 0 for successful preview and 2 for invalid configuration or denied requests.
Install from this source directory in an isolated environment. The PyPI name
`hypershell` is also used by an unrelated project; do not use a bare package-name install.

## Live execution and security

Live `start/status/chat/tui/stop/doctor/recover` commands require Linux root, dedicated
workload UID/GIDs, JiuwenSwarm and a compatible JiuwenBox backend, trusted runtime
bundles, and namespace/Landlock/seccomp/cgroup and firewall support.
Installing this Python package alone does not provision that environment.
The JiuwenBox snapshot at the target repository's local revision `1e0b3b9` lacks
the cleanup-control contract required by this runner; live backend compatibility
must be resolved before using that combination. The startup check rejects it.
See the [user guide](docs/USER_GUIDE.md) (Chinese).

The current network profile allows loopback and approved model public IPv4 TCP 443,
and blocks direct DNS and external IPv6. Permission changes require stopping and
recreating affected instances. Web runs in a privileged process and lacks production
session revocation and login rate limiting; keep demos on loopback in a controlled lab.
Supply a signing key file with `--secret-file` to preserve Web sessions across restarts.
Without a configured or existing legacy key file, the demo keeps its signing key in memory.
See [security boundaries](SECURITY.md) for the threat model and remaining work.

## Development

```bash
python -m pip install -e ".[dev,web]"
python -m pytest tests -q -ra --basetemp=.test-tmp/pytest
```

The test suite includes mocks and platform-specific tests; passing unit tests is not
proof of Linux isolation. See the [user guide](docs/USER_GUIDE.md) and [contributing](CONTRIBUTING.md).

| Path | Contents |
| --- | --- |
| `hypershell/policy/`, `hypershell/config.py` | Permission compiler and strict YAML configuration |
| `hypershell/runner/` | JiuwenBox adapter, lifecycle, runtime verification and terminal transport |
| `hypershell/web/` | Demo administrator UI and user entry |
| `examples/`, `scripts/dev/` | Preview examples and explicit lab tools |
| `tests/`, `docs/` | Regression tests and maintained documentation |

The [documentation index](docs/README.md) lists the Chinese design document and
user guide. The English README and security guide describe the supported entry
points and limitations.
Licensed under [Apache-2.0](LICENSE).
