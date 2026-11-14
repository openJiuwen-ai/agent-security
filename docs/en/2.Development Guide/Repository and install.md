# Repository and install

The repository root has no single install entry. Each component has its own `pyproject.toml` and is installed from its own directory. All five components require Python 3.11 or newer, and you can install only the ones you need.

---

## 1. Decide what to install

| What you need | Install | Extra preparation |
| --- | --- | --- |
| allow / ask / deny before a tool call | `agent-shield` | None; tree-sitter is installed with the package |
| Intercept Windows file, process, and network access | `agent-shield` + `agent-security-dll` | Windows x64; DLL guard needs the binary package |
| Run commands inside a sandbox | `jiuwenbox` | Linux needs bubblewrap; Windows needs an administrator setup for accounts, WFP, and ACLs |
| Observe agent runtime behavior and detect threats | `agent-ssas` | HTTP mode also needs `[http]` |
| Store API keys and tokens encrypted | `security-gateway` | None |
| Mask sensitive spans in streaming output | `security-mask` | None |

## 2. Environment

| Component | Platform | Runtime dependencies |
| --- | --- | --- |
| Agent SSAS | Windows / Linux / macOS | `PyYAML`; HTTP mode also needs `[http]` (fastapi, uvicorn, httpx) |
| JiuwenBox | Linux; Windows x64 | pydantic, fastapi, uvicorn, httpx, mcp; Linux needs bubblewrap, and network isolation also needs iproute2, iptables, nftables |
| agent-shield | Cross-platform; native guards are Windows x64 only | `PyYAML` plus four tree-sitter packages (bash / pwsh / batch parsing); DLL guard also needs `[dll-guard]` and `agent-security-dll` |
| Security Gateway | Cross-platform | `cryptography`, `PyYAML` |
| Security Mask | Cross-platform | No third-party runtime dependency |

JiuwenBox's Windows runtime needs a one-time administrator setup for accounts, WFP, and ACLs. When the environment is not ready, the service fails to start instead of reporting a successful start that cannot serve traffic. See [JiuwenBox](JiuwenBox.md) and `jiuwenbox/README.md`.

agent-shield's `process_guard.exe` must be built locally or installed from the `agent-security-dll` binary package. DLL guard additionally requires x64 targets.

## 3. Local install

From the repository root, enter each component directory.

### Agent SSAS

```bash
cd agent_ssas
uv venv
uv pip install -e .
uv pip install -e ".[http]"
```

If you only need in-process detection, skip `[http]`.

### JiuwenBox

```bash
cd jiuwenbox
uv venv
uv sync
uv pip install -e .
```

Wheel build, server startup, and Windows setup live in [jiuwenbox/README.md](../../../jiuwenbox/README.md). Sample policies are in `jiuwenbox/src/jiuwenbox/configs/`.

### agent-shield

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

For the Windows DLL guard, install the binary package as well:

```bash
pip install -e ".[dll-guard]"
pip install agent-security-dll
# From a source checkout you can also install locally:
# pip install ./native/windows-process-guard/python
```

### Security Gateway

```bash
cd security_gateway
pip install -e ".[dev]"
pytest tests -q
```

### Security Mask

```bash
cd foundation
pip install -e ".[dev]"
pytest
```

## 4. Verify the install

| Component | How to check | Expected |
| --- | --- | --- |
| Agent SSAS | `python -c "import agent_ssas"`; for HTTP mode, start the service and call `/health` | Import succeeds; the service reports healthy |
| JiuwenBox | Start `jiuwenbox-server`, then `curl http://127.0.0.1:8321/health` | `status: ok` and the active runtime |
| agent-shield | `pytest` | Tests pass; DLL guard cases are skipped when binaries are missing |
| Security Gateway | `pytest tests -q` | All tests under `tests/unit` pass |
| Security Mask | `pytest` | `test_stream_mask.py` passes |

JiuwenBox's `/api/v1/capabilities` also reports which runtimes are available on the host. On Windows, probe it before deciding whether to create a sandbox.

## 5. Where to go next

| Component | In-repo document |
| --- | --- |
| Agent SSAS | [Agent SSAS](Agent%20SSAS.md); the full tutorial set is `agent_ssas/docs/README.md` |
| JiuwenBox | [JiuwenBox](JiuwenBox.md); API and deployment notes are in `jiuwenbox/README.md` and `jiuwenbox/docs/jiuwenbox_server_api.md` |
| agent-shield | [Agent Shield](Agent%20Shield.md); the design document is `agent_shield/docs/agent_shield-design.md` |
| Security Gateway | [Security Gateway](Security%20Gateway.md) |
| Security Mask | [Security Mask](Security%20Mask.md) |

Note: the leftover `agent-ssas/` and `jiuwen_security/` directories contain only historical build artifacts, no source, and no installable component. The live directories are `agent_ssas/` and `agent_shield/`.
