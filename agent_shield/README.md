# agent-shield

[English](./README_EN.md) | 简体中文

进程内安全判定 SDK（纯规则、不调大模型、不做网络 IO）。它在工具调用和本机访问发生前给出确定性的 allow / ask / deny，并在 Windows 上提供两套原生防护把文件、进程和网络访问拦在执行前。

## 能力分层

| 目录 | 作用 |
|---|---|
| `policy_engine/` | 行为策略决策点（PDP）：四层规则、十级优先级、`Decide` 结算、回环 HTTP 服务与 `agent-pdp` CLI |
| `intercepts/tool_call/` | 工具调用 → `agent-event/v1` 事件 |
| `intercepts/native_call/` | 原生系统调用 → 事件；包含进程守卫与 DLL 防护的接入 |
| `intercepts/tool_output/` | 工具结果文本 → 内容检测 |
| `tool_permission/` | 既有动作决策组件：toolguard / fileguard / netguard / hostguard / delguard，以及 `runtime` 授权复用 |
| `detection/` | 内容检测引擎，输出提示词注入等概率性软信号 |
| `native/windows-process-guard/` | `process_guard.exe` 与 x64 / x86 Hook DLL 的 C/C++ 实现 |
| `native/windows-dll-guard/` | `jiuwen_runtime_guard.dll` 的用户态防护实现 |

沙箱（F2）是独立交付件，见同仓 `../jiuwenbox/`。

## Windows 原生防护

两套方案共用 `agent-security-dll` 分发包里的二进制文件，接入方式不同：

| 方案 | 入口 | 形态 |
|---|---|---|
| 进程守卫 | `agent_shield.intercepts.native_call.wrap()` | 独立 `process_guard.exe` + Hook DLL，JSON `native-record/v1` 管道，支持回收站删除与 x86 WOW64 子进程 |
| DLL 防护 | `agent_shield.intercepts.native_call.dll_guard.RuntimeGuardManager` | 宿主进程内管理会话，导入表注入 `jiuwen_runtime_guard.dll`，二进制帧 IPC，支持运行中审批、授权复用与前后台进程树 |

新接入的异步工具链优先使用 `RuntimeGuardManager`。它只支持 Windows x64；每次工具调用在 `async with manager.tool_execution(...)` 内通过 `create_process()` 启动进程，命中 ask 时由宿主渲染事件并调用 `manager.approvals.resolve(...)` 交回决定。既有 `Decide` / `wrap` 协议保持原有行为，继续由进程守卫承载。

```python
from agent_shield.intercepts.native_call.dll_guard import (
    RuntimeGuardManager,
    create_process,
    locate_guard_dll,
)
```

## 目录 ↔ 工作项对照

| 工作项 | 目录 |
|---|---|
| W1a 命令判定引擎 | `tool_permission/toolguard/` |
| W2 路径防护 | `tool_permission/fileguard/` |
| W3 出站判定 | `tool_permission/netguard/` |
| W4 内容检测 | `detection/` |
| W6 总入口 / 对外门面 | `tool_permission/__init__.py` 与 `tool_permission/manager.py` |
| W8 测试 | `tests/` 下同名子目录 |
| 行为策略引擎 | `policy_engine/` |
| 工具调用接入 | `intercepts/tool_call/` |
| 工具结果接入 | `intercepts/tool_output/` |
| W1b 宿主进程守卫 | `intercepts/native_call/`（`wrap` + `process_guard.exe`） |
| DLL 防护 | `intercepts/native_call/dll_guard/` + `native/windows-dll-guard/` |
| W7 宿主接入 | 不在本仓（jiuwenswarm / agent-core 侧） |
| W5 沙箱接线 | 服务端在 `../jiuwenbox/`，SDK 侧接线随 W6 定 |

`schema/` 存放决策与 native record 的 JSON Schema。`native/windows-process-guard/` 是进程守卫的 C/C++ 实现；Microsoft Detours 是构建期外置依赖（见 `native/windows-process-guard/third_party/NOTICE.md`），安装和导入 Python 包不需要拉取。三方规则经规则集接口注册，PDP 设计见 [docs/agent_shield-design.md](docs/agent_shield-design.md)。

## 环境

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter 及 bash / pwsh / batch 语法包是必需依赖。需要使用 DLL 防护时再安装：

```bash
pip install -e ".[dll-guard]"
pip install agent-security-dll
# 源码检出也可从本地安装：
# pip install ./native/windows-process-guard/python
```

## 裁决与授权

- 行为策略引擎的每次裁决产出 `agent-decision/v1`，`action` 取值 `allow` / `ask` / `deny` / `undetermined`。`undetermined` 表示该部分没有任何规则命中，引擎不会自动把它当成 allow。
- `unmatched` 是宿主启动时设定的无命中改写策略（`none` / `allow` / `ask` / `deny`，默认 `none`），只改写结果为 `undetermined` 的部分；它不进入 DecisionRequest，规则集更新也不能修改它。
- `approval_overrides` 属于 `tool_permission`，是 `PermissionManager` 与 DLL 防护复用的运行时授权匹配；PDP 的 `grants` 是另一套机制：由 HITL 审批沉淀、随 DecisionRequest 传入、只允许精确资源的 allow，并受十级优先级位置 4 约束。两者格式与生效范围都不同，不要混用。

## 规则

- 对外从子模块根导入，例如 `from agent_shield.tool_permission import get_permission_manager`；`agent_shield` 包根不导出任何名字。宿主不应直接依赖 `tool_permission.runtime`，需要独立运行时辅助时用 `agent_shield.tool_permission.runtime_policy`。
- 权限判定：生产调用方必须用 `get_permission_manager()` 取进程级单例；测试或需要与单例隔离的实例用 `new_permission_manager()`；直接 `PermissionManager()` 会抛 `RuntimeError`。
- `PermissionEngine` 位于 `agent_shield.tool_permission.engine`，仅供内部实现使用，不从门面导出。
- `approval_overrides` 的匹配授权优先于命令规则和工具基线：
  - 原文或剥壳后的完整命令命中时，整次调用直接 ALLOW，不再执行其他 Guard。
  - 仅子命令命中时，只将该候选直接判为 ALLOW；其他候选和整串检查仍取最严格结果。
  - 运行时授权另外支持 `exact_operation`、父目录、域名与子命令范围。
- 子模块内部用相对导入；跨子模块优先只导入对方的根；`jiuwenbox` 等外部项目同样只导入到子模块根（由 `tests/test_import_rules.py` 守住）。
- 各工作项目录内部组织自己定；在统一收口前，不要跨目录引用。

## 文档

中文从 [../docs/zh/SUMMARY.md](../docs/zh/SUMMARY.md) 进入，英文在 [../docs/en/SUMMARY.md](../docs/en/SUMMARY.md)。PDP 与原生协议的设计细节见 [docs/agent_shield-design.md](docs/agent_shield-design.md)。
