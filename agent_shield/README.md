# agent-shield

[English](./README_EN.md) | 简体中文

进程内安全判定 SDK（纯规则、不调大模型、不做网络 IO）。它在工具调用和本机访问发生前给出确定性的 allow / ask / deny，并在 Windows 上通过公共 DLL 把文件、进程和网络访问拦在执行前。

## 能力分层

| 目录 | 作用 |
|---|---|
| `policy_engine/` | 行为策略决策点（PDP）：四层规则、十级优先级、`Decide` 结算、回环 HTTP 服务与 `agent-pdp` CLI |
| `intercepts/tool_call/` | 工具调用 → `agent-event/v1` 事件 |
| `intercepts/native_call/` | 原生系统调用 → 事件；包含进程守卫与 DLL 防护的接入 |
| `intercepts/tool_output/` | 工具结果文本 → 内容检测 |
| `tool_permission/` | 既有动作决策组件：toolguard / fileguard / netguard / hostguard / delguard，以及 `runtime` 授权复用 |
| `detection/` | 内容检测引擎，输出提示词注入等概率性软信号 |
| `../foundation/agent-security-dll/` | Agent Shield 与 JiuwenBox 共用的 Windows Hook 和软删除实现 |

沙箱（F2）是独立交付件，见同仓 `../jiuwenbox/`。

## Windows 原生防护

SDK 可选的 [Windows DLL 用户态防护层](../foundation/agent-security-dll/README.md) 在 Windows x64 上检查受保护进程的文件、程序启动和网络访问。
宿主通过 `from agent_shield import ProcessGuard` 创建会话。使用 `await guard.spawn(argv, task_id=..., tool_call_id=..., tool_name=...)` 启动一棵受保护的进程树，使用 `await proc.wait()` 取得根进程退出码。宿主提供 `policy_snapshot`、`confirm`、`save_grant` 和 `audit`。默认删除模式 `recover` 与 JiuwenBox 共用 foundation 的原生回收实现。

要在这个入口使用行为规则，宿主在 `policy_snapshot()` 中同时提供 `ruleset` 和 `tasks`。下面的规则会在一次文件替换开始前检查备份目的地。

```python
{
    "revision": 7,
    "workspace_root": "C:/project",
    "config": {"enabled": True, "tools": {"bash": "allow"}},
    "ruleset": {"spec": "agent-pdp/v1", "rules": [{
        "id": "org.protected_backup", "object": "file", "ops": ["write"],
        "pattern": ["C:/project/protected/**"], "action": "deny",
    }]},
    "tasks": {"task-42": {"subject_id": "user-7", "user_rules": [], "grants": []}},
    "unmatched": "none",
}
```

`spawn(..., task_id="task-42", ...)` 使用该任务的规则、主体、已保存授权以及可选的 `user_intent` 和 `host_capabilities`。组织规则通过原有行为规则引擎编译。运行时资源策略与任务规则中的拒绝均生效。宿主在改变快照时更新 `revision`。每次决策的 `policy_decision` 审计记录包含进程、任务、工具调用、裁决和命中规则 ID。Windows x64 宿主当前支持 x64 和 WOW64 目标，后代按实际位数继续使用同一会话。

详见 [DLL 构建与架构验收](../foundation/agent-security-dll/README.md)。

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
| W1b 宿主进程守卫 | `intercepts/native_call/dll_guard/process_guard.py`（`ProcessGuard.spawn()`） |
| W7 宿主接入 | 不在本仓（jiuwenswarm / agent-core 侧） |
| W5 沙箱接线 | 服务端在 `../jiuwenbox/`，SDK 侧接线随 W6 定 |

`schema/` 是决策、事件与审计的 JSON Schema，`../foundation/agent-security-dll/` 是进程守卫的 C/C++ 实现（Microsoft Detours 为**构建期外置依赖**，见 `../foundation/agent-security-dll/third_party/NOTICE.md`；安装/导入 Python 包无需拉取 Detours）。三方规则经规则集接口注册。PDP 设计见 [docs/agent_shield-design.md](docs/agent_shield-design.md)。

## 环境

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter 及 bash / pwsh / batch 语法包是必需依赖。在 Windows 上先按 [DLL 构建说明](../foundation/agent-security-dll/README.md) 构建并安装对应 wheel，再安装 SDK 扩展。

```bash
pip install -e ".[dll-guard]"
```

## 裁决与授权

- 行为策略引擎的每次裁决产出 `agent-decision/v1`，`action` 取值 `allow` / `ask` / `deny` / `undetermined`。`undetermined` 表示该部分没有任何规则命中，引擎不会自动把它当成 allow。
- `unmatched` 是宿主启动时设定的无命中改写策略（`none` / `allow` / `ask` / `deny`，默认 `none`），只改写结果为 `undetermined` 的部分；它不进入 DecisionRequest，规则集更新也不能修改它。
- `approval_overrides` 属于 `tool_permission`，是 `PermissionManager` 与 DLL 防护复用的运行时授权匹配；PDP 的 `grants` 是另一套机制：由 HITL 审批沉淀、随 DecisionRequest 传入、只允许精确资源的 allow，并受十级优先级位置 4 约束。两者格式与生效范围都不同，不要混用。

## 规则

- 对外从子模块根导入，例如 `from agent_shield.tool_permission import get_permission_manager`；`agent_shield` 包根按需导出 `ProcessGuard`。宿主不应直接依赖 `tool_permission.runtime`，需要独立运行时辅助时用 `agent_shield.tool_permission.runtime_policy`。
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
