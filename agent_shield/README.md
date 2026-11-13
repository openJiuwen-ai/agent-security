# agent-shield

安全决策 SDK（进程内、纯规则、无 LLM、无网络 IO）。三件事：

- **F1 动作决策**（`tool_permission/`）：对工具调用输出确定性结论 allow / ask / deny
- **行为策略**（`policy_engine/`）：对工具调用和 native record 给出 allow / ask / deny。`intercepts/tool_call/` 接入工具调用，`intercepts/native_call/` 接入系统调用，`intercepts/tool_output/` 把工具结果交给 `detection`
- **F3 内容检测**（`detection/`）：对进入模型的内容做注入等检测，输出概率性软信号

沙箱（F2）是独立交付件，见同仓 `../jiuwenbox/`。

SDK 可选的 [Windows DLL 用户态防护层](native/windows-dll-guard/README.md) 在 Windows x64 上检查受保护进程的文件、程序启动和网络访问。
宿主通过 `dll_guard.RuntimeGuardManager` 管理会话内的前台及后台进程树。SDK 通过 `emit` 交付运行中的审批请求，宿主渲染事件并通过 `manager.approvals.resolve` 交回用户的决定。运行时、策略回调类型和审批回执均从 `agent_shield.intercepts.native_call.dll_guard` 导入。

文档在仓库根目录，中文从 [../docs/zh/SUMMARY.md](../docs/zh/SUMMARY.md) 进入，英文在 [../docs/en/SUMMARY.md](../docs/en/SUMMARY.md)。

## 目录 ↔ 工作项对照

| 工作项 | 目录 |
|---|---|
| W1a 命令判定引擎 | `tool_permission/toolguard/` |
| W2 路径防护 | `tool_permission/fileguard/` |
| W3 出站判定 | `tool_permission/netguard/` |
| W4 内容检测 | `detection/` |
| W6 总入口 / 对外门面 | `__init__.py` 与 `tool_permission/` 根（收口人定） |
| W8 测试 | `tests/` 下同名子目录 |
| 行为策略引擎 | `policy_engine/` |
| 工具调用接入 | `intercepts/tool_call/` |
| 工具结果接入 | `intercepts/tool_output/` |
| W1b 宿主进程守卫 | `intercepts/native_call/` |
| W7 宿主接入 | 不在本仓（jiuwenswarm / agent-core 侧） |
| W5 沙箱接线 | 服务端在 `../jiuwenbox/`，SDK 侧接线随 W6 定 |

`schema/` 是决策与 native record 的 JSON Schema，`native/windows-process-guard/` 是进程守卫的 C/C++ 实现（Microsoft Detours 为**构建期外置依赖**，见 `native/windows-process-guard/third_party/NOTICE.md`；安装/导入 Python 包无需拉取 Detours）。三方规则经规则集接口注册。PDP 设计见 [docs/agent_shield-design.md](docs/agent_shield-design.md)。

## 环境

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

## 规则

- 对外只从子模块根导入，例如 `from agent_shield.tool_permission import get_permission_manager`；`agent_shield` 包根不导出任何名字，子模块内部（`toolguard` 等）禁止深导
- 权限判定：生产调用方必须用 `get_permission_manager()` 取进程级单例；测试或需要与单例隔离的实例用 `new_permission_manager()`；直接 `PermissionManager()` 会抛 `RuntimeError`
- `PermissionEngine` 位于 `agent_shield.tool_permission.engine`，仅供内部实现使用，不从门面导出
- `approval_overrides` 的匹配授权优先于命令规则和工具基线：原文或剥壳后的完整命令命中时，整次调用直接 ALLOW，不再执行其他 Guard；仅子命令命中时，只将该候选直接判为 ALLOW，其他候选和整串检查仍取最严格结果
- 子模块内部用相对导入；跨子模块只能导入对方的根；`jiuwenbox` 等外部项目同样只导入到子模块根（由 `tests/test_import_rules.py` 守住）
- 各工作项目录内部组织自己定，收口前不要跨目录引用
