# agent-shield

安全决策 SDK（进程内、纯规则、无 LLM、无网络 IO）。三件事：

- **F1 动作决策**（`tool_permission/`）：对工具调用输出确定性结论 allow / ask / deny
- **行为策略**（`policy_engine/`）：对工具调用和 native record 给出 allow / ask / deny。`intercepts/tool_call/` 接入工具调用，`intercepts/native_call/` 接入系统调用，`intercepts/tool_output/` 把工具结果交给 `detection`
- **F3 内容检测**（`detection/`）：对进入模型的内容做注入等检测，输出概率性软信号

沙箱（F2）是独立交付件，见同仓 `../jiuwenbox/`。

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
| W7 调用方迁移 | 不在本仓（jiuwenswarm / agent-core 侧） |
| W5 沙箱接线 | 服务端在 `../jiuwenbox/`，SDK 侧接线随 W6 定 |

`schema/` 是决策与 native record 的 JSON Schema，`native/windows-process-guard/` 是进程守卫的 C/C++ 实现（Microsoft Detours 为 git submodule，克隆需 `--recurse-submodules`）。三方规则经规则集接口注册。PDP 设计见 [docs/agent_shield-design.md](docs/agent_shield-design.md)。

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
- 子模块内部用相对导入；跨子模块只能导入对方的根；`jiuwenbox` 等外部项目同样只导入到子模块根（由 `tests/test_import_rules.py` 守住）
- 各工作项目录内部组织自己定，收口前不要跨目录引用
