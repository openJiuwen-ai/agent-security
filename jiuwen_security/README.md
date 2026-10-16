# jiuwen-security

安全决策 SDK（进程内、纯规则、无 LLM、无网络 IO）。两件事：

- **F1 动作决策**（`policy/`）：对工具调用输出确定性结论 allow / ask / deny
- **F3 内容检测**（`detection/`）：对进入模型的内容做注入等检测，输出概率性软信号

沙箱（F2）是独立交付件，见同仓 `../jiuwenbox/`。

## 目录 ↔ 工作项对照（依据 docs/重构分工.md）

| 工作项 | 目录 |
|---|---|
| W1a 命令判定引擎 | `src/jiuwen_security/policy/toolguard/` |
| W2 路径防护 | `src/jiuwen_security/policy/fileguard/` |
| W3 出站判定 | `src/jiuwen_security/policy/netguard/` |
| W4 内容检测 | `src/jiuwen_security/detection/` |
| W6 总入口 / 对外门面 | `src/jiuwen_security/__init__.py` 与 `policy/` 根（收口人定） |
| W8 测试 | `tests/` 下同名子目录 |
| W1b 宿主命令守卫、W7 调用方迁移 | 不在本仓（jiuwenswarm / agent-core 侧） |
| W5 沙箱接线 | 服务端在 `../jiuwenbox/`，SDK 侧接线随 W6 定 |

## 环境

```bash
cd jiuwen_security
pip install -e ".[dev]"
pytest
```

## 规则

- 对外只从 `jiuwen_security` 包根导入，禁止深导（门面由 W6 收口）
- 各工作项目录内部组织自己定，收口前不要跨目录引用
