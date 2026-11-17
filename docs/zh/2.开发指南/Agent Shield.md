# Agent Shield

agent-shield（分发名 `agent-shield`，导入名 `agent_shield`）是进程内的安全判定 SDK。它不负责资源隔离，也不调用大模型，而是回答三个问题：

- 这次工具调用能不能放行？
- 这次系统调用要不要拦？
- 这段进入模型或工具结果的内容有没有风险？

前两个问题给出确定性的 allow / ask / deny，第三个问题给出概率性风险信号。动作判定还可能返回 `undetermined`：它表示这一部分没有命中任何规则，不能直接当成 allow，需要宿主用 `unmatched` 配置决定改写成 allow、ask 还是 deny。

---

## 1. 它解决什么问题

Agent 的工具调用通常长这样：工具名是 `shell`，参数里有 `command`；或者工具名是 `write_file`，参数里有路径和内容。不同框架、不同工具的参数格式各不相同，如果每个工具自己判断安全，规则会散落各处，结果也难以解释。

agent-shield 把这些调用统一成事件，再做一次集中裁决：

```text
工具调用 / 系统调用
        │
        ▼
  规范化为事件与 effect
        │
        ▼
  四层规则匹配（内置 / 三方 / 用户 / grant）
        │
        ▼
  十级优先级聚合
        │
        ▼
  allow / ask / deny
        │
        └── ask → 宿主打开审批窗口
```

比如 `git push --force` 会命中强制推送规则，返回 `ask`；`rm -rf ~` 会命中工作区外强制删除规则，同样返回 `ask`。真正返回 `deny` 的是写入受保护文件、裸盘写入等 critical 行为。裁决结果里会带上胜出规则和用户可见说明，宿主可以直接展示或审计。

## 2. 三种接入方式

| 接入方式 | 入口 | 适合什么场景 | 产出 |
| --- | --- | --- | --- |
| 工具调用判定 | `agent_shield.tool_permission.get_permission_manager()` | 已有工具调用链，只想在执行前拿一个决定 | `PermissionResult`，含 `permission`、`matched_rule`、`reason` |
| 行为策略引擎 | `agent_shield.policy_engine.evaluate()`、`Decide`、`agent-pdp serve` | 需要四层规则、任务绑定、审批结算或独立回环服务 | `agent-decision/v1` 决定信封 |
| Windows 原生防护 | `agent_shield.ProcessGuard.spawn()` | 需要拦截文件、进程、网络等系统调用 | 放行或拒绝本次 API 调用 |

三种方式可以单独使用，也可以组合。比如用 `tool_permission` 做工具调用判定，再用 DLL 防护挡住工具启动后的子进程访问。

## 3. 能力分层

| 目录 | 作用 |
| --- | --- |
| `policy_engine/` | 行为策略决策点（PDP）：四层规则、十级优先级、`Decide` 结算、回环 HTTP 服务与 `agent-pdp` CLI |
| `intercepts/tool_call/` | 把一次工具调用编成 `agent-event/v1` 事件，交给 PDP |
| `intercepts/native_call/` | 把一条原生系统调用记录编成事件；包含进程守卫与 DLL 防护的接入 |
| `intercepts/tool_output/` | 把工具结果文本交给内容检测 |
| `tool_permission/` | 既有动作决策组件：命令、路径、网络、宿主与删除防护，以及运行时授权 |
| `detection/` | 内容检测引擎，输出提示词注入等概率性软信号 |
| `foundation/agent-security-dll/` | `agent_security_guard.dll` 的用户态防护实现 |

`policy_engine/` 与 `tool_permission/` 同包名空间、分开演进：前者管「一次事件该不该放行」，后者管「工具调用和本机访问的具体规则」。

## 4. 一次判定经过哪些步骤

以工具调用为例：

1. **规范化**。适配器从工具名和参数里取出命令、路径、网络端点和操作类型，拆成一个或多个 effect。命令只做解析，不执行。
2. **规则匹配**。内置规则、三方规则、用户规则和 grant 同时参与匹配。内置规则是安全底线，不可删除；三方规则经规则集接口注册；用户规则和 grant 由宿主传入。
3. **优先级聚合**。每一部分取优先级最高的命中，再按 deny > ask > undetermined > allow 聚合。deny 永远不会被 allow 翻转，内置 ask 和三方 ask 也不会被宽匹配的用户 allow 压过。没有命中任何规则的部分是 `undetermined`，由宿主的 `unmatched` 配置改写；默认 `none` 表示保持未决定。
4. **生成结果**。结果是 `ask` 时，引擎会为可沉淀的部分生成建议 grant；宿主可以打开审批窗口，决定放行这一次或拒绝。
5. **留下记录**。注册表、审计文件或调用方日志会记录胜出规则、动作和事件 id，方便追溯。

## 5. Windows 原生防护

宿主按会话创建 `ProcessGuard(session_id=..., host=...)`，进入异步上下文后，用 `await guard.spawn(argv, task_id=..., tool_call_id=..., tool_name=...)` 启动每棵受保护进程树。宿主提供 `policy_snapshot`、`confirm`、`save_grant` 和 `audit`。用 `await proc.wait()` 取得根进程退出码。会话持续管理后代，直至 Job 为空或会话关闭。

Windows x64 SDK 加载公共 `agent_security_guard.dll`，默认删除模式为 `recover`。详见 [SDK 示例](../../../agent_shield/README.md) 和 [架构验收记录](../../../foundation/agent-security-dll/README.md)。

## 6. 最小使用示例

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

默认配置会加载内置的命令、路径、网络和删除防护，但不包含宿主自己的用户规则和 grant。不调用 `update_config` 时，审批沉淀和用户自定义规则不会生效；如果某个部分没有命中内置规则，结果可能是 `undetermined`，需要宿主自己决定怎么处理。生产接入时，宿主应先用 `manager.update_config(config, key="session-1")` 注册自己的策略，再在调用时传入同一个 `key`；需要与进程级单例隔离的测试实例用 `new_permission_manager()`。`PermissionEngine` 位于 `agent_shield.tool_permission.engine`，属于内部实现，不要直接构造。

在真实工具循环里，通常这样接入：

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

## 7. 安装与测试

```bash
cd agent_shield
pip install -e ".[dev]"
pytest
```

tree-sitter 及其 bash / pwsh / batch 语法包是必需依赖，命令结构分析不再退回字符级扫描。需要使用 DLL 防护时再安装：

```bash
pip install -e ".[dll-guard]"
pip install agent-security-dll
# 源码检出也可从本地安装：
# pip install ./foundation/agent-security-dll/build/wheels/agent_security_dll-0.3.0-py3-none-win_amd64.whl
```

## 8. 继续阅读

| 想了解 | 文档 |
| --- | --- |
| 规则模型、优先级、协议与测试 | [agent_shield-design.md](../../../agent_shield/docs/agent_shield-design.md) |
| DLL 防护的构建与验证 | `foundation/agent-security-dll/README.md` |
| 组件职责与配置项 | 同目录 [Agent Shield 组件与配置参考](Agent%20Shield组件与配置参考.html) |
