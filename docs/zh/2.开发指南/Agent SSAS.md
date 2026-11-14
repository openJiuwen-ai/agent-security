# Agent SSAS

Agent SSAS（包名 `agent-ssas`，导入名 `agent_ssas`）是一个 Agent 安全态势感知系统。它采集 Agent 运行时事件，做威胁检测，并把结果写成 OCSF 格式的日志。它不绑定某一个智能体框架，当前通过安全 Rail 接入 JiuwenSwarm。

组件自己的文档中心在 [agent_ssas/docs/README.md](../../../agent_ssas/docs/README.md)，里面有教程、操作指南、配置参考和架构说明。本文只说明它在仓库中的位置和核心概念。

---

## 1. 它解决什么问题

Agent 执行任务时会连续调用模型和工具：读文件、跑命令、访问网络、修改状态。单看某一步可能都正常，但连起来可能形成一条风险链：先读敏感文件，再把内容发到外部地址；或者先被提示词注入，再执行破坏性命令。事后查日志往往只知道“调用过”，不知道“为什么有风险”。

Agent SSAS 在运行过程中采集事件，把事件送进检测模块，输出风险评估和威胁日志。它不要求改 Agent 的业务代码，也不要求所有框架统一；检测引擎可以嵌进任意 Python 进程。

## 2. 两个子系统

| 子系统 | 包路径 | 职责 |
| --- | --- | --- |
| AgentSSASCore | `agent_ssas.core` | 检测引擎：数据预处理、分析流水线、检测模块管理、存储、OCSF 呈现 |
| AgentSSASClient | `agent_ssas.backend_client` | 事件采集与上报。openjiuwen 客户端的核心类是 `AgentSSASSecurityRail` |

检测引擎可以单独嵌进任意 Python 进程。只有接入 JiuwenSwarm 的那一层客户端依赖智能体运行时；`AgentSSASSecurityRail` 继承 agent-core 的 `BaseSecurityRail`，采集 6 类生命周期事件（`invoke_start`、`llm_input`、`tool_input`、`tool_output`、`llm_output`、`invoke_end`）和 1 类安全衍生事件（`permission_interrupt_tool`）。

## 3. 事件怎么流动

```text
Agent 运行时
    │  生命周期事件 / 安全衍生事件
    ▼
AgentSSASClient
    │  规范化、过滤、上报
    ▼
AgentSSASCore 预处理
    │
    ▼
检测模块（数据建模 + 威胁分析）
    │  风险评估、威胁日志
    ▼
OCSF 输出 + SQLite 存储
```

检测模块用 `module.yaml` 声明订阅哪些事件、用哪些插件。模块可以按 notify 模式异步运行，不阻塞主流程；也可以按 auth 模式同步参与安全决策。notify 适合审计和后台检测，auth 适合需要在工具结果返回前给出结论的场景，并有超时兜底。

## 4. 运行方式

| 模式 | 行为 |
| --- | --- |
| `inprocess` | 默认。检测跑在同一进程里，没有网络开销 |
| `http` | 独立的 FastAPI 服务，默认监听 `0.0.0.0:8443`，多个智能体共用一台分析引擎 |

HTTP 服务暴露 `POST /api/v1/events` 和 `GET /health`。认证通过 `AgentSSASConfig.http_token` 配置；设置后未认证请求返回 401。未设置 token 时服务不启用认证，不要把它直接暴露在公网。

## 5. 检测模块

内置模块包括：

- `agent_moss`：规则、行为链与 Agent Behavior Graph 数据外泄分析。
- `security_rail_detection`：对其他安全 Rail 的发现做衍生分析，按拒绝场景推导置信度。
- `test_detection`：验证流水线用，默认关闭。

新模块用 `module.yaml` 声明，不改框架代码。模块目录、插件命名规则和自定义方法见 `agent_ssas/docs/zh/tutorial/05-custom-detection-module.md`。

## 6. 决策策略与失败处理

决策策略有两种：

- `observe_only`：默认。只记录，全部放行。
- `active_protection`：critical 时阻断，high / medium / low 告警，safe 放行。

检测引擎自身出错时不拦住调用方，也就是 fail-open。初始化失败、事件格式错误、检测超时都不会让主流程不可用；这是为了把安全观测和业务可用性解耦。注意 fail-open 只覆盖检测链路自身的故障：一旦检测正常产出 critical 结论，`active_protection` 仍会阻断。

## 7. 从这里继续

| 想做的事 | 文档 |
| --- | --- |
| 认识概念 | `agent_ssas/docs/zh/tutorial/01-introduction.md` |
| 在本进程跑通 | `agent_ssas/docs/zh/tutorial/02-quickstart.md` |
| 接入 JiuwenSwarm | `agent_ssas/docs/zh/tutorial/03-integrate-jiuwenswarm.md` |
| 配置字段 | `agent_ssas/docs/zh/reference/configuration.md` |

示例在 `agent_ssas/examples/`。JiuwenSwarm 的接入补丁在 `agent_ssas/patches/`：`jiuwenswarm_ssas_local.patch` 使用本地 `../agent-security/agent_ssas` 路径，`jiuwenswarm_ssas_online.patch` 使用 `agent-security` 仓库的 `develop` 分支。
