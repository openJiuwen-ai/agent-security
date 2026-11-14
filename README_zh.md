# Agent Security

[English](./README.md) | 简体中文

## 简介

**Agent Security** 是 openJiuwen 面向 Agent 场景的安全能力合集仓库，覆盖运行过程观测、隔离执行、进程内判定、加密存储与出站文本脱敏，为 Agent 提供全链路的纵深安全防护。

当前仓库包含以下组件。每个组件独立安装、独立运行，后续将持续扩展更多安全能力：

- **Agent SSAS**：Agent 安全态势感知系统（Security Situation Awareness System）。通过事件采集与可插拔检测模块框架，实时感知 Agent 行为并产出 OCSF 格式威胁报告，支持进程内与独立 HTTP 服务两种运行模式，可接入 JiuwenSwarm 等智能体运行时。详见 [agent_ssas/README.zh.md](./agent_ssas/README.zh.md)。
- **JiuwenBox Sandbox**：轻量 Agent 安全沙箱服务，为 Agent 工具调用与代码执行提供分层隔离，支持 Linux 与 Windows。详见 [jiuwenbox/README_CN.md](./jiuwenbox/README_CN.md)。
- **agent-shield**：进程内动作决策与内容检测，并在 Windows 上提供 `process_guard.exe` 与 `jiuwen_runtime_guard.dll` 两套原生防护。详见 [docs/zh/2.开发指南/Agent Shield.md](./docs/zh/2.开发指南/Agent%20Shield.md)。
- **Security Gateway**：加密字段存储库，按 schema 决定字段加密并支持密钥轮换。详见 [security_gateway/README.md](./security_gateway/README.md)。
- **Security Mask**：流式文本脱敏工具，供网页通道把命中片段替换为星号。详见 [foundation/README.md](./foundation/README.md)。

这些组件彼此独立，不要求同时部署。常见的组合是：agent-shield 在工具调用前给出决定，JiuwenBox 提供执行环境，Agent SSAS 负责记录和检测，Security Gateway 保存加密凭据，Security Mask 处理网页通道的出站文本。第一次接触这个仓库，建议先读 [产品简介](./docs/zh/1.产品简介.md)。

## 文档

中英文文档统一放在 [docs/](./docs/)：

- [docs/zh/SUMMARY.md](./docs/zh/SUMMARY.md)
- [docs/en/SUMMARY.md](./docs/en/SUMMARY.md)

## 参与贡献

我们欢迎所有形式的贡献，包括但不限于：

- 提交问题和功能建议
- 改进文档
- 提交代码
- 分享使用经验

## 开源许可证

本项目依据 [Apache-2.0](./LICENSE) 许可证授权。

本产品仅作为流程编排工具，不包含 AI 模型能力；用户在连接 AI 模型用于特定业务场景时，需自行承担欧盟 AI 法案等相关合规义务。
