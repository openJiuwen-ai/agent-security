# Agent Security

English | [简体中文](./README_zh.md)

## Introduction

**Agent Security** is openJiuwen's collection of security capabilities for Agent scenarios. It focuses on Agent behavior detection, isolated execution, security auditing, and related areas, providing full-chain defense-in-depth for Agents.

This repository currently includes the following components, and more security capabilities will be added over time:

- **Agent SSAS**: Agent Security Situation Awareness System. It senses Agent behavior in real time through event collection and a pluggable detection-module framework, produces OCSF-format threat reports, supports both in-process and standalone HTTP service modes, and integrates seamlessly with agent runtimes such as JiuwenSwarm. See [agent-ssas/README.md](./agent-ssas/README.md).
- **JiuwenBox Sandbox**: A lightweight Agent security sandbox service that provides layered isolation for Agent tool calls and code execution.

## Contributing

We welcome all forms of contribution, including but not limited to:

- Reporting issues and feature requests
- Improving documentation
- Submitting code
- Sharing usage experience

## License

This project is licensed under the [Apache-2.0](./LICENSE) License.
