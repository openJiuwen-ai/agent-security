# Agent Security

English | [简体中文](./README_zh.md)

## Introduction

**Agent Security** is openJiuwen's collection of security capabilities for Agent scenarios. It covers runtime observation, isolated execution, in-process decisions, encrypted storage, and outbound text masking, providing defense in depth for Agents.

The repository currently contains the following components. Each is installed and run on its own, and more capabilities will be added over time:

- **Agent SSAS**: Agent Security Situation Awareness System. It senses Agent behavior in real time through event collection and a pluggable detection-module framework, produces OCSF-format threat reports, supports both in-process and standalone HTTP service modes, and integrates with agent runtimes such as JiuwenSwarm. See [agent_ssas/README.md](./agent_ssas/README.md).
- **JiuwenBox Sandbox**: A lightweight Agent security sandbox service that provides layered isolation for Agent tool calls and code execution on Linux and Windows. See [jiuwenbox/README.md](./jiuwenbox/README.md).
- **agent-shield**: In-process action decisions and content detection, plus two native Windows guards (`process_guard.exe` and `jiuwen_runtime_guard.dll`). See [docs/en/2.Development Guide/Agent Shield.md](./docs/en/2.Development%20Guide/Agent%20Shield.md).
- **Security Gateway**: An encrypted field store library with schema-driven encryption and key rotation. See [security_gateway/README.md](./security_gateway/README.md).
- **Security Mask**: A streaming text masking utility used by web channels to redact matched spans. See [foundation/README.md](./foundation/README.md).

The components are independent and do not have to be deployed together. A common combination is: agent-shield decides before a tool call, JiuwenBox provides the execution environment, Agent SSAS records and detects, Security Gateway stores encrypted credentials, and Security Mask handles outbound web-channel text. If you are new to the repository, start with the [product overview](./docs/en/1.%20Product%20Overview.md).

## Documentation

Chinese and English guides live together under [docs/](./docs/):

- [docs/zh/SUMMARY.md](./docs/zh/SUMMARY.md)
- [docs/en/SUMMARY.md](./docs/en/SUMMARY.md)

## Contributing

We welcome all forms of contribution, including but not limited to:

- Reporting issues and feature requests
- Improving documentation
- Submitting code
- Sharing usage experience

## License

This project is licensed under the [Apache-2.0](./LICENSE) License.

This product serves solely as a workflow orchestration tool and does not embed any AI model capabilities. When users integrate AI models for specific business scenarios, they shall bear full responsibility for compliance obligations under the EU AI Act and other relevant regulatory frameworks.
