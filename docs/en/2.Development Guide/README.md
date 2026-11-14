# Development Guide

This guide covers how to install the components in this repository and which document to read next for each one.

## 1. Documentation map

| Goal | Start with | Content |
| --- | --- | --- |
| Understand what the repository does | [1. Product Overview](../1.%20Product%20Overview.md) | What each of the five components solves and how they cooperate in one tool call |
| Install components on this machine | [Repository and install](Repository%20and%20install.md) | Layout, Python version, local install, and post-install checks |
| Return allow / ask / deny before a tool call | [Agent Shield](Agent%20Shield.md) | Three integration modes, decision flow, native guards on Windows |
| Run commands inside a sandbox | [JiuwenBox](JiuwenBox.md) | Sandbox workflow, Linux / Windows isolation, policy, and API |
| Observe agent runtime behavior and detect threats | [Agent SSAS](Agent%20SSAS.md) | Event flow, two subsystems, detection modules, and decision policies |
| Store API keys and tokens encrypted | [Security Gateway](Security%20Gateway.md) | Schema, DEK / KEK, read/write and rotation flow |
| Mask sensitive spans in streaming output | [Security Mask](Security%20Mask.md) | Token / delimiter concepts, replacement rules, and streaming examples |

## 2. Suggested reading order

1. Read [1. Product Overview](../1.%20Product%20Overview.md) to see what each of the five components solves.
2. Read [Repository and install](Repository%20and%20install.md) and install what you need.
3. Open the page for the component you chose to learn its inputs, outputs, and minimal usage.
4. For rule details, protocols, or deployment specifics, continue with the component's README, design document, and API reference.
