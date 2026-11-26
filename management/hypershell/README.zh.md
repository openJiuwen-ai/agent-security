# HyperShell

[English](README.md) | 简体中文

HyperShell 是为 [openJiuwen Agent Security](https://github.com/openJiuwen-ai/agent-security)
准备的受管工作空间与权限治理组件。管理员定义资源上限、角色和用户授权，HyperShell
编译启动计划，再通过 JiuwenBox 启动使用独立 Linux 身份的 JiuwenSwarm 工作空间。

**当前为实验阶段 / Alpha（`0.1.0.dev0`）。** 配置预览可直接运行；真实沙箱需要管理员
准备 Linux 环境。Web 和普通用户 TUI 是演示入口，尚不具备生产多租户服务条件。

## 组件分工

| 组件 | 职责 |
| --- | --- |
| HyperShell | 用户授权、角色模板、工作空间生命周期、策略转换与校验 |
| JiuwenBox | 沙箱执行及操作系统隔离 |
| Agent Shield | 进程内动作判定与内容检测 |
| Agent SSAS | 运行事件采集与威胁检测 |

当前已接入 JiuwenBox 和 JiuwenSwarm；尚未接入 Agent Shield、Agent SSAS。
同一用户内的 Agent/skill 共享外层权限，没有逐 Agent 的内核隔离。

## 快速开始：权限预览

需要 Python 3.11–3.13。先在 agent-security 仓库根目录执行 `cd management/hypershell`，再运行以下命令。

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
python examples/demo/run_demo.py
```

示例验证正常申请、写入只读资源和申请未授权资源三个场景，结果写入 `demo-output/`。
它不会创建系统账号、沙箱或连接模型。示例 Linux 路径是占位数据。
本组件从源码安装，请使用独立虚拟环境；PyPI 上存在无关同名项目，不能按裸包名安装。

```bash
python -m hypershell config validate --config examples/demo/hypershell-roles.yaml
python -m hypershell grants explain --config examples/demo/hypershell-roles.yaml --user u1
python -m hypershell plan --config examples/demo/hypershell.yaml --request examples/demo/request-allowed.yaml --demo-user u1
```

`--demo-user` 只模拟选择用户，不构成认证。预览成功退出 0，配置或授权错误退出 2。
资源登记与用户授权分开；仅添加 `allowed_roots` 不会授予权限。

## 能力与限制

- 严格 YAML 校验、资源上限、角色授权并集、用户限制、配额与权限来源解释。
- Linux 管理员 `start/status/chat/tui/stop/doctor/recover` 生命周期、专用 UID/GID 和私有状态。
- 启动前运行副本校验、策略读回、身份和边界探针；chat/TUI 经受限后端执行。
- Web 管理员配置界面、账号登录、普通用户聊天和认证 TUI 入口；控制面自动监管每用户 Web relay（起停实例自动带起/关闭 Web 入口）。

真实运行依赖 Linux root、JiuwenSwarm、兼容的 JiuwenBox、受信任运行副本和内核隔离能力。
安装本 Python 包不会自动完成部署。网络目前只放行 loopback 和批准的模型公网 IPv4:443，
拒绝直接 DNS 与外部 IPv6。授权变更需要停止并重建实例；Web 特权控制面尚未拆分。
如需在重启后保留 Web 登录会话，请用 `--secret-file` 提供已有签名密钥文件。
没有配置密钥文件且旧版默认密钥不存在时，演示服务使用进程内密钥。

目标仓库本地提交 `1e0b3b9` 的 JiuwenBox 缺少 runner 要求的清理控制接口，当前组合会被
启动检查拒绝。需要完成后端接口适配后才能使用同仓后端运行，详见部署文档。

## 文档与开发

- [文档导航](docs/README.md)：设计文档，以及按任务的配置、部署、运行副本、Web 和测试说明。
- [设计方案](docs/DESIGN.md)：唯一的设计文档，实现边界、组件关系和生产化缺口。
- [安全说明](SECURITY.md)：信任模型和安全问题报告。
- [贡献指南](CONTRIBUTING.md)：测试与提交约定。

```bash
python -m pip install -e ".[dev,web]"
python -m pytest tests -q -ra --basetemp=.test-tmp/pytest
```

`hypershell/` 为 Python 包，`tests/` 为回归测试，`examples/` 与 `scripts/dev/` 提供预览和
实验工具，`docs/` 保留维护文档。实验记录、个人部署材料、凭据和运行产物不属于组件内容。
采用 [Apache-2.0](LICENSE) 许可证。
