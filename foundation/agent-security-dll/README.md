# agent-security-dll

Process Guard、Runtime Guard 和 JiuwenBox 的独立软删除入口共用原生包。每种架构生成一份 `agent_security_guard.dll`。

## 从源码构建

在 Windows PowerShell 中运行。需要 MSVC 的 x64/x86 工具、Windows SDK 和 Microsoft Detours v4.0.1 的本地 Git 检出。脚本核对固定提交，构建过程中无需下载源码。

```powershell
./scripts/package-source.ps1 -Destination C:/build/guard-source.zip
./scripts/build-windows.ps1 -DetoursRoot C:/deps/Detours -BuildTestClient
./scripts/package-local.ps1 -Destination C:/build/wheels
```

便携 MSVC 可通过 `-ToolchainRoot` 指向包含 `setup_x64.bat` 和 `setup_x86.bat` 的目录。构建默认写入 `build/`，可以用 `-OutputDirectory` 指定输出位置，并给 package-local 传相同的 `-BuildDirectory`。本地 wheel 使用装有 build、setuptools、wheel 的 Python，通过 `-Python` 选择。将该 wheel 安装到 Windows 产品构建环境，并收集 `agent_security_dll/bin`。

## 目录

| 位置 | 内容 |
| --- | --- |
| native/windows/guard | 公共 DLL 初始化、SDK 通信和进程启动配置 |
| native/windows/file、process、network | 文件、进程和网络拦截及参数快照 |
| native/windows/softdelete | 路径与句柄删除、替换目标、回收站、归档和代理客户端 |
| native/windows/launcher | 供 Process Guard 的 wrap 使用的启动器 |
| src/agent_security_dll | 成品位置和清单校验 |
| tests | 构建探针和原生测试源码 |
| third_party | Detours 版本和许可 |

## 启动入口

| 入口 | 启动方式与策略 |
| --- | --- |
| Process Guard | `preflight()` / `wrap()` 使用独立启动器和目标架构的 DLL，沿用 Decide、JSON 记录和 broker 管道。 |
| Runtime Guard | `RuntimeGuardManager.tool_execution()` 由 Windows x64 宿主管理会话管道、Job 和审批，支持 x64 与 WOW64（32 位）根进程和子进程。 |
| JiuwenBox | 沙箱 runner 与本地执行经独立入口启用软删除，box-server 通过同一 DLL 处理回收。x86 工具及其后代使用各自架构的 DLL。 |
