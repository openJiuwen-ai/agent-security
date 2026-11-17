# agent-security-dll

Agent Shield 和 JiuwenBox 使用同一个 Windows 原生包。x64 与 x86 的构建目录各含一份 `agent_security_guard.dll`。Windows x64 宿主的 ProcessGuard.spawn() 支持 x64 与 x86 目标及其后代，按目标位数加载 DLL，共用会话、策略、审计和软删除实现。JiuwenBox 的宿主、runner 和 broker 使用 x64；独立软删除为进程树中的 x86 工具及其后代加载同包对应架构的 Guard。

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
| src/agent_security_dll | 成品位置和清单校验 |
| tests | 构建探针和原生测试源码 |
| third_party | Detours 版本和许可 |

JiuwenBox 的本地执行和沙箱 runner 从 `agent_security_dll.validated_library()` 找到 DLL；box-server 校验请求后调用同一 DLL 的本地回收函数。在 recover 模式下，只有确认回收或归档才返回成功。沙箱代理的查询和重复请求复用操作 ID。

## 公共 native 生命周期与结果

`native/windows/include/guard_lifecycle.h` 定义唯一的有状态入口 `guard_open(const GuardOpenConfig*) -> HANDLE` 和 `guard_close(HANDLE) -> BOOL`。配置包括结构大小、能力集合、recover/permanent、Shield 会话、归档目录和代理绑定。Shield 的会话配置在目标启动前注入，DLL 初始化时通过 `guard_open` 持有自动句柄。JiuwenBox 的 `install_win_soft_delete` 显式打开 recovery 句柄，`uninstall_win_soft_delete` 成对关闭并释放模块引用。runner 的导入式加载和 Git Bash 调试树内的子工具导入准备携带完整、不可变的回收配置 payload，并持有自动句柄。普通 `LoadLibrary` 不安装 Hook，broker 的 `guard_recover_local` 继续作为无状态本地回收执行器。

首次打开确定执行绑定并安装一组 Hook。相同绑定的后续打开返回独立持有句柄并复用注册，归档、代理、会话或删除模式冲突则拒绝。共同启用时须在启动前合并配置，不能先启动 recovery 再追加另一个 Shield 会话。关闭一个句柄保留其他使用者，最后一个句柄关闭时事务卸钩、清理待删除登记、缓存、TLS 和绑定配置。卸钩失败保留句柄供调用方重试。显式最终关闭前调用方应停止使用受保护 API，再调用 FreeLibrary。进程终止时由操作系统释放进程资源。

删除登记时生成 operation_id，保存真实处置路径与最初授权路径，句柄重试关闭、ReplaceFile 内部临时名、策略版本复核和 broker 查询均沿用该 ID。同一策略版本下的关闭复核不重复审批或预留，新版本重新裁决完整资源。MSYS/Cygwin 的 unlink、unlinkat、rmdir、remove 在 POSIX 入口同步调用同一处置器，失败设置该运行库的 errno，不把错误延迟到可能被忽略的 NtClose。目录 fd 复用公共句柄路径解析。取消登记报告 not_executed，成功只结算一次，unknown 保留预留直到执行结束。执行关闭时，已经获准但缺少结果的请求记为 unknown，尚未获准的请求记为 not_executed，已有终态不会重复上报。

对外的审批资源、裁决、授权保存和结果事件统一只提供 `operation_ids: list[str]`。单项操作为 `[id]`，合并审批为所有关联 ID 的去重列表，无关联操作为 `[]`，不再输出单数 `operation_id` 字段。内部删除登记、预留去重和 native 消息仍逐项使用一个 GUID。`result` 记录旧目标处置，`operation_result` 分别记录 `handle_close`、`rename`、`replace` 的实际原生返回状态和错误码，两类单项事件的 operation_ids 均为同一个 `[id]`。关闭成功而回收失败时仍记录关闭成功与回收失败，禁止再次关闭已关闭句柄。旧目标已回收但重命名失败时分别记录处置成功与外层失败。显式备份经文件身份核对后记为 backup。recover 失败或未知始终向调用方返回错误，不回退物理删除。

真实进程回归在仓库的 `agent_shield/tests/intercepts/dll_guard` 和 `jiuwenbox/tests/unit`，本地验证前先使用 `-BuildTestClient`。两个架构的清单均为协议 13，SDK 和 JiuwenBox 的独立软删除共用 `file/file_hooks.c` 的注册表和 `softdelete/softdelete.c` 的处置器。清单声明 Windows x64 宿主、目标架构和能力集合，公共加载器与打包脚本共同核验 PE 结构、架构、摘要、必要导出和 Detours helper 的序号 1。声明支持 x86 时，SDK 在启动前同时锁定并校验 x86 成品。

复合操作同时保留角色与每项实际 access，覆盖目标的 delete 不会被 rename 的 write 替代。关闭时删除在原生打开/创建之前完成授权和登记预留；拒绝时不调用可能创建或截断文件的系统 API。打开本身失败则释放预留。程序审计保留实际映像、解析后的 argv 和原始命令行。`authorization_saved` 的 operation_ids 关联对应裁决、处置和关闭/替换阶段的操作 ID，并携带进程实例身份。

JiuwenBox 独立启用时，`GuardOpenConfig.result_file` 绑定 UTF-8 JSONL 结果文件，或从 `JIUWENBOX_SOFT_DELETE_RESULTS` 继承。绑定与归档、代理一样不可变，子进程沿用同一文件。`collect_win_soft_delete_results()` 一次读取完整新记录，字段包含 kind、operation_ids、pid、status、disposition、os_error、path，以及阶段结果的 phase/native_status。文件在关闭后保留以便读取收尾结果。runner 在现有日志帧中用 `soft_delete_result` 字段转发这些记录；程序 stdout/stderr 不承载审计。独立本地安装未提供路径时创建临时结果文件；调用方可在收集完成后清理该文件。

JiuwenBox 独立启动 Git Bash 时保留调试树，在 CREATE_PROCESS_DEBUG_EVENT、加载器启动前为删除工具准备公共 DLL 导入。准备失败会终止该子进程，DLL 初始化失败由 Windows 加载器阻止程序执行。旧断点 LoadLibrary stub 已移除。只有回收站、归档或绑定代理确认成功，删除工具才获得成功返回。find、脚本的最终退出码仍遵循各自命令语义。

Token/Logon 返回的挂起子进程先通过真实父进程句柄、OS PPID 和 Job 核验，再读取实际 TokenUser SID。该执行的现有与后续管道实例只增加目标 SID 的客户端 I/O 权限，不含创建管道实例权限；就绪通过消息 49 向已核验的 Job 成员复制仅含 EVENT_MODIFY_STATE 的事件句柄，DLL 不再按名称打开就绪事件。宿主保留已核验的进程句柄，用于异账户后代的成员查询与 PID/创建时间审计。管道仍校验 Windows 返回的客户端 PID 和 Job 成员资格，不接受客户端自报 SID。无法读取身份、授权或登记则终止该次创建，不恢复未受保护的子进程。

当前账户 AsUser 的 x86/x64 允许与拒绝已实测；当前账户 WithToken 的四项在具备 SeImpersonatePrivilege 的管理员测试进程中通过。UAC 过滤令牌缺少该权限时，无 DLL 基线返回 1314，对应用例明确跳过。Windows 原生测试在 Linux 按平台跳过。

当前产品验收范围为同一账户的受保护进程树，不要求树内再次切换 Windows 账户。凭据创建 API 仍受拦截，无法核验子进程身份或加入 Job 时拒绝创建，不允许降级成未受保护执行。JiuwenBox 的 box-server→jbx-sandbox runner 身份切换在宿主启动层完成，继续保留；它不依赖 Guard 树内跨账户启动。额外的真实账户、凭据读取、私有桌面验收脚手架已移除。

ProcessGuard.spawn() 的 WOW64 根进程和 x64 父进程启动的 WOW64 子进程均已通过真实文件规则与 PID 验收。跨位数加载复用 Detours 的同位数 helper；会话配置通过 Detours payload 传递。宿主仍要求 Windows x64 和 64 位 Python。

用 `-BuildTestClient` 构建后，在仓库根目录运行以下验收。六个启动场景覆盖两种位数的根进程与 x64→x64、x64→x86、x86→x86、x86→x64 后代。每项要求目标报告实际位数、PID 与创建时间，确认允许文件存在、拒绝文件未创建，并核对规则 ID 和实际目标审计。另有 x86 回收、代理失败与永久删除验收。

同一测试文件中的 `test_x86_session_client_file_policy` 单独验证客户端。它把与 x86 DLL 相同的 Guard 源码编入测试程序，在自身进程初始化 Hook，通过真实会话管道获得文件授权。审计同时核对 Windows 返回的 PID 和创建时间。这个用例不经过 `spawn()`，也不验证成品 DLL 的启动入口。

```powershell
python -m pytest -v agent_shield/tests/e2e_tests/run_windows_process_guard_architectures.py
```

## 迁移验收

| 能力 | 新方案覆盖 |
|---|---|
| 规则 | 100 项操作与原裁决结果、命中规则 ID 对照 |
| 文件 API | x64/x86 真实读取、属性、枚举、写入、目录、复制、移动、替换及链接 |
| 程序 | 真实映像、argv、工具来源、父子关系、PID 与创建时间；ShellExecute 限定 open；凭据 API 返回的子进程登记到原 Job |
| 会话 | 审批合并、版本复核、撤销、后台后代、超时、退出码、清理重试 |
| 删除 | 按任务预留、成功结算、失败释放、未知与去重；回收、归档和代理由公共处置器执行 |
| 交付 | 双架构 DLL、清单校验、源码归档；仓库与 wheel 均移除旧启动器和旧协议 |

Windows 宿主账户的创建进程权限仍由操作系统检查。涉及其他账户和实际凭据的验收需要相应测试账户；测试不使用真实用户密码。JiuwenBox 的独立软删除入口继续保留。
