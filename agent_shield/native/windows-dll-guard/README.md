# Windows DLL 用户态防护层

在 Windows x64 上，SDK 通过 DLL Hook 检查受保护进程的文件访问、程序启动和网络请求，并支持运行中的 ASK 审批、临时授权和后台进程管理。防护范围限于被 Hook 捕获的 API 调用，不提供操作系统级强隔离。该能力按需启用，导入 SDK 不会安装 Hook 或启动服务。验证范围见 [验证记录](VALIDATION.md)。

## SDK 与宿主职责

宿主从 `agent_shield.intercepts.native_call.dll_guard` 导入运行时 API 和回调类型。前台工具与后台进程共用一个执行入口，每个会话创建一个 `RuntimeGuardManager`。

| 入口 | 职责 |
| --- | --- |
| `RuntimeGuardManager` | 在工具调用处绑定启动器，按需建立执行，持有前台及后台进程树，处理会话关闭 |
| `RuntimeApprovalRequests` | 按会话、执行和通道关联审批；拒绝过期、错误归属和取消后的回答 |
| `RuntimePermissionEngine` | 使用 SDK 现有 Guard 组件构建独立宿主的有效策略 |
| `HostPolicyAdapter` | 接入宿主已经组合好的有效策略和原生命令身份绑定 |
| `create_process` | 在 `manager.tool_execution(...)` 内把真实进程创建点接入当前执行 |

管理器按需创建底层执行对象，并向同一会话的执行传入自己的审批注册表。宿主可显式传入 `approvals=registry`。从旧接口迁移时，删除构造参数 `directory`，将工作目录通过进程工厂的 `cwd` 参数传入。原先直接创建执行对象并绑定启动器的调用方，改用 `manager.tool_execution(...)` 和 `create_process(...)`。

宿主在可信调用边界提供会话 ID、工具调用 ID、工作目录、策略版本及审批回调，并负责用户界面、传输编码和永久授权存储。进程创建点必须经过绑定的启动器，才能进入注入流程。模型参数和子进程自报信息不能作为可信执行归属。

ASK 会暂停当前资源操作，批准后继续同一进程。拒绝、超时、取消或身份校验失败均不放行，也不会重放工具命令。授权约束包含对象、动作、EXE、argv、cwd 和策略版本，不能覆盖显式 DENY。持久化保存失败与当前一次批准分别处理。

工具返回后仍在运行的后台进程由会话持有，直到进程树结束或宿主关闭会话。宿主在可信工具调用处进入 `manager.tool_execution(...)`，需要按连接取消待答审批时，在该调用上传入 `channel`，断开时调用同一注册表的 `cancel_channel(channel)`。

同一次调用启动多个进程时，策略拒绝只终止本次被拒绝的挂起根进程。即使该异常传出工具上下文，先前已经启动的后台进程仍由管理器回收。Job 归属、注入、就绪握手或清理发生故障时，SDK 会关闭整个执行树。

根进程通过绑定上下文内的 `create_process` 接入。Windows 上首次绑定会注册 CPython 审计钩子。当前上下文内的 `subprocess.Popen` 事件若发生在受保护工厂调用之外，会记录一条不含命令参数的告警。同步 Popen 本身仍无自动防护，未继承上下文的线程和直接调用 Win32 的创建点超出该诊断范围。

### 运行中审批回调

`RuntimeGuardManager` 通过异步回调 `emit(event)` 交付 `RuntimeApprovalEvent`。宿主负责渲染审批事件、投递给用户并解析回答。`approval_timeout` 指定每个请求发出后的等待秒数，默认为 120，投递时间也计入期限。

| 字段 | 含义 |
| --- | --- |
| `request_id` | 此次待答审批的唯一标识，回答时原样交回 |
| `session_id`、`execution_id`、`tool_call_id` | 会话、受保护执行及发起工具调用的归属 |
| `resource` | 实际访问对象，含 `kind`、该类型的操作参数以及 `can_remember`。例如文件访问含 `accesses` 中的路径和动作 |
| `matched_rule`、`reason` | 触发审批的规则和原因，均可能为 `None` |

当 `resource["can_remember"]` 为真，宿主可调用同一包导出的 `scope_options(resource)` 获取可选授权范围。宿主核对回答者的会话身份后，调用 `manager.approvals.resolve(session_id, request_id, PermissionConfirmResponse(...))`。`resolve` 返回布尔值，表示待答请求是否接受了这份回执。缺少 `emit` 时，需要 ASK 的原生操作会被拒绝。

可选的异步回调 `notify(event)` 接收 `RuntimePersistenceEvent`。每次尝试保存授权后，通过 `persisted` 和 `scope`（`session` 或 `permanent`）回报保存结果，并携带 `session_id`、`execution_id`、`tool_call_id`。宿主可据此提示用户保存失败。

### 策略与授权回调

| 构造参数与公开协议 | 调用约定 |
| --- | --- |
| `take_approval` · `TakeApproval` | 同步调用 `(tool_call_id, tool_name, inputs)`。在本次工具调用首次启动进程时读取已批准的 `ApprovalReceipt`，没有回执时返回 `None`。回执包含 `operation`，可带 `accesses`、`grants` 和 `confirmation`。 |
| `program_decision` · `ProgramDecision` | 本地程序判定为 `UNDETERMINED` 时，等待 `(subject, result, *, session, tool_call_id, execution_id)`。宿主从 `ProgramSubject` 读取实际 EXE、argv、cwd 及调用来源，返回 `PermissionResult` 或 `None`。未给出有效决定时进入 ASK。 |
| `persist` · `PersistApproval` | 同步调用 `(session_id, config, grant, *, permanent)`。`grant` 为 SDK 生成的 `ApprovalGrant`，`permanent` 区分永久与会话保存，返回布尔值报告保存结果。 |
| `revision` · `PolicyRevision` | 同步无参调用，返回宿主有效策略的稳定版本标识（字符串或整数）。版本变化会触发策略重新求值和旧授权失效。 |

达到批量删除阈值时，尚未批准的命令需要确认。当前执行和策略版本内，已批准的同一命令及其可确定的 Shell 子进程复用该确认。更换删除目标后按新命令求值。

### 授权复用的默认范围

下表适用于回答同时省略 `authorization_mode` 和 `authorization_scope` 的情况。记住指 `auto_confirm=True`，需要宿主提供 `persist` 回调。显式选择 `exact`，或只指定 `authorization_mode="allow"`，均只覆盖当前对象。

| 审批对象 | 普通批准 | 选择记住 |
| --- | --- | --- |
| 普通文件的读、写或执行 | `parent` | `parent` |
| 含删除动作的文件请求 | `exact` | `exact` |
| URL | `exact` | 有可注册域名范围时取 `domain`，否则取 `exact` |
| 工具层可拆分的 Bash 复合命令 | `exact` | 有可用的 `subcommands` 范围时取该范围，否则取 `exact` |
| 原生程序启动、DNS 名称、数值端点 | `exact` | `exact` |

`parent` 覆盖父目录及其子目录中的相同动作。例如，对盘符根目录直属文件的普通 `exec` 批准，可在本次执行内复用到该盘子目录中的其他 `exec` 请求。每次访问仍先检查当前策略中的显式拒绝。受不可变执行配置或批量删除保护的强制确认使用精确审批，并禁用会话和永久保存。回调可以用 `confirmation` 交接用户的原始答复，旧宿主仅提供文件授权记录时沿用记录中的范围。

运行中的审批绑定到发起时的策略版本。SDK 在收到批准、调用保存回调后，以及调用通知回调后，分别通过同一入口复查执行状态、策略版本和当前资源决定。如果保存只新增本次授权及其组合版本元数据，事务可以继续。其他策略变更、显式拒绝或新的 ASK 规则均使旧回执失效。执行与会话内的授权在最后一次复查通过后写入。宿主保存回调已经产生的外部写入由宿主管理。

受管 Git 沿用宿主的 `CLAW_GIT_EXE`。未设置时使用 SDK 的 `AGENT_SHIELD_GIT_EXE`。仅识别该安装内的已知转发目标，保留原 argv、cwd 和每个程序的策略检查。Git Bash 使用 `GIT_BASH` 或 `GIT_BASH_PATH` 指定。

## 策略与默认行为

实际 EXE、argv 和 cwd 在可信原生上下文中检查。运行时仍按文件策略检查实际的读取、写入、删除和执行权限，显式拒绝优先。可复用 Shell 授权使用已有 Shell AST，保留重定向并校验完整输入；不能可靠分析时只支持精确授权。

`RuntimePermissionEngine` 的可选配置包含私钥目录保护和 loopback allow，显式拒绝优先。已有宿主有效策略应使用 `HostPolicyAdapter`，由宿主管理配置组合。普通 SDK 接口、默认规则、JiuwenBox 默认配置和既有 `native_call.wrap` 协议保持原有行为。

启用文件防护和内置目录表时，Windows 按大小写无关的路径规则保护当前用户的凭据。DPAPI 的 `%APPDATA%/Microsoft/Protect`、本地和漫游的 `Microsoft/Credentials`、主目录的 `.git-credentials` 默认拒绝。对于 `%LOCALAPPDATA%` 下采用 Chromium `User Data` 布局的浏览器，配置目录内的 `Login Data` 和根目录的 `Local State` 也默认拒绝。访问主目录的 `.pypirc`、`.azure` 或 GitHub CLI 的 `%APPDATA%/GitHub CLI/hosts.yml`、`~/.config/gh/hosts.yml` 默认需要审批。自定义凭据文件位置可通过文件策略指定。

启用内置网络规则后，`169.254.169.254`、`metadata.google.internal`、`fd00:ec2::254` 和 `100.100.100.200` 默认拒绝。数值地址规则同时匹配 URL 和带端口的端点。`package_builtin_rules: false` 关闭这份运行时内置策略。

## 原生能力与限制

将公共 SDK 的引擎实例直接传入 `RuntimeGuardManager(..., engine=engine)`，可在每个被注入进程中缓存最多 256 条允许结果。普通 TCP/UDP 端点按协议、数值地址和端口精确匹配，代理请求仍检查目标 URL。仅当编译后的文件规则对所有目标均允许读取时，才缓存本地盘符路径的纯读决定；存在按路径拒绝或审批的读规则时，每次仍解析实际目标。审批回执、写入、执行及删除不会进入进程缓存。

通过 `engine.update_config(...)` 更新策略或调用 `set_permission_checks_active(...)` 时，SDK 在发布变更前同步撤销当前执行树的缓存。该执行随后逐次请求 IPC，新执行可以使用新策略建立自己的缓存。传入可替换的引擎回调、动态启用回调或外部策略版本回调时，也逐次请求 IPC。

文件覆盖打开、删除、截断、重命名和链接目标；目录读取、遍历和元数据查询按 read 检查，文件执行按 exec 检查。网络覆盖 WinHTTP、DNS API、IPv4/IPv6 TCP/UDP、HTTP 代理绝对 URL 和 HTTPS CONNECT，包含分片与散射发送。URL、DNS 和数值端点分别授权，域名许可不会扩大为结果 IP 的通用许可，TLS 证书校验保持生效。

`gethostbyaddr` 按 IPv4 或 IPv6 地址发起 DNS 决策。如果 Windows 随后查询 PTR 名称，该名称也会应用 DNS 策略。`WSALookupServiceBeginA/W` 检查 DNS 命名空间中的名称，以及 `NS_ALL` 下已识别的主机和 TCP/UDP 服务类名称。拒绝时返回 Winsock `WSAEACCES`（10013）。本地蓝牙等其他命名空间不在这项 DNS 覆盖范围内。

### 启动保护与错误处理

对 `connect`、`WSAConnect`、`ConnectEx`、`sendto`、`WSASendTo` 和 `WSASendMsg` 显式传入的目的地址，DLL 使用同一份地址快照完成检查和调用。此保证限于目的地址，代理请求载荷及其他网络参数仍有各自的缓冲区生命周期。子进程启动审批从新建的挂起进程读取命令行，查询失败时终止该子进程。

执行启动时，SDK 先以只共享读取的方式打开 DLL 和同名 manifest，再验证协议、AMD64 PE 头和 SHA-256。SDK 持有这两个文件的句柄，并对解析后的上级目录保持禁止重命名的共享模式，直至后台 Job 和进程清理完成。校验或初始化失败会释放已取得的句柄。安装来源和首次校验时的 manifest 属于部署信任边界，更新文件应安排在相关执行全部关闭之后。

每个执行的命名管道在创建首个和后续实例时均使用受保护的 DACL，只允许宿主进程用户 SID，拒绝远程客户端。首个实例要求独占创建该名称。连接后继续核对内核报告的客户端 PID 和 Job 成员身份。DACL 的隔离粒度为 Windows 用户，同用户进程还需要通过 Job 检查才能请求决策。

宿主可以从 `dll_guard` 导入 `GuardError` 及以下异常类型。

| 异常 | 含义 |
| --- | --- |
| `GuardPlatformError` | 当前宿主不满足 Windows x64 条件 |
| `GuardBundleMissingError`、`GuardBundleError` | 缺少 DLL 或 manifest，或文件锁定、协议、架构、摘要校验失败 |
| `GuardStartupError`、`GuardPipeError` | Job 或就绪事件初始化失败，或无法创建受保护的监听管道 |
| `GuardPolicyDenied` | 根程序启动被策略拒绝 |
| `GuardInjectionError` | 根程序准备、恢复或就绪握手失败；若 Win32 调用失败，可从 `__cause__` 读取底层异常 |

子进程启动失败通过调用进程的 Win32 错误返回。已验证的原因包括 PE 头无效（193）、架构不匹配（216）、导入描述符超过 127 个（214）、ANSI 路径缓冲区不足（122）。策略拒绝仍返回 5。失败时清理尚未放行的进程，实际调用方可在对应边界处理原因。

直接系统调用、预先持有的句柄、未覆盖的 API 以及恶意卸载 Hook 均超出防护范围。Windows Job 用于跟踪和回收受保护进程树。原生执行仅支持 Windows x64，非 Windows 环境可以导入纯配置和授权模块。

## 构建与分发

在仓库根目录执行，工具链目录需提供 `setup_x64.bat`：

```powershell
./agent_shield/native/windows-dll-guard/build.ps1 `
  -ToolchainRoot <MSVC-and-SDK-root> -DetoursRoot <Detours-v4.0.1-checkout> -BuildTestClient
```

脚本不下载依赖，校验 Detours v4.0.1 commit `e4bfd6b03e50de46b47abfbd1e46b384f0c5f833`，静态链接 CRT。中间文件和测试客户端写入 `build/`，发布文件写入可选原生包的 `bin/win_amd64/`。

DLL、测试客户端和静态链接的 Detours 以 MSVC `/W4 /WX /guard:cf` 编译。Detours 使用独立的 CFG 对象目录。DLL 和客户端以 `/GUARD:CF /DYNAMICBASE /NXCOMPAT` 链接。

使用 SDK 时，安装 `agent-shield[dll-guard]` 和配套的 `agent-security-dll` Windows x64 wheel。原生包可单独安装，无 Python 运行时依赖。`agent_security_dll.binary_directory()` 返回安装后的产物目录，供 `native_call.wrap` 和 `dll_guard` 共同使用。原生包包含两套 Guard 的 DLL、配套 EXE、运行时 manifest 和许可文件。源码检出可直接使用构建脚本写入的产物目录。

可选依赖按授权范围降级。缺少 `tld` 或无法读取随包发布的公共后缀列表时，新 URL 审批只提供精确 URL 范围。缺少 `tree-sitter`、`tree-sitter-bash` 或 Bash 语法版本不兼容时，Bash 命令仍可按完整命令审批，子程序按实际启动请求独立检查。安装 `agent-shield[dll-guard]` 可启用域名范围和 Bash 子命令授权复用。

manifest 记录协议、架构、后端版本、DLL SHA256 和 UTF-8/LF 源码哈希。运行时校验哈希与 x64 PE，校验失败会阻止该次执行，不自动无保护重放。哈希用于产物一致性检查，不代替代码签名或安装目录的信任管理。
