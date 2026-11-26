# HyperShell 设计方案

> 本文是 HyperShell 的设计文档（design document）。使用与运维见 [用户使用手册](USER_GUIDE.md)，安全信任模型见 [SECURITY](../SECURITY.md)。

HyperShell 面向 openJiuwen 的受管用户工作空间。当前应用为 JiuwenSwarm，执行后端为 JiuwenBox；当前是管理员 CLI 原型，并带演示级 Web 与命令行 TUI 入口，尚未完成生产多租户验收。

## 运行链路

管理员配置与启动请求 → 权限编译 → LaunchPlan → JiuwenBox 策略 → 创建沙箱 → 策略读回与身份/边界探针 → 启动 JiuwenSwarm。

- 管理员登记资源 ID、可信宿主路径、访问上限、用户身份和配额。请求仅选择资源 ID 和模式，不能提交宿主路径、UID 或原始后端策略。
- HyperShell 与 JiuwenBox 管理进程位于工作负载之外。管理 socket 和状态目录不挂入工作负载。
- 每用户一个持久工作空间、至多一个受管运行实例。整个 JiuwenSwarm 及其子进程位于外层沙箱；同一用户内多个 Agent/skill 共享该用户的外层权限。
- 个人配置、skill、memory、会话和项目持久化；停止实例删除临时执行资源，保留个人数据。
- TUI 由沙箱内受限 daemon 启动 PTY broker 并派生；宿主固定 relay 仅进入对应网络 namespace、
  降权后转发终端字节。TUI 与 chat 复用后端隔离上下文，见 下文的受限 PTY 实现。

## 权限模型

编译器核心使用 `E = B ∩ G ∩ R ∩ T`：组织上限、用户授权、可选个人限制和可选任务限制。未提供的限制层继承；显式空限制层表示无授权。访问级别为 `none < read < read_write`，配额取已设置上限的最小值。

当前 YAML 接入资源 `max_mode`、用户 grants、required、配额；version: 2 增加多角色授权并集和稀疏 `resource_limits`。个人/任务限制及网络资源尚未作为完整配置接口开放。具体语义见 [配置与授权](USER_GUIDE.md)。

超权请求整体拒绝，不静默裁剪；required 不满足时拒绝启动。LaunchPlan 包含稳定摘要。runner 转换后端策略并读回核验，在启动应用前检查真实身份和边界；策略读回不能代替行为测试。

## 执行与信任

- Linux 专用 UID/GID、namespace、只读挂载、Landlock、seccomp 和 cgroup 共同限制工作负载。
- 当前网络 profile 仅允许 loopback 与批准模型公网 IPv4:443，阻断直接 DNS 和外部 IPv6；它不是通用域名代理。
- 管理员配置和 runtime 来源须可信且不可由负载用户修改；`--demo-user` 是预览，`--user` 是管理员选择空间，都不是普通用户登录。演示级普通用户入口（Web 登录、`hypershell-tui` 账号认证）见 [Web 与用户入口](USER_GUIDE.md)。
- 修改授权后需人工停止并重建实例。显式 recover 只处理具备跨开机证据且无相关残留的失效记录，不提供通用自动恢复。

## Web 管理视图

当前 Web demo 由同一管理员进程提供管理和普通用户路由，直接调用 `ManagedRunner`；生产所需的
非特权网关与特权 controller 尚未拆分。页面鉴权、CSRF 与配置编译仍复用现有认证和权限语义。

用户 Web 入口由控制面监管（`web/relays.py` 的 `RelaySupervisor`）：启用 `--relay-port-base` 时，
为每个 `RUNNING` 用户起一个**独立 relay 子进程**（按用户顺序分配端口），`STOPPED` 时停止并回收，
后台周期按 `phase` 收敛以自愈。relay 持可撤销会话租约、不占操作锁，并在首次请求把浏览器 Cookie
交给网关 `/_gate/whoami` 做会话鉴权。relay 必须是独立进程（否则“终止会话”会误杀网关）。当前监管
仍在同一特权进程内实现，跨用户 Web 隔离尚未认证（见 [SECURITY](../SECURITY.md)）。

`web/admin_view.py` 只生成展示数据：默认读取与 Web 启动相同的请求，调用 `AdminConfig.compile`
和 `explain`，展示配置授权与本次预计挂载。它不创建沙箱，JiuwenBox 策略投影不包含 runner
追加的运行时挂载、环境或网络策略，也不代表运行实例的策略读回。

总览将当前授权摘要、启动请求计划与实例启动记录比较，并在角色记录可用时核对角色，提示待重建、
下次启动应用或无法确认。摘要一致只证明这些记录相符，不覆盖运行身份、runtime 配置或完整隔离边界。保存配置会提示可能
受影响的用户，不自动停止或重建实例，也不构成可靠撤权事务。

错误结构的稳定 `code` 定义在 `hypershell/policy/errors.py`，用于 CLI 和 Web 展示；错误中的 HTTP 状态元数据不表示已提供稳定的公共 HTTP API。

安全限制见 [SECURITY](../SECURITY.md)，后续工作见本文末尾，验证方法见 [测试与验证](USER_GUIDE.md)。

## 已观测运行基线

`runner/provenance.py` 记录部署源码、实际应用解释器的后端代码及全部 distribution 版本、内核、
配置/请求和兼容 overlay 指纹。`runner/runtime_baseline.py` 提供管理员显式 capture/check，
保存完整观测旁证并比较稳定投影；未知关键项拒绝采集，默认不覆盖已有参考。

这是一条独立管理检查路径，不自动阻止 runner 启动、改变配置或重建实例。版本元数据和部分代码
摘要尚未覆盖完整运行 payload，也不使源目录自动不可变。范围和验收见 [运行基线](USER_GUIDE.md)。

`runner/runtime_bundle.py` 另行构建并校验完整应用/依赖静态副本；`runtime_trust.py` 只读审计
显式运行树的权限和链接。start、doctor、基线采集和入口验收在 root 执行应用解释器之前必须通过
副本门禁；控制入口本身仍须使用独立可信解释器。副本重建 `jiuwenswarm` / `jiuwenswarm-start` /
`jiuwenswarm-tui` / `jiuwenswarm-web` / `jiuwenbox-server` 固定入口，并随 `jiuwenswarm` 包携带
前端 `dist`。范围、切换和外部信任根见 [运行副本](USER_GUIDE.md)。

## 受限 PTY TUI 执行路径

当前 TUI 通过 JiuwenBox 受限执行进程启动。原先在宿主 `nsenter + setpriv` 后直接执行 TUI 的
路径已删除；聊天与 TUI 都以现有沙箱 daemon 为应用进程的父执行环境。

## 进程与信任边界

```text
管理员 CLI / 已认证普通用户启动器
  → ManagedRunner 持有该用户操作锁确认 RUNNING，并登记可撤销的会话租约
  → JiuwenBox exec_background：启动受限标准库 PTY broker
      → pty.fork → 执行 jiuwenswarm-tui → 连接沙箱内 Gateway
  → 宿主固定 relay：进入该用户 netns、降 UID/GID、清附加组、no-new-privs
      → loopback 认证连接，仅转发终端输入/输出、窗口大小和关闭消息
```

TUI 与 broker 继承后端已经建立的 namespace、cgroup、seccomp 和 Landlock 上下文。
宿主 relay 仅承担传输，没有命令执行接口，仍处于宿主文件系统，因此使用固定源码、隔离标准库
解释器 `-I -S` 和最小环境，不加载工作区代码或调用方 PYTHONPATH。root 协调进程只在附着与
状态检查时短暂持有操作锁；实际 TUI/relay 会话期间由可撤销的会话租约登记，使用配置中的非 root 身份。

## 实现分工

- `runner/terminal_broker.py`：纯标准库源码；在受限后端创建 PTY、启动 TUI、处理帧和清理后代。
- `runner/terminal_relay.py`：固定宿主转发器；保存/恢复终端状态，转发窗口尺寸。
- `runner/terminal_session.py`：后台任务、就绪检测、凭据管道、降权 relay 及任务清理编排。
- `ManagedRunner.tui()` 和 `run_probe("tui")`：共同调用上述路径，探针也经过同一个 PTY 子进程分支。

启动要求实例为 RUNNING，交互模式要求真实终端。必要能力不可用、认证失败或清理无法确认时
报错，没有宿主 TUI 回退。固定会话上限为两小时，空闲超时为五分钟。退出 TUI 不停止工作区；
会话期间不阻塞管理员 stop/recover（见“会话租约与锁模型”）。

## 传输与凭据

broker 只监听所在 netns 的 loopback 随机端口。唯一就绪文件为 0600，只含版本、端口和凭据摘要；
读取检查常规文件、UID、权限及硬链接数。256 位随机凭据经后台 stdin 交给 broker，经独立继承
FD 交给 relay，不进入 argv、环境变量、就绪文件或 HyperShell 审计。错误凭据不启动 TUI 子进程。

帧为四字节网络序长度加 JSON，单帧上限 65536 字节。客户端只能发送输入字节、合法窗口尺寸
或关闭；服务端只能发送就绪、输出和退出码。协议不接受命令、路径、PID 或任意信号。
队列及探针捕获输出均有上限，非法帧和超时终止会话。

## 生命周期

PTY 子进程创建新会话，并在启动前设置父进程死亡信号；broker 必须具备 Linux subreaper
能力，否则拒绝启动。正常退出、关闭、断连、协议错误、TERM/HUP 和会话超时均进入清理：
终止自身 PTY 进程组、回收主进程及领养后代，再删除自身就绪记录。

清理保留尚未回收的 PID 身份，避免对已释放的 PID 再次 killpg；后台任务终止优先发送 TERM，
让 broker 清理后代。最终状态无法确认时记录 `TUI_CLEANUP_REQUIRED` 并报错，不能仅凭杀死
broker 就认为后代全部退出。主机故障或不可处理的强杀仍需管理员核查。

## 会话租约与锁模型

同一用户的短时生命周期操作（start/stop/recover/chat）共用一把按用户的独占 flock
（`ManagedRunner.locked()`）。长时 Web/TUI 会话不再占用该锁，而是各自登记一条**会话租约**：

- 租约写在 `<state>/sessions/<uuid>.json`，字段 `id/kind(web|tui)/pid/user_id/started/last_seen/boot_id/start_ticks`；
  心跳线程每 5 秒刷新 `last_seen`。
- `list_sessions()` 扫描注册表，按 pid 存活（`boot_id`、`start_ticks` 校验）与心跳 TTL（90s）回收僵尸租约。
- `terminate_session(id)` 读取 pid，先 TERM、超时后 KILL，再删除租约；`revoke_sessions()` 终止该用户全部会话。
- `stop()`/`recover()` 先取操作锁、再 `revoke_sessions()`、最后执行停止/恢复，因此管理员不会被长会话挡住。
- `web()`/`tui()` 仅在附着/状态检查阶段短暂持有操作锁，随后只持租约；`_live_state()` 不再要求外层持锁。
- admin 总览注入各用户 `list_sessions()`，展示类型/PID/起始/时长，并提供
  `POST /admin/sessions/{user}/{session_id}/terminate`（复用 CSRF 校验）。

## 实现取舍与后续工作

权限编译与沙箱执行分层，适合作为一级组件维护。当前 runner 通过启动适配器设置
JiuwenBox 的私有 workspace 常量，并检测关闭全局 orphan sweep 的后端契约；这依赖后端
实现细节，不能假设任意版本均兼容。后续应在 JiuwenBox 提供明确的多实例存储配置与生命周期 API，
并建立针对固定版本的集成测试。不要在核心编译器中复制 Agent Shield 或 Agent SSAS 的职责。

| 优先事项 | 完成标准 |
| --- | --- |
| 可复现 Linux 部署 | 参数化安装、固定依赖与兼容矩阵、干净 VM 安装和卸载测试 |
| 特权控制面拆分 | 非特权 Web/CLI 网关通过受限协议调用 controller |
| 可靠撤权与恢复 | 停止旧实例的事务、同次开机崩溃残留处理、并发配置发布 |
| 生产身份与审计 | 登录限速、会话撤销、SSO、外部可信审计 |
| 完整网络与资源支持 | 域名代理/模型网关、配额压力和外部 DNS/IPv6 测试 |
| 可信发布链 | 外部 Python/Node/系统依赖冻结、制品来源认证和升级回滚 |

这些是后续工作，不代表当前已交付能力。当前不承诺通用应用运行、逐 Agent/skill 内核权限，
也没有自动将检测信号接入撤权决策。
