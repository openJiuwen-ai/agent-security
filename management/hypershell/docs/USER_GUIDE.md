# HyperShell 用户使用手册

本手册面向部署和使用 HyperShell 的管理员与普通用户，涵盖配置授权、Linux 部署与操作、管理员控制的运行副本、Web/TUI 入口与测试验收。系统设计与信任模型见 [设计方案](DESIGN.md) 与 [安全说明](../SECURITY.md)。

## 目录

1. 配置与授权
2. Linux 受管 demo（部署与操作）
3. 管理员控制的运行副本
4. Web 与普通用户入口
5. 测试与验证

---

## 1. 配置与授权


```yaml
version: 1
allowed_roots:
  - /srv/hypershell/users
resources:
  u1.project:
    type: directory
    host_path: /srv/hypershell/users/u1/project
    sandbox_path: /workspace
    max_mode: read_write
users:
  u1:
    login_uid: 1000
    run_as_user: hs-u1
    run_as_group: hs-u1
    grants:
      u1.project: read_write
    quotas:
      cpu: 1
      memory_bytes: 2147483648
      pids: 128
```

`login_uid` 是调用者身份；`run_as_user` / `run_as_group` 是沙箱负载使用的 Linux 身份。读取配置不会创建账户。Linux 上省略 `--demo-user` 时，使用 `os.getuid()` 的真实 UID 映射用户，不从请求文件接受身份。`--demo-user` 仅模拟选择配置，输出标记 `simulated: true`，不构成认证。

资源 `max_mode` 形成管理员上限，用户 `grants` 形成授权；请求必须同时满足两者。`required` 可声明此用户实例必需的资源，遗漏时拒绝。顶层和用户 `quotas` 取最小值。

路径必须是规范化的绝对 Linux 路径；拒绝根目录 `/`、路径中的 `..`、重复 YAML 键、未知字段、未知版本、非正数配额、非整数内存/进程数、root 运行身份及超出资源上限的管理员授权。资源访问模式为 `none / read / read_write`。

第一版配置支持 file/directory 资源及 CPU、内存、进程配额。CPU 范围为 0.00001–1024，整数配额最大为 2^53。网络资源、磁盘配额和自定义应用尚未接入配置层。

配置来源的信任由调用环境负责：普通用户自行提供 YAML 只能做预览。特权运行入口必须从管理员拥有的固定位置加载配置，并检查目录实际归属、符号链接、运行 UID/GID、内核和网络边界。plan 输出只是工作负载资源投影；Linux demo 另有启动和边界验证，但生产不可变运行包仍未完成。


### 角色模板与个人追加授权

角色配置从 `version: 2` 起可用，旧 `version: 1` 配置保持兼容。角色定义和用户绑定
都放在管理员拥有的配置中，普通用户不能通过启动请求给自己分配角色。

### 配置

保留原来的 allowed_roots、resources 和用户身份字段，资源 ID 必须提前登记。

```yaml
version: 2
roles:
  employee:
    description: 公共知识库
    grants:
      company-knowledge: read
users:
  u1:
    login_uid: 1000
    run_as_user: hs-u1
    run_as_group: hs-u1
    roles: [employee]
    grants:
      u1.state: read_write
      u1.home: read_write
      u1.project: read_write
      desktop-project: read_write
    resource_limits:
      desktop-project: read
    required:
      u1.state: read_write
      u1.home: read_write
      u1.project: read_write
```

完整的本地预览配置见 `examples/demo/hypershell-roles.yaml`；其中 Linux 路径是示例，
不能直接替换 VM 的实际配置。

- 多角色和直接 grants 取更高访问级别；用户直接写 read 不会降低角色给出的读写权限。
- resource_limits 对全部授权来源生效：read 为只读上限，none 为禁止；未列出的项继承。
- resource_limits 不能新增授权。角色/直接 grants 只接受 read/read_write；禁止访问时使用 limits 中的 none。
- 删除角色只移除该角色贡献，其他来源仍有效。角色采用引用，每次重新加载配置重新计算。
- 原始授权超过资源 max_mode、角色未知/重复、未知字段、required 不满足均拒绝配置。
- 限制不能通过重叠父目录、子目录或路径别名绕过；发现模式冲突即拒绝。
- 角色只管理已接入的文件/目录资源；配额保持顶层与用户取最小值，角色暂不支持配额和继承。
- 公共角色应引用共享只读资料。私人 state/home/project 保持每用户独立，不支持跨用户共享可写目录。

### 校验与权限解释

```bash
python -m hypershell config validate --config examples/demo/hypershell-roles.yaml
python -m hypershell grants explain --config examples/demo/hypershell-roles.yaml --user u1 --resource desktop-project
```

explain 输出 sources、granted、limit、effective 和 authorization_digest，说明授权来源和
限制结果。它是配置查询，不表示实例已经重新应用了这些权限，也不构成身份认证。
管理员可在 VM 使用 `sudo hypershell-demo` 代替 `python -m hypershell`。
启动状态保存角色绑定与授权摘要，旧实例没有这些字段仍可正常停止。

### 应用变更

1. 保存当前有效配置备份，在暂存配置中修改角色/绑定/grants/limits，执行校验和解释。
2. 新增资源时更新对应 request-USER.yaml；降低或禁止资源时同步降级/删除该请求项。
3. 使用仍可解析旧用户的有效配置停止受影响实例，确认停止成功，再发布新配置。
4. 启动新实例并检查策略与实际访问。失败时保持停止，不自动恢复旧的高权限实例。

VM 示例：

```bash
sudo hypershell-demo config validate --config /etc/hypershell-demo/admin-next.yaml
sudo hypershell-demo grants explain --config /etc/hypershell-demo/admin-next.yaml --user u1
sudo hypershell-demo stop --user u1
# 发布已验证的配置及对应请求文件后：
sudo hypershell-demo start --user u1
sudo hypershell-demo status --user u1
```

修改文件不会改变旧沙箱挂载，也无法收回用户已经读取或复制的数据。当前采用人工停止/
重建流程，自动热更新和可靠撤权事务仍待实现；Web 已提供配置影响提示。


---

## 2. Linux 受管 demo

当前实现可在 Linux 中通过 JiuwenBox 启动独立 JiuwenSwarm。它仍是实验部署流程，尚无面向新服务器的通用安装器。首个基线使用 Ubuntu 20.04、Linux 5.15、Python 3.11；不表示这些版本构成完整支持矩阵。

### 运行要求

#### 后端兼容性

当前 runner 要求 `jiuwenbox.supervisor.network` 提供
`ENV_SKIP_ORPHAN_NET_CLEANUP` 和 `cleanup_orphaned_uplinks`，并支持关闭全局清理。
整理时核对的 agent-security 本地提交 `1e0b3b9` 中没有这两项接口，不能直接将同仓
JiuwenBox 当作已经适配的运行后端。`start` 的契约检查会拒绝此组合，不应绕过检查。
需要先与后端对齐多实例存储与清理接口，再验证固定版本的完整生命周期。
配置预览和默认回归不依赖 JiuwenBox，因此仍可独立运行。

#### 系统与运行环境

- root 管理员、支持当前 JiuwenBox 所需 namespace/Landlock/seccomp/cgroup 与 IPv4/IPv6 防火墙的 Linux 环境。
- 已准备的 JiuwenSwarm、JiuwenBox、应用解释器及依赖、Node 和模型连接配置。
- 已验证的管理员运行副本，以及独立 root 控制的管理端解释器。
- 专用非 root 负载账户，可信管理员配置目录与各用户持久目录。
- JiuwenBox 版本需支持 runner 使用的多实例存储及关闭全局 orphan sweep 契约。

`examples/demo/install_vm_demo.py` 是固定实验布局的安装器：源码中以 `/home/demo` 等占位路径表示特定源码、venv、模型配置及系统依赖，会创建账户、复制配置并安装包装命令。使用前必须逐项审阅和适配；不要在陌生服务器直接 sudo 执行。它不是已参数化的社区安装方案，重装前必须停止已有实例并备份数据。

安装器现在必须传入 `--runtime-bundle /opt/hypershell-releases/release-001`
和 `--control-python /opt/hypershell-control/bin/python`；它先验证副本与控制端树，管理包装器不再
从旧应用 venv 引导 root。控制端 venv 需独立准备 HyperShell 依赖；安装器本身也应由已批准的
解释器和 root 控制的源码运行。既有部署不会自动升级。

### 启动链路

1. 检查管理员配置、真实 UID/GID、资源归属及可信路径。
2. 编译 LaunchPlan，通过私有 Unix socket 创建 JiuwenBox 沙箱。
3. 读回并对比策略，安装只允许 loopback/批准模型 IPv4:443 的网络规则。
4. 检查身份、capabilities、文件边界后，在沙箱内启动 JiuwenSwarm。
5. chat 在沙箱内执行客户端；TUI 由受限后端 daemon 派生 PTY，宿主仅降权转发，连接实例 Gateway。

管理进程和 socket 留在负载之外。个人 data/home/project 持久化，停止实例保留数据。运行权限当前以用户为单位，不提供逐 Agent/skill 的独立内核权限。




### 使用已经部署的实例

以下 `hypershell-demo` 是实验安装器生成的包装命令；安装 Python 包提供的命令为 `hypershell`。包装命令还选择特定应用解释器和代码路径，不能仅安装本包就假设其存在。

```bash
sudo hypershell-demo doctor --user u1
sudo hypershell-demo status --user u1
# 仅在 STOPPED 且部署配置已准备时启动：
sudo hypershell-demo start --user u1
sudo hypershell-demo chat --user u1 --session first-use '只回复你好，不调用工具'
sudo hypershell-demo tui --user u1
```

TUI/Web 会话登记为可撤销的「会话租约」，不再长期占用操作锁，因此管理员仍可在用户使用中执行 stop/recover（会先撤销会话）。退出 TUI 不停止实例。直接运行原版 TUI 不会自动连接受管空间；chat 等短时操作仍与 start/stop/recover 共用操作锁。

`--user` 是管理员选择空间，不是用户登录认证。双用户用法见下文「多用户配置与生命周期」一节。

### 配置与权限变更

| 文件 | 内容 |
|---|---|
| /etc/hypershell-demo/admin.yaml | 资源、身份、授权、必需资源与配额 |
| /etc/hypershell-demo/runtime.yaml | 可信应用代码/解释器、状态目录、模型网络和依赖 profile |
| /etc/hypershell-demo/request-USER.yaml | 对应用户本次启动选择的资源 |

配置与父目录由 root 控制，不能由负载用户修改。管理员多用户 CLI 不会回退使用单用户
`request.yaml`；Web 的启动与预览优先使用同目录的 `request-USER.yaml`，不存在时回退到
`request.yaml`。请求只接受资源 ID 和模式，不能提交宿主路径、UID 或后端策略。

角色与个人限制、校验及撤权步骤见 「配置与授权」一节。当前必须人工停止、发布已验证配置及请求、再启动；只改 YAML 不会撤销旧实例权限。必需的 /data、/home/agent、/workspace 当前都要求可写。

```bash
sudo hypershell-demo stop --user u1
# 发布已验证的新配置和请求后：
sudo hypershell-demo start --user u1
sudo hypershell-demo status --user u1
```

失败时不自动恢复旧高权限实例。stop 保留个人数据，start 创建新沙箱。

#### Web 管理界面核对

在 `/admin/config` 编辑 YAML，校验通过后可查看可能受影响的用户；保存会备份并记录审计，
不会停止或重建实例。删除用户配置也不会停止其旧实例，应在删除前停止该实例；已经删除时需
使用备份配置核查并处理旧工作区。角色绑定页的保存同样不热更新实例。

总览 `/admin` 显示状态说明、诊断和配置应用提示。`RUNNING` 可停止，`STOPPED` 可启动，
`LOST` 可“检查并恢复”；`ERROR` 和 `ERROR_CLEANUP_REQUIRED` 可在查看诊断后“尝试停止”，
仍由 runner 检查是否可安全清理，拒绝时需管理员核查。其他异常先查看诊断。
停止与恢复有确认提示，恢复成功后仍需手动启动。
`/admin` 另有「活跃会话」表，列出各用户当前的 TUI/Web 会话（类型、PID、起始时间、时长），可逐条「终止」；终止走服务端会话撤销（SIGTERM，超时 SIGKILL），不受长会话阻塞。
“待重建”来自当前授权、角色或启动请求计划与启动记录的差异；记录缺失或请求不可编译时，
不能认定配置已应用。“一致”也只核对授权与启动计划，不证明运行身份、runtime 配置或完整隔离边界。

`/admin/preview` 默认按 Web 的实际启动请求预览，逐资源显示授权来源、个人限制、本次申请和
预计挂载；请求缺失或越权会报错。“全部可申请权限”用于检查配置授权，不表示资源都会挂载。
预览不创建沙箱，不包含 runner 附加的运行时挂载、环境与网络配置。

### 状态与恢复

RUNNING 还需核对 observed_app.running 及引擎结果。STOPPED 表示未运行；LOST 表示引擎身份失效；ERROR 表示引擎查询或应用异常。status 只读，非健康状态返回 ok=false 和退出码 1。配置/授权/runner 错误通常返回 2。

机器重启后，确认旧实例失效、无相关进程及资源残留时：

```bash
sudo hypershell-demo recover --user u1
sudo hypershell-demo start --user u1
```

recover 备份旧状态并恢复为 STOPPED，start 才创建新实例。同次开机引擎丢失或存在残留时拒绝恢复，不执行整机清理。旧格式记录迁移要求管理员独立确认重启，详见 「多用户配置与生命周期」一节。

### 数据、日志与排错

默认每人的项目、配置、skill、memory 和会话位于 `/srv/hypershell-managed/USER/`。管理记录、策略、引擎 socket 与管理审计位于 `/var/lib/hypershell-managed/USER/`；实际位置以 runtime 为准。

备份整个用户 data/home/project 与管理配置，不只复制单个 SQLite 主文件。Agent 轨迹在用户可写数据中，不是不可篡改审计。

doctor 只检查运行环境和文件锁兼容性，不证明隔离已经生效。SQLite 实验兼容方式见 「管理员控制的运行副本」一节。安装限制见 本手册「Linux 受管 demo」，验证方法见 「测试与验证」，安全缺口见 [SECURITY](../SECURITY.md)。

### 多用户配置与生命周期


- `/etc/hypershell-demo/admin.yaml`：两个用户及授权、共享只读知识库。
- `/etc/hypershell-demo/runtime.yaml`：用 `state_root: /var/lib/hypershell-managed`
  自动形成每用户状态目录。`state_root` 与旧 `state_dir` 必须二选一；旧字段只允许单用户配置。
- `/etc/hypershell-demo/request-u1.yaml`、`request-u2.yaml`：各自默认启动请求。
  `--request` 可显式指定文件；多用户配置不会回退到单用户请求文件。
- `/srv/hypershell-managed/u1/`、`u2/`：root 管理父目录；其中 data/home/project
  归各自运行用户所有，目录权限为 0700。
- `/var/lib/hypershell-managed/u1/`、`u2/`：root 私有的 instance.json、engine.sock、
  lock、policy.json、管理和引擎审计。
  引擎实际的 policies/sandboxes/workspace 位于各自的 `engine-home/`，通过启动适配器
  在载入 JiuwenBox 消费模块前设置路径；不能只设置 HOME，后端会忽略它。

启动前解析所有运行账户的实际 UID/GID，拒绝 root、缺失账户、UID/GID 别名，以及
跨用户重叠的可写资源树。允许共享只读知识库。当前 demo 不支持共享可写协作目录。

### 网络与生命周期

JiuwenBox 的全局 orphan sweep 假设整机只有一个管理服务，可能终止另一个工作空间。
runner 检查该版本支持 `JIUWENBOX_SKIP_ORPHAN_NET_CLEANUP`，为受管引擎设置此变量，
只通过指定 sandbox ID 执行正常清理。缺少此契约时拒绝启动。
创建/删除沙箱及安装防火墙通过 `/run/hypershell/network.lock` 串行，避免后端未加
`iptables -w` 的操作发生 xtables 锁竞争；应用运行、聊天和各自 TUI 仍可并发。
整机其他自行启动的 JiuwenBox 服务也必须避免执行全局 sweep；本 runner 无法约束外部
管理员启动的服务。重启后可用下述 recover；同次开机内崩溃的孤儿自动清理仍待完成，不应执行整机清理来停止某一用户。

#### VM 重启后恢复

`status` 会将引擎身份失效的实例显示为 `LOST`，返回 `ok: false`、退出码 1，
不会把旧状态文件中的 RUNNING 当作实际存活。引擎查询失败显示 ERROR。

```bash
sudo hypershell-demo status --user u1
sudo hypershell-demo recover --user u1
sudo hypershell-demo start --user u1
```

recover 只归档上次开机的失效记录并恢复为 STOPPED；start 才创建新实例。
每个新实例记录 boot ID、generation 与引擎进程启动时间。恢复持有用户锁和宿主网络锁，
拒绝仍存在的相关进程、绑定 socket、namespace、veth 或 cgroup；保留个人数据和另一用户。
旧状态原文备份到该用户状态目录下 `recovery-<id>.json`，审计记录准备和完成事件。
重复 recover 对 STOPPED 无操作。检查或备份失败时不宣称恢复完成。

首次迁移的旧实例没有 boot ID。管理员独立确认 VM 确实重启、记录未在本次开机修改后，
可用 `recover --user u1 --legacy-after-reboot`；该选项还检查状态文件 mtime/ctime 早于本次
开机时间。时钟证据有疑问时停止恢复并人工调查。新实例不需要此参数。
同次开机内引擎丢失、存活实例及残留资源一律拒绝恢复，不会杀掉未知进程或执行整机 sweep。
没有配置开机自动启动，也没有实现生产控制面的自动重试、调度或撤权事务。

在应用启动前，runner 在各自 netns 安装 `HS_OUTPUT` / `HS_INPUT` 链并置于引擎规则前：
允许内部 loopback 和已批准公网模型 IPv4 的 TCP 443，拒绝其他外部流量；IPv6 只允许
loopback。直接 DNS TCP/UDP 53 同样拒绝，模型使用启动时的只读 hosts 快照。
所需 IPv4/IPv6 防火墙无法安装时清理并拒绝启动。当前不支持绕过 runner 热更新引擎策略。

这是一种窄模型网络 profile：搜索、远程 MCP、新模型域名不会自动放行。生产域名代理、
模型网关、凭据托管和网络变更事务尚未实现。


---

## 3. 管理员控制的运行副本

`runner/runtime_bundle.py` 为当前 Linux / Python 3.11 实验布局提供
静态运行副本：将已批准的应用源码、Python 依赖和应用静态资源复制到全新的 root 管理目录，
重建 editable 导入与固定入口，并生成完整 payload 清单。它不安装依赖，不运行输入代码。

### 解决的问题

root 引擎启动前会加载应用解释器的 site 初始化和 JiuwenBox。仅把 runtime.yaml 设为 root
所有，并不能阻止普通账号修改源码、虚拟环境或 editable 指向的包。只检查 `/opt/node20`
顶层也不够：子目录可能仍属于解压归档时的普通 UID。

新版本在 `start` 的后端契约检查、`doctor`、运行基线采集和入口验收调用应用解释器之前，
要求 `runtime_bundle` 校验通过且 source / Python / Node 路径与清单一致。缺少副本、payload
漂移或路径不匹配均拒绝执行。`status`、`stop` 和现有实例的受限执行路径不要求重新启动应用，
因此仍可诊断和停止旧实例。该检查不会升级或停止其他部署。

控制命令本身必须先由**独立、管理员控制的解释器**启动。旧包装命令若仍使用普通账号可写的
应用 venv，Python 内的门禁来不及保护其 `.pth` 初始化。固定实验安装器现在要求显式传入
`--control-python` 和 `--runtime-bundle`，生成清空调用者环境的控制入口。不要继续使用旧包装器
去执行新版本管理操作。

### 构建

以下均是部署路径示意，先准备 root 控制、无符号链接的发布父目录。输入应来自管理员批准的、
停止修改的安装树。工具不会判定输入代码是否可信，也不会自动识别任意文件中的秘密。
不要把用户数据目录作为输入。

```bash
sudo /opt/hypershell-control/bin/python -P -B -m hypershell.runner.runtime_trust \
  /opt/python3.11 /opt/node20-approved

sudo /opt/hypershell-control/bin/python -P -B -m hypershell.runner.runtime_bundle build \
  --source /srv/approved-jiuwenswarm \
  --destination /opt/hypershell-releases/release-001 \
  --python-prefix /opt/python3.11 --node-prefix /opt/node20-approved \
  --package gateway=gateway \
  --package jiuwenswarm=jiuwenswarm \
  --package jiuwenbox=jiuwenbox/src/jiuwenbox \
  --package jiuwenswarm_tui=packages/jiuwenswarm-tui/jiuwenswarm_tui

sudo /opt/hypershell-control/bin/python -P -B -m hypershell.runner.runtime_bundle verify \
  /opt/hypershell-releases/release-001
```

`--package` 必须恰好覆盖输入安装树的全部受支持 PEP 660 literal mapping；namespace editable、
legacy egg-link、未知路径钩子或与已安装同名包的遮蔽冲突会被拒绝。源码包保持原相对布局，
因此保留 TUI 按仓库根定位 `frontend/dist` 的行为；前端 `channels/web/frontend/dist` 随
`jiuwenswarm` 包一并复制，Web 入口所需的 `jiuwenswarm-web` 启动器也由工具重建。
Node 依赖及其他非 Python 资源也纳入复制。

默认拒绝硬链接输入。uv 等安装方式可能让依赖与缓存共享 inode；确认输入已经获得批准后，
可以显式增加 `--copy-linked-inputs` 按值复制。输出文件始终是独立 inode；此选项不让输出继承
硬链接，也不放宽输出属主和权限检查。

构建中使用 FD / `O_NOFOLLOW` 检查、流式读取和变化检测，拒绝特殊文件；有条目、深度、字节
和清单大小预算。site-packages 不接受链接。源码包允许仅指向同一复制包树内的相对链接，
完成前审计其实际闭包；缺少目标、逃逸或循环会拒绝发布。输出目录独占创建，完成前保持私有，
已有目标直接拒绝。失败只清理本次创建的目录，不支持原地覆盖运行版本。

旧 editable finder / 钩子被静态解析后移除，以数据型相对 `.pth` 重建；仅保留精确匹配的
setuptools distutils 兼容钩子。venv 关闭 system-site-packages，仅重建当前所需的固定 CLI 入口：
`jiuwenswarm`、`jiuwenswarm-start`、`jiuwenswarm-tui`、`jiuwenswarm-web`、`jiuwenbox-server`。缓存、版本库、`direct_url.json`、`.env` 和 `.env.*` 不复制。应用初始化需要的
`jiuwenswarm/resources/.env.template` 由工具生成为空模板，不继承原模板值；每个工作区的
模型设置须由管理员另行配置。副本不支持整体改名或搬家，入口 shebang 固定为发布路径。

### runtime 配置与切换

```yaml
version: 1
state_root: /var/lib/hypershell-managed
runtime_bundle: /opt/hypershell-releases/release-001
source_dir: /opt/hypershell-releases/release-001/source
python_prefix: /opt/python3.11
node_prefix: /opt/node20-approved
model_host: model.example.org
landlock: hard_requirement
# dependency_overlay: /opt/hypershell-demo/compat
```

完整 YAML 的身份、授权和资源规则见 「多用户配置与生命周期」一节。应用的 Python 基础 prefix、
Node prefix 和可选兼容 overlay 必须分别受管理员控制。静态审计逐项检查全部祖先、属主、写权限、
文件类型与链接，不能用一次顶层 `chown` 代替。应用和引擎禁止生成字节码，隔离检查子进程
使用相应的 `-B`；后端契约子进程还使用 `-I` 排除调用者当前目录。

切换前备份管理员配置和各用户持久数据；在独立空间完成启动、入口和清理验收后，再停止待迁移
实例、更新可信 runtime 路径并重建。保存配置不切换正在运行的引擎。不要覆盖旧 release；回滚
使用保留的旧配置/副本与显式重建。当前没有升级事务、自动迁移或跨版本数据兼容承诺。
新路径使 runtime 字节指纹发生变化，需重新采集 「已观测运行基线」一节。

JiuwenBox 的 daemon 使用 Unix socket，实验状态根应保持简短，例如 `/var/lib/hs-runtime`。
较深路径可能在外部后端派生 socket 名后超过 Linux AF_UNIX 限制；此时创建失败，runner 会清理
本次实例。创建响应中的 id 不证明 daemon 已就绪，runner 还要求后端状态为 `ready` 才继续安装网络规则。

`runtime_trust` 退出码：0 可信、1 不可信、2 未完整检查。`runtime_bundle` 退出码：0 构建成功/
校验一致、1 payload 漂移、2 输入/权限/格式错误。库入口失败抛 `RunnerError`。

### 范围

清单覆盖副本内路径、类型、权限、文件大小、全部文件 SHA-256 和链接目标，包含依赖 payload、
原生扩展、应用 JS 与静态资源。Python 基础 prefix、Node 和操作系统库仍是外部信任根；
它们接受静态权限审计，没有被纳入此副本的内容冻结。控制解释器与 HyperShell 控制代码也独立管理。

这是同一主机 / Python ABI 上的静态安装快照，不是从干净机器重建的依赖 lock、签名制品或
内核强制不可变文件系统。root 仍能修改副本及其清单；检查与执行之间没有原子绑定。
邻接清单的 SHA 用于检测漂移，不提供来源认证。完整可复现构建、可信发布链、外部依赖冻结、
自动升级/回滚和生产控制面仍待实现。


### 已观测运行基线

运行基线将指定部署中可观测的代码、依赖版本、解释器、内核、配置和兼容 overlay 身份保存为
可比较的指纹。后续 `check` 重新采集同一范围并报告差异，用来发现运行环境相对基线发生的变化。

它与 「测试与验证」中的执行入口边界验收 的作用不同：基线检查比较环境身份，
边界验收测量进程和行为。基线一致不代表隔离验收通过；边界验收通过也不代表环境已被冻结。

### 采集基线

在部署主机上由管理员执行，使用实际控制端解释器，并从当前部署的 HyperShell 代码加载工具：

```bash
sudo PYTHONPATH=/opt/hypershell-demo /path/to/control/python \
  -m hypershell.runner.runtime_baseline capture \
  --config /etc/hypershell-demo/admin.yaml \
  --runtime /etc/hypershell-demo/runtime.yaml \
  --users u1 u2 \
  --output /var/lib/hypershell-managed/runtime-baseline.json
```

`capture` 只读配置、代码和解释器元数据，将已知的稳定字段保存为基线；遇到关键字段缺失、
未知或采集不完整时拒绝建立基线。明确的 `not_installed` 是已观察到的缺席状态，允许保存并
参与比较；它与 `unknown` 不同。未启用 overlay 也会作为明确状态记录。

输出父目录须已存在并由管理员控制，不能被工作负载用户写入。默认拒绝覆盖现有基线。
默认发布以同目录临时私有文件加原子 no-clobber 操作完成；并发采集同一新路径只允许一个胜者。
有意重新建立基线时，使用相同命令并显式增加 `--replace`；应先保留需要对照的旧版本和
差异报告，再替换参考值。替换基线只更新参考文件，不会修复当前部署或应用新权限。

请求默认按所选用户读取管理员配置同目录的 `request-<user>.yaml`。使用其他请求文件时，
在 `capture` 和后续 `check` 中指定同一选择：

```bash
--request u1=/etc/hypershell-demo/request-u1.yaml \
--request u2=/etc/hypershell-demo/request-u2.yaml
```

用户及请求集合属于基线范围；只采集 `u1`、`u2` 不能宣称其余用户的请求也已固定。

### 检查漂移

```bash
sudo PYTHONPATH=/opt/hypershell-demo /path/to/control/python \
  -m hypershell.runner.runtime_baseline check \
  --config /etc/hypershell-demo/admin.yaml \
  --runtime /etc/hypershell-demo/runtime.yaml \
  --users u1 u2 \
  --baseline /var/lib/hypershell-managed/runtime-baseline.json \
  --output /var/lib/hypershell-managed/runtime-baseline-check.json
```

`--baseline` 指向已保存的参考文件；`--output` 是可选的检查报告路径。检查重新观察当前环境，
验证输入结构和摘要，再比较稳定指纹。发现差异时报告变化项，不改配置、代码、依赖或原基线，
也不会自动将当前环境“接受”为新基线。

此工具不创建 `ManagedRunner`，不要求实例处于 `RUNNING`，不启动、停止、恢复或重建实例，
不创建边界验收 fixture，也不连接模型服务。检查未通过时，应按差异定位原因，不能通过
反复覆盖基线代替处理意外变更。

| 退出码 | 含义 |
|---|---|
| `0` | 基线采集成功，或当前稳定指纹与基线一致 |
| `1` | 检查发现漂移；参考值与当前观测存在明确差异 |
| `2` | 参数、权限、基线格式/摘要错误，或关键观测未知、不完整，无法完成采集或比较 |

关键值未知不会按“相等”处理。检查失败与环境确实漂移应分别解读，不能把工具执行错误写成
某项安全边界已通过或已失效。

### 稳定指纹范围

| 项目 | 固定内容 |
|---|---|
| HyperShell / 应用源码 | 受采集范围约束的代码哈希，以及代码清单范围的摘要 |
| JiuwenBox 后端 | 实际后端代码清单的哈希及其范围 |
| 依赖元数据 | 应用解释器观察到的全部 distribution 版本集合摘要；另固定六个重点包的安装状态与版本 |
| 解释器 | 应用和控制端 Python 的版本与实现 |
| 系统 | 操作系统、内核版本和架构身份 |
| 配置 | 管理员配置、runtime 和所选各用户请求文件的 SHA-256 |
| 兼容 overlay | 明确的未启用状态，或已配置 overlay 的类型与内容摘要 |

六个重点包为 `jiuwenbox`、`jiuwenswarm`、`openjiuwen`、`PyYAML`、`filelock` 和
`pysqlite3-binary`。版本集合摘要可以发现新增、移除和版本变更；显式缺席状态也会比较。
源码清单涵盖的扩展名、包根目录和排除项属于范围定义，不能省略范围后将摘要解释为整台主机的哈希。

基线不直接比较原始 observed manifest 的总摘要。采集时的源码绝对位置、Git 仓库根、
Git dirty 状态、控制解释器暂存路径等信息可能随部署或采集方式改变；它们可以作为旁证，
但不应污染稳定内容指纹。报告时间、run ID、PID、开机 ID、sandbox ID 和 namespace inode
也不属于环境基线。配置文件本身仍按原始字节计算哈希，其内部路径、注释或排版变化都会改变配置摘要。

基线和检查报告使用严格 JSON、结构及摘要验证。摘要可以发现文件内部不一致，不能证明文件
来自可信发布者；参考文件本身仍须由管理员控制，不能交给被测工作负载维护。
基线同时保存完整 observed manifest 作为旁证，并校验其与稳定指纹一致。检查输出不能覆盖
参考基线、管理员配置、runtime 或所选请求文件；采集覆盖已有基线必须显式使用 `--replace`。
输出还必须位于被测源码、后端代码、overlay、Python/Node 运行目录和控制解释器目录之外。
建议始终使用独立的管理员报告目录。缺少新代码/依赖观测字段的历史 manifest 不能直接冻结为完整基线。

### 当前边界

采集/检查现在还会在执行应用解释器前校验 runtime 的 `runtime_bundle`。旧的用户可写源码
runtime 不能继续以 root 采集；需先准备「管理员控制的运行副本」一节。这项门禁独立于
基线稳定投影，历史采集记录不代表已完成副本迁移。

这是 **observed 范围的参考基线**，尚不是可复现安装的依赖 lock、不可变运行包或签名发布证明。
采集过程不安装或锁定依赖，也不阻止比较完成后环境再次变化。

全部 distribution 版本集合属于元数据观测，不能证明每个依赖包的实际 payload 未被修改。
除明确采集的后端代码范围外，其他依赖的同版本文件替换可能不触发漂移。Node / TUI 的 JS
资源、Node 及 Python 解释器二进制、所有原生扩展和系统库没有被完整纳入字节级冻结；
源码清单也有明确的目录和扩展名范围。文件属主、权限及运行中的进程状态不能从这些摘要中推导。

因此，检查一致只表示当前观测范围与参考值一致。完整不可变运行包、依赖 payload 校验、
可信发布链、升级/回滚事务以及其他运行边界仍需单独实现和验收。


### SQLite 实验兼容补丁

`scripts/dev/apply_sqlite_compat.py` 针对已知 filelock 源码中的 `sqlite_schema` 查询提供
版本、原文件 SHA-256 和替换次数检查，只在匹配时改为 `sqlite_master` 并备份原文件。
它是旧 SQLite 实验环境的兼容工具，不是默认安装步骤。

仅在独立、管理员控制的依赖副本中使用安装器的 `--sqlite-compat-overlay`，不要直接修改
共享 site-packages。runtime 的 `dependency_overlay` 只读挂入沙箱；`doctor` 使用同一
配置检查实际文件锁行为。回滚需停止实例、去掉 overlay 配置并重建，旧兼容故障可能重现。
正式部署优先使用验证过的上游修复或 SQLite 版本，并重新生成运行副本和基线。


---

## 4. Web 与普通用户入口

Web 提供管理员 YAML 校验/保存、备份与审计、角色绑定、实际启动请求预览及实例启停；
普通用户通过账号映射进入自己的工作空间并聊天。当前仍是同一特权进程直接调用
`ManagedRunner` 的实验入口，使用前先完成 「Linux 受管 demo」部署。

### 依赖与账号

在独立且由管理员控制的控制端 Python 环境中，从组件源码安装 `.[web]`。
在同一环境运行（路径按实际部署调整）：

```bash
sudo /opt/hypershell-control/bin/python -P -B scripts/dev/create_accounts.py   --out /etc/hypershell-demo/accounts.yaml --admin-user admin --users u1,u2
```

脚本逐个提示输入并确认独立密码（至少 12 字符），只保存 Argon2id 哈希，文件权限为 0600。
不提供默认密码或命令行明文密码参数；已有账号文件会拒绝覆盖。需要自动化时，
`--password-stdin` 从标准输入按 admin、u1、u2 的顺序读取各一行密码，缺失或空密码拒绝写入。
不要将密码、账号文件或 shell 历史提交到仓库。

账号名与 OS 用户名不同；普通账号的 `user_id` 必须对应 `admin.yaml` 中的用户。
管理员账号不绑定工作负载身份，也不能通过普通用户 TUI 登录。

### 启动

```bash
sudo /opt/hypershell-control/bin/python -P -B -m hypershell.web \
  --host 127.0.0.1 --port 8090 \
  --config /etc/hypershell-demo/admin.yaml \
  --runtime /etc/hypershell-demo/runtime.yaml \
  --accounts /etc/hypershell-demo/accounts.yaml \
  --relay-port-base 8091 --relay-host 127.0.0.1 \
  --relay-gate-url http://127.0.0.1:8090 \
  --relay-login-url http://127.0.0.1:8090/login
```

在主机本地或 SSH 隧道中访问 `http://127.0.0.1:8090`。配置、账号、密钥和备份的父目录
必须由管理员控制。审计默认写入 `/var/lib/hypershell-managed/web-audit.jsonl`，
备份和审计路径可用 `--backup-dir` 和 `--audit` 修改。

需要跨重启保留登录会话时，由部署方把固定的随机签名密钥以只读文件提供给 Web 服务，
并通过 `--secret-file` 或 `HYPERSHELL_WEB_SECRET` 指定路径。文件应仅授权给 Web 服务账号读取，
持久化加密由部署的密钥管理服务或存储层负责。Linux 上密钥须为普通文件，且不得授予组或其他用户权限，例如 `0600` 或 `0400`。
显式指定的文件缺失、不可读、权限不合适或内容为空时，服务拒绝启动。
升级时，未显式指定路径的服务仍可读取既有的 `/etc/hypershell-demo/web-secret`。
如果该文件也不存在，演示服务使用进程内的随机密钥，重启后用户需要重新登录。

环境变量统一使用 `HYPERSHELL_`：`WEB_HOST`、`WEB_PORT`、`ADMIN_CONFIG`、`RUNTIME`、
`ACCOUNTS`、`BACKUP_DIR`、`WEB_AUDIT`、`WEB_SECRET`，以及 relay 相关的 `RELAY_HOST`、
`RELAY_PORT_BASE`、`RELAY_FRONTEND_PORT`、`RELAY_GATE_URL`、`RELAY_LOGIN_URL`、
`RELAY_LOG_DIR`、`RELAY_PYTHON`。其中 `WEB_SECRET` 是密钥文件路径。
旧实验部署升级时需迁移拼写错误的环境变量并重新安装包装命令。

### 用户 Web 入口与 relay 自动监管（P3）

当 `--relay-port-base > 0` 时，控制面为每个 `RUNNING` 用户自动起一个**独立的 web relay 子进程**，
端口按配置用户顺序为 `base + index`（如 u1=8091、u2=8092），沙箱内前端端口由
`--relay-frontend-port` 指定（默认 5173）。relay 持可撤销会话租约、不占用操作锁；它把浏览器
Cookie 转发给网关 `/_gate/whoami` 做会话鉴权，未登录请求 302 到 `--relay-login-url`。

- 实例 `start` 成功后自动拉起该用户 relay；`stop`/`recover` 后自动停止并回收，**无需再手动起 relay**。
- 后台每 15 秒按实例 `phase` 收敛一次，自愈崩溃的 relay；网关 `shutdown` 会回收全部 relay 子进程。
- `--relay-port-base 0` 关闭自动监管，退回手动 `python -m hypershell web --user USER --listen-port PORT ...`。
- relay 必须是独立进程：它持会话租约并阻塞服务，若跑在网关进程内，“终止会话”会误杀网关。
- admin 的实例 `start` 是同步请求，建沙箱可能耗时数十秒；浏览器等待超时通常仍在后台完成，随后监管器
  会拉起 relay，可刷新总览确认。

### 配置应用

- 保存前复用严格配置编译器校验；保存做备份和审计，提示可能受影响的用户。
- YAML 编辑保留文本，角色绑定页会重新序列化 YAML，可能丢失注释和排版。
- 预览优先使用同目录的 `request-USER.yaml`，缺失时回退 `request.yaml`；仅表示本次预计挂载。
- 保存不热更新实例。降低权限、删除用户前先停止受影响实例，发布配置及请求后再启动。
- “一致”只表示授权和启动计划记录相符，不证明 runtime、身份或完整隔离边界已验证。

### 普通用户 TUI

管理员审阅 `scripts/dev/install_tui_launcher.sh` 并确认独立控制解释器及代码目录由 root
控制后运行。脚本安装固定 root 包装命令和 sudoers 白名单，不转发调用者参数；入口清空
调用者环境，认证成功后按账号映射选择工作空间。

```bash
sudo sh scripts/dev/install_tui_launcher.sh
# 普通用户执行，然后输入账号与密码；实例必须已由管理员启动：
hypershell-tui
```

安装路径可通过管理员环境变量 `HYPERSHELL_WEB_PYTHON`（默认控制端解释器）和
`HYPERSHELL_ROOT`（默认 `/opt/hypershell-demo`）指定。控制端需要安装 Web 认证依赖。
TUI 在受限后端 PTY broker 中启动，宿主 relay 降权后只转发字节。退出 TUI 不停止实例，
同一用户的 TUI/Web 会话登记为可撤销租约（不再长期持有操作锁），管理员可在总览终止。见 [设计方案](DESIGN.md)。

### 演示边界

签名 Cookie、CSRF 和 Argon2id 已实现；登录限速、SSO、账号管理 UI、外部会话存储和即时
会话撤销尚未实现。账号文件在 Web 启动时加载，修改后需重启；已有 Cookie 不会因此自动失效。
HTTP demo Cookie 未启用 Secure，不能直接面向公网。生产化需要拆分非特权网关与 controller，
补充 TLS、会话和权限撤销机制，详见 [安全说明](../SECURITY.md)。


---

## 5. 测试与验证

### 默认测试

在组件根目录（包含 pyproject.toml）执行：

```bash
python -m pip install -e ".[dev,web]"
python -m pytest tests -q -ra --basetemp=.test-tmp/pytest
```

`dev` 包含 pytest、Hypothesis 和管理员 HTTP 测试使用的 httpx；`web` 提供 FastAPI、模板、
表单、会话及 Argon2 认证依赖，与 CI 的安装方式一致。仅安装 `.[dev]` 可检查核心能力，
但缺少 Web 依赖时相应路由或认证测试会跳过；测试通过时需同时检查跳过原因。

| 测试文件 | 保留原因 |
|---|---|
| test_policy.py | 权限交集、配额、越权整体拒绝和摘要 |
| test_config_cli.py | 严格配置、身份映射和 CLI 行为 |
| test_roles.py | 角色并集、个人限制、撤权来源及入口安全 |
| test_runner_policy.py | 后端策略转换及无额外挂载 |
| test_managed_runner.py | 托管启动、可信路径与失败处理 |
| test_multiuser.py | 用户身份、独立存储及跨用户冲突 |
| test_recovery.py | 失效识别、残留阻断、备份及幂等恢复 |
| test_diagnostics.py | 实际解释器和文件锁诊断 |
| test_sqlite_compat.py | 实验兼容补丁只接受已知源码 |
| test_native_verification.py | 验收必须依赖成功工具事件及真实内容 |
| test_web.py / test_tui_launcher.py | 配置保存、账号认证与普通用户启动器身份映射 |
| test_admin_view.py | 实际请求预览、权限解释、授权/启动计划漂移及异常状态引导 |
| test_admin_routes.py | 管理员 HTTP 流程、访问控制、CSRF、配置修复及保存无隐式启停；活跃会话展示与终止 |
| test_sessions.py | 会话租约登记/清理、pid 死亡与 TTL 回收、终止/全量撤销、stop/recover 先撤销会话 |
| test_entry_execution.py | chat/探针共用后端执行、TUI/探针共用附加路径，保留操作锁/会话租约与无宿主回退 |
| test_boundary_probe.py / test_boundary_evaluation.py | 实际标准库探针与严格证据判定，缺项、未执行及未知错误不能误报通过 |
| test_boundary_verify.py / test_provenance.py | 验收前置条件、合成 fixture 清理和 observed 运行版本清单 |
| test_terminal_broker.py / test_terminal_relay.py / test_terminal_session.py | 真实 PTY 帧协议、认证、窗口、退出/断连/超时及后代回收；宿主不执行工作负载 |
| test_runtime_baseline.py | 未知/损坏观测拒绝、稳定投影漂移、参考保护与真实原子并发发布 |

`test_sqlite_compat.py` 和 `test_native_verification.py` 虽然面向实验工具，但能防止错误修改依赖和验收误报；在对应脚本仍随仓库提供时保留。没有将安全回归测试作为历史材料移出。

Windows 跳过部分 Linux flock/Unix socket 用例，本地测试不能替代真实隔离验收。测试会生成被忽略的 `.test-tmp/` 等目录。

### Linux 测试环境

使用独立测试 venv，避免向业务解释器安装测试依赖：

```bash
bash scripts/dev/run_vm_tests.sh python3
# 离线依赖已准备时：
bash scripts/dev/run_vm_tests.sh python3 wheelhouse
```

`requirements-test.txt` 引用同一组 `dev,web` extras，不再维护另一份历史版本清单。

### 真实运行验收

下文的 chat/TUI 执行入口边界工具 可对两个已运行实例执行固定探针，
不启停实例、不调用模型；报告关联运行代码、解释器、依赖、内核和配置摘要。
它检查两条入口的执行边界，不能代替后续完整生命周期、交互登录或模型应用验收。

`examples/demo/` 中以下脚本仍依赖现有实验部署和固定路径，不能直接当作新服务器安装/CI 入口。执行前阅读源码、确认测试环境、退出 TUI 并备份数据；测试会创建或停止/重建实例、产生测试会话和文件，可能调用模型服务。
在管理员控制的源码目录中，按[示例运行方式](../examples/README.md)选择独立控制端解释器和已部署的 HyperShell 包。

| 脚本 | 用途 |
|---|---|
| verify_vm_demo.py | 单用户身份、文件/网络边界、停止与会话持久性 |
| verify_native_file.py | 原生 read_file 的真实成功事件及文件内容 |
| verify_multiuser.py | 并发、跨用户文件/网络隔离及独立启停 |
| verify_roles.py | 角色授权、只读限制及重建后的撤权 |

双用户默认包含多轮启动；`--skip-chat` 只做 OS 层检查，不代表应用验收通过。同名 skill/memory 文件检查只证明存储隔离，不能证明完整 skill 安装/演进能力。


### chat / TUI 执行入口边界验证

本工具在两个**已经运行**的受管工作区中，分别沿 chat 后端执行路径和 TUI 附加路径运行同一段
标准库探针，记录进程身份、内核状态以及文件和网络行为。它用于暴露两个入口的边界差异，
不调用模型，不启动、停止、恢复或重建实例，也不会为测试临时放宽隔离策略。

### 执行前提

- 在已适配的 Linux demo 主机上由管理员执行，需要现有 `ManagedRunner` 运行环境和
  `ip netns` 等工具。Windows 单元测试不能代替本项真实运行验收。
- 两个不同用户的实例均须为 `RUNNING`，当前配置、角色和请求必须与启动记录一致。
  每个请求须挂载可写的 `/workspace` 和指定的同源只读共享目录资源。
- 先退出这两个工作区的交互 TUI，避免其持有用户操作锁；验收期间不要对实例执行启停、
  重建或变更配置。工具会检查实例身份变化，证据不完整时不会报告通过。
- 验收代码必须从与引擎启动时相同的部署位置加载。例如，已有部署使用
  `/opt/hypershell-demo` 时，设置下例的 `PYTHONPATH`。从另一份源码运行可能导致
  `engine.py` 绝对路径身份校验失败，被判为 `LOST / ENGINE_IDENTITY_MISSING`。
  工具不会为此自动恢复或重启实例。
- 输出父目录须已存在、由 root 控制，且不能被组或其他用户写入。报告原子写入，权限为
  `0600`；输出目标不能是符号链接或多重硬链接文件。

### 命令

将控制端解释器替换为实际已安装 HyperShell 依赖的 Python：

```bash
sudo PYTHONPATH=/opt/hypershell-demo /path/to/control/python \
  -m hypershell.runner.boundary_verify \
  --users u1 u2 \
  --shared-resource company-knowledge \
  --output /var/lib/hypershell-managed/entry-boundary.json
```

默认管理员配置为 `/etc/hypershell-demo/admin.yaml`，runtime 为同目录 `runtime.yaml`；
执行前还会验证 runtime 的 `runtime_bundle`，拒绝以 root 加载旧的用户可写应用环境，见 「管理员控制的运行副本」一节。
可用 `--config`、`--runtime` 指定其他可信配置。`--users` 必须给出两个不同用户，
`--shared-resource` 是双方请求中实际以只读方式挂载的目录资源 ID。

请求默认从管理员配置同目录读取 `request-u1.yaml`、`request-u2.yaml`，**不回退**到
`request.yaml`。使用其他文件时显式传入：

```bash
sudo PYTHONPATH=/opt/hypershell-demo /path/to/control/python \
  -m hypershell.runner.boundary_verify \
  --users u1 u2 \
  --request u1=/etc/hypershell-demo/request-u1.yaml \
  --request u2=/etc/hypershell-demo/request-u2.yaml \
  --shared-resource company-knowledge \
  --output /var/lib/hypershell-managed/entry-boundary.json
```

请求路径必须可信，不能为适应测试擅自改写已运行实例的请求或启动记录。配置已发生变化时，
先由管理员按正常流程处理，再重新执行验收。

### 测量内容

探针通过应用解释器的 `python -I -c` 执行，只使用标准库。`-I` 排除工作区当前目录、
用户 site 和调用方 `PYTHONPATH` 对导入的影响，避免 `/workspace/json.py` 等文件替换
测量代码依赖。控制端加载 HyperShell 所需的 `PYTHONPATH` 与探针的隔离导入是两件事。

| 范围 | 实际收集或执行 |
|---|---|
| 进程身份 | 真实/有效 UID、GID、补充组、PID、当前目录 |
| 内核进程状态 | `/proc/self/status` 中 `CapEff`、`CapBnd`、`NoNewPrivs`、`Seccomp` |
| namespace / cgroup | mnt、net、pid、ipc、uts、cgroup namespace 链接，以及 `/proc/self/cgroup` |
| 自有工作区 | 读取随机 fixture 并核对 SHA-256；独占创建随机文件后删除 |
| 共享目录 | 读取合成 fixture 并核对 SHA-256；在专用子目录中先以相同 UID/GID 做宿主写入正控，再检查入口创建文件是否被只读挂载阻止 |
| 他人及管理目录 | 尝试读取另一个用户和管理目录中的合成 fixture；宿主正控证明 fixture 确实存在 |
| 网络 | 临时 TCP listener 的 loopback / 本工作区地址正控，以及跨用户地址的拒绝检查 |

进程评估要求配置指定的非 root UID/GID、无补充组、`CapEff=0`、`NoNewPrivs=1`、
`Seccomp=2`，并核对 namespace 与宿主的差异、TUI 与 chat 的 cgroup 观测是否一致。
`CapBnd` 会记录在证据中；seccomp 模式号和这些身份字段均不等于完整策略认证。

文件读取只输出哈希和字节数，不回显内容。创建测试使用随机名称、`O_EXCL` 和
`O_NOFOLLOW`，拒绝覆盖现有文件。网络探针仅连接工具指定的数字 IPv4 地址和临时端口，
每次连接使用短超时，不解析模型域名或发送模型请求。

缺少 `/proc` 字段、工具不可执行、无效 JSON、未实际执行的操作和不在明确允许列表内的错误，
都不能当作隔离成功。不存在路径和连接失败必须结合独立宿主或 peer 正控解释；
“没有服务监听”不能充当跨用户网络隔离证据。

### 临时数据与清理

每次使用唯一 run ID 创建 `.hs-boundary-*` 合成 marker，并在双方网络 namespace 中启动
临时 listener。探针自己的写入测试使用 `.hypershell-boundary-*` 随机文件名。
这些是测试数据，不读取账号凭据或用户原有文件，也不生成模型对话或用户会话。

正常结束和可处理的失败均会进入清理流程：停止测试 listener，并核对文件身份后只删除
本次创建的 fixture。身份发生替换时拒绝删除，清理失败会写入错误并将报告标为
`incomplete`。进程被强制杀死或主机断电仍可能留下临时数据；此时应根据 run ID 核查，
不能把没有完成清理的旧报告解释为通过。

### 报告与退出码

报告包含宿主观测、正控、独立预期哈希/目标、每个用户的 chat / TUI 原始证据与逐项判定、清理错误、
运行时间和 observed manifest。终端只输出简短结果；完整 JSON 以 `--output` 指定的文件为准。

| 退出码 | 含义 |
|---|---|
| `0` | 报告为 `passed`，双方两个入口的检查通过且清理没有报错 |
| `1` | 报告为 `failed` 或 `incomplete`；存在边界差异、前置条件或证据/清理不完整 |
| `2` | 命令执行失败，如参数、管理员权限或报告输出路径错误 |

manifest 的 `kind` 为 `observed`，记录本次观察到的 HyperShell / 应用源码身份、解释器、
依赖版本、内核、配置及请求哈希、兼容 overlay 身份，并提供摘要关联报告。未知项会明确记录。
它不是依赖 lock、签名证明或不可变运行包，也不能单凭一个摘要证明部署来源可信。


### 证据范围

固定探针复用 chat/TUI 的受限执行路径，不驱动交互式账号登录或全部 Agent 工具。
文件/网络拒绝不能单独认证 Landlock 或完整 seccomp 规则；cgroup 观测不替代 CPU/内存压力测试。
完整部署还需验证真实 TUI 登录退出、重启恢复、模型调用、外部 DNS/IPv6 和生命周期清理。
历史私有 VM 报告不作为当前提交的通过证据；提交时记录本次版本、命令、平台及跳过原因。
