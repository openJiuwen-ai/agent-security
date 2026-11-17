# agent_shield 设计文档

## 1. 引言

### 1.1 背景与问题

Agent 运行时把模型输出变成真实动作：执行命令、读写文件、访问网络、创建子进程。面对的风险包括：

- **越权执行**：注入指令诱导 Agent 执行危险命令——提权、强制推送、混淆命令、远程脚本；
- **数据外发**：把密钥、令牌或敏感文件发送到外部端点；
- **路径越界**：读写工作区之外的用户文件、受保护系统文件、设备与命名管道；
- **驻留**：创建定时任务等持久化手段；
- **规避**：命令在静态解析层被伪装（解码管道、引号技巧），绕过纯文本检查。

`agent_shield` 的定位是 **Agent 全流程的多层安全护栏**，覆盖五条安全相关流：用户输入输出、模型输入输出、工具（含系统层事件）执行、工具输出、skill 安装。按职责可以分成三层：

1. **`intercepts/`——接入层（拦截点）**：把流经点编成事件或检测请求，再调用对应引擎。已落地三个接入点：`tool_call`（工具调用）、`native_call`（进程树系统调用）、`tool_output`（工具结果）；用户输入输出、模型输入输出、skill 安装是预留接入点（未落地，不建空目录）；
2. **`policy_engine/`——行为策略引擎**：对文件、工具、命令、网络四类行为给出 `allow`、`ask`、`deny` 或 `undetermined` 之一。工具调用在解析层拦截（命令不执行），系统调用在执行前拦截（拒绝则该 API 不执行，fail-closed）；
3. **`detection/`——内容检测引擎**：对进入模型或工具结果的内容做提示词注入等检测，输出概率性软信号；`tool_output` 接入点调用它。

行为决策与内容检测分工：行为引擎管「**能不能做**」（fail-closed 的动作裁决），检测引擎管「**内容里有什么**」（注入与敏感内容信号），两者产出不同、消费方式也不同。`tool_permission/` 是仓库内既有的动作决策组件（括号里的 W1a/W2/W3/W6 是仓库内部的工作项编号，下文的 W4/W5 同理）。不并入上述三层。**本文档详细描述接入层与行为策略引擎**：对 `detection` 只说明接入契约（见 2.2 路径 C），对 `tool_permission` 只说明它与 DLL 防护的关系（见第 8 节）；两者的内部实现由各自文档描述（见 12）。

### 1.2 设计目标

1. **统一裁决**：一次工具调用或一条 原生操作，产出恰好一个决定（`agent-decision/v1` 信封）。
2. **结构性安全**：deny 永不被任何 allow 翻转；内置/三方 ask 永不被宽匹配的用户 allow 压过——由固化的优先级表保证，不依赖运行时判断。
3. **四层规则、十级优先级**：内置 / 三方 / 用户自定义 / 用户交互授权（grant）四层来源在同一张优先级表上裁决。
4. **精确授权**：HITL 审批沉淀的 grant 只覆盖本次的精确资源；不可沉淀的 ask 不提供「总是允许」。
5. **失败关闭（fail-closed）**：规则加载失败、任务未打开、宿主回调失败、native 管道或注入不可用，一律 deny 或拒绝执行，绝不退回裸进程或空规则。
6. **宿主解耦**：引擎不 import 任何 Agent 框架；宿主通过 `Host` 协议提供上下文与审批窗口；引擎不落盘任何外部规则或 grant。
7. **审计完整**：注册、更新、每次裁决、每次 grant 采纳/剔除、native 结算全部留痕。

### 1.3 非目标

- **不是隔离边界**：进程守卫只做行为决策，不做资源隔离；沙箱是 `jiuwenbox` 的职责。`execution.plane=sandbox` 不降低任何风险档。
- **不抵御同进程恶意代码**：trusted in-process 部署的安全边界是宿主进程本身；同进程代码可以直接改写参数。
- **不做静态行为分析之外的语义理解**：意图核对是纯文本匹配（见 4.8），不调用模型。
- **不落盘规则**：三方规则集、用户规则、grant 只存在于引擎内存与宿主存储中。

### 1.4 范围与模块清单

```
agent_shield/                       ← 本目录自身即 agent_shield 包（flat 布局，
  README.md                            pyproject 的 package-dir 把根映射为 agent_shield）
  docs/agent_shield-design.md        本设计文档
  policy_engine/                策略决策点（引擎 + 服务）
    evaluate.py                 公开 evaluate()
    audit.py                    文件审计（JSONL）
    errors.py                   规则加载失败（PolicyError）
    matchers/                   路径、网络、命令、工具与行为规则；dispatch 分发对象规则
    models/                     规则对象（BehaviorRule / ObjectRule）
    core/                       规则集加载、裁决编排、聚合
    builtin/                    随包行为规则、目录表与策略快照
    events/                     工具调用和 原生操作 共用的事件构造
    server/                     Decide / Host / RulesetRegistry / 回环 HTTP / CLI
  intercepts/                       接入层（拦截点）：把流经点编成事件或检测请求
    tool_call/                        工具调用 → 行为策略引擎
      adapters/jiuwenswarm/tool_call.py 工具调用 → 事件
    native_call/                      进程树系统调用 → 行为策略引擎（原 process_guard Python 侧）
      dll_guard/                          ProcessGuard 会话、审批与原生执行
    tool_output/                      工具结果 → 内容检测引擎
      inspect.py                          异步 inspect()：文本交 detection 后端评估
      adapters/jiuwenswarm/tool_result.py 从工具结果提取待检文本
  tool_permission/                   既有动作决策组件（toolguard / fileguard / netguard / hostguard / delguard）
    runtime/                         原生适配用的运行时配置、授权与引擎（内部）
    shell_structure.py               方言 AST 拆叶与结构分析
  schema/                        现行 JSON Schema
  tests/                         Python 单元测试 + e2e（见 13.1）
```

同仓还有两个**范围外**的兄弟子包：`detection/`（内容检测引擎——提示词注入等检测，被 `intercepts/tool_output` 调用）与 `tool_permission/`（既有动作决策组件：toolguard/fileguard/netguard/hostguard/delguard）。它们与本文档的组件同包名空间、分开演进，由各自的文档描述，本文档不展开（见 12）。

### 1.5 术语表

| 术语 | 含义 |
|---|---|
| PDP | Policy Decision Point，策略决策点，即 `policy_engine` 包 |
| 接入点（intercept） | `intercepts/` 包内把一条流经点（工具调用、系统调用、工具结果）编成事件或检测请求的组件 |
| 宿主（Host） | 集成 agent_shield 的 Agent 应用运行时，持有用户规则与 grant，提供审批窗口 |
| 主体（`subject_id`） | 宿主为当前用户/profile 填写的隔离键，grant 按它隔离 |
| 任务（`task_id`） | 宿主生成的任务标识，与 `ruleset_id`、`subject_id` 组成任务绑定三元组 |
| 规则集（`agent-pdp/v1`） | 三方配置：对象规则、目录追加、行为覆盖、`action_mapping`。经规则集接口注册 |
| 事件（event） | `agent-event/v1`，一次工具调用或一条 原生操作 的规范化描述 |
| effect | 事件拆出的原子行为：`process.exec`、`fs.*`、`net.*`、`privilege.escalate`、`schedule.create` |
| 行为规则 | 按风险档描述的行为分类，动作由风险换算 |
| 对象规则 | 直接声明 allow/ask/deny 的五类对象规则（file/domain/command/agentTools/nativeTools） |
| 目录（catalog） | 可被规则引用的名单数据（路径、glob、主机、CIDR、程序名等） |
| grant | HITL 审批沉淀的精确资源授权，仅 allow，位于优先级位置 4 |
| HITL | Human-in-the-loop，宿主打开的审批窗口 |
| `unmatched` | 宿主启动时设定的无命中改写策略（none/allow/ask/deny） |
| 回环 PDP | `agent-pdp serve` 启动的独立 HTTP PDP 进程，只监听本机回环 |

---

## 2. 总体架构

工具调用由 tool_permission 和行为规则引擎裁决。Windows 原生执行统一从 `from agent_shield import ProcessGuard` 接入。SDK 持有会话、任务规则、审批、Job 和审计，Agent Shield 与 JiuwenBox 使用同一份按架构构建的公共 DLL。

```mermaid
flowchart TD
    Shield["Agent Shield · ProcessGuard.spawn()"] --> Session["SDK 会话 · Job / 任务规则 / 审批 / 审计"]
    Box["JiuwenBox · 本地执行 / 沙箱 runner"] --> DLL["agent_security_guard.dll · x64 / x86"]
    Session --> DLL
    DLL --> Check["操作请求 · 可信进程身份"]
    Check --> Engine["PermissionEngine.evaluate_operation()"]
    Engine --> Ask["ASK → host.confirm() → 策略复核"]
    Ask --> Decision["最终 ALLOW / DENY"]
    Engine --> Decision
    Decision --> Recovery["获准删除 · 公共软删除处置"]
    Box --> Recovery
    Recovery --> Local["本地回收站 / 同卷归档"]
    Recovery --> Broker["JiuwenBox 宿主代理 · 去重与查询"]
    Recovery --> Permanent["宿主显式配置 permanent"]
    Local --> Result["按 operation_ids 上报结果与结算"]
    Broker --> Result
    Permanent --> Result
    Result --> Session
```

每次 spawn 创建一个 execution，task_id 绑定规则与删除计数。每个实际目标的文件、进程、设备、管道和网络操作均在执行前核验。复合文件操作保留各资源角色，由统一引擎综合判定。纯工具调用和回环 HTTP PDP 继续使用 agent-event/v1 与 agent-decision/v1。

## 3. 数据模型

### 3.1 事件与 effect（`agent-event/v1`）

事件描述「被评估的行为」。裁决读取的主要字段：

| 字段 | 用途 |
|---|---|
| `id`、`time` | 决定里的 `event_id`；建议 grant 的 `decision_id` 与 `approved_at` |
| `action.category` | `model_call` 直接放行；其余进入匹配 |
| `action.raw.name` | agentTools 只比较这个工具名（大小写不敏感）；native 事件为 `native`，不参与 agentTools 匹配 |
| `action.command_line` / `command_tokens` | 命令行原文与空白分词；对象 command 规则的匹配键 |
| `action.normalization.status` | `failed`/`partial` 且无运行时拦截时命中 `exec.unobserved` |
| `execution.intercept` | 只参与 `exec.unobserved`；native 事件恒 true |
| `workspace.root`、`trusted_dirs`、`os` | 路径归一化、userFiles 范围；`os` 决定 `.exe` 省略与按操作系统展开的目录 |
| `host_capabilities.hitl`、`auto_intent` | Decide 是否打开审批；意图核对能否把 medium ask 放成 allow |
| `user_intent` | 意图核对的用户原话；模型计划不是意图 |
| `cause.tool_call_id/name` | native 事件携带，溯源到工具调用 |

事件里的 `preauth` 使事件非法（schema 层禁止）。`subject_id` 不从事件读取。

适配器把一次工具调用或一条 原生操作 拆成 effect 列表：

| effect | 来源与载荷 |
|---|---|
| `process.exec` | 命令段。可带 `argv`（shell argv）、`command_line`、`command_tokens`、`image`（被创建进程映像）、`shell_meta{obfuscated, interpreter_sink, privilege, pipe_target}` |
| `fs.read` / `fs.write` / `fs.delete` | 路径、scope、`path_kind`（file/device/named_pipe）、`device_class`、`exists`、`force`、`bulk` |
| `net.connect` / `net.fetch` / `net.egress` | 主机、IP、端口、`method`、`secret_like`、`local_files` |
| `privilege.escalate` | 提权标记 |
| `schedule.create` | 创建定时任务 |

命令按 `&&`、`||`、`;`、`|` 分段，每段一个 `process.exec`；一段上的 allow 不放行另一段（`git status && rm -rf ~` 中 `git` 的 allow 不放行 `rm`）。`command_tokens` 只盖本次调用直接产生的 `process.exec`；父进程 `process.image` 不复制到文件 effect 上。

### 3.2 DecisionRequest（`agent-decision-request/v1`）

规则是「评估的依据」，放在事件信封外层；非法事件 → `invalid_event`，非法规则 → `invalid_ruleset`，两者错误语义分开。

| 字段 | 要求 |
|---|---|
| `spec` | 固定 `agent-decision-request/v1` |
| `request_id` | 字符串，可省略，透传审计 |
| `ruleset_id` | 字符串。回环 PDP 上为空则 deny（`missing_ruleset`），未知则 409（`unknown_ruleset`） |
| `subject_id` | 非空字符串。缺失为 `missing_subject`（隔离 PDP 返回 401 且无 `action`） |
| `task_id` | 非空字符串。缺失为 `invalid_ruleset` |
| `event` | `agent-event/v1` 对象 |
| `user_rules` | 对象规则列表，默认空，≤500 条 |
| `grants` | grant 列表，默认空，≤2000 条 |

加载时校验（fail-closed，违反即整份请求 `invalid_ruleset`）：未知键、错误类型、用户规则里出现 `source`、grant 携带 `action`/`pattern`/`match`/`cidrs`/`mac`、grant 缺非空 `subject_id` 与 `provenance{decision_id, approved_at, via}`、`hosts`/`names`/`tokens` 出现 `*`。`unmatched`、三方规则与 `action_mapping` 不能出现在请求里。请求体超过 1 MiB 为 `too_large`。

用户规则在加载时包成 `agent-user-rules/v1`（只允许 `spec` 与 `rules`）。

### 3.3 决定信封（`agent-decision/v1`）

Schema 为 `schema/agent-decision.v1.json`，`additionalProperties=false`。

| 字段 | 含义 |
|---|---|
| `spec` | 固定 `agent-decision/v1` |
| `event_id` | 事件 id，缺省空字符串 |
| `action` | `unmatched` 改写后的结果：`allow`/`ask`/`deny`/`undetermined` |
| `raw_action` | 改写前结果；无命中为 `undetermined` |
| `winner_rule_id` | 胜出规则 id；无胜出规则为 `null`；请求级失败为错误码 |
| `advice.user_visible` | `summary`、`content`、`risk`（无/低/中/高/严重风险） |
| `grants` | 建议 grant，仅最终动作为 ask 时可能非空 |

请求级失败也用这份信封（action=deny）。唯一例外是隔离 PDP 的 `missing_subject`：请求在进入裁决前就被拒绝，HTTP 直接返回 401，响应体只有 `{"error": "missing_subject"}`，不含 `action`。

| `winner_rule_id` | 场合 |
|---|---|
| `invalid_ruleset` | 请求或规则无法加载；CLI 退出码 2 |
| `missing_subject` | 无主体；隔离 PDP 返回 401 且响应无 `action` |
| `missing_ruleset` | 回环 PDP 上缺 `ruleset_id` |
| `unknown_ruleset` | 规则集不存在或已注销；HTTP 409 |
| `unknown_task` | 任务未打开 |
| `invalid_event` | 事件非法，或 原生操作 顶层夹带 `user_rules`/`grants`/`rules`/`preauth` |
| `host_context_unavailable` | Decide 的宿主回调失败或返回非法内容 |
| `process_identity_mismatch` | 原生操作 与绑定身份不符（native 通道） |

### 3.4 原生运行时 IPC

公共 DLL 使用统一的协议 13 清单和受限二进制帧。任务规则消费转换后的 agent-event/v1，SDK 在原生 API 执行前返回最终裁决。删除从登记到策略复核、回收与结算沿用 operation_id。result 记录旧目标处置，operation_result 分别记录 handle_close、rename、replace 的实际返回状态，对外事件只输出 operation_ids 数组，单项为 [id]，合并审批为去重后的多个 ID，无关联操作为 []。两者关联审计而独立结算。详见第 8、9 节。


### 3.5 Schema 清单

| 文件 | spec | 用途 |
|---|---|---|
| `schema/agent-decision.v1.json` | `agent-decision/v1` | 决定信封 |
| `schema/agent-event.v1.json` | `agent-event/v1` | 事件；禁止 `preauth` |
| `policy_engine/core/request.py`（代码内建校验，无 JSON 文件） | `agent-decision-request/v1` | 请求信封（闭集校验） |
| `schema/audit-event.v1.json` | `audit-event/v1` | 文件审计记录 |

`schema/test_schema_contracts.py` 保证 schema 始终接受 PDP 与适配器的实际产物。

---

## 4. 规则模型

### 4.1 四层规则来源

归属由**加载路径**决定，调用方不能在条目里写 `source`。

| 层 | `source` | 进入路径 | 能写什么 |
|---|---|---|---|
| 内置 | `builtin` | 包内 `builtin/rules.py` | 29 条静态行为 + 目录初值 + `decide()` 时按 OS 展开的 nativeTools 对象规则 |
| 三方 | `third_party` | 规则集接口注册的 `agent-pdp/v1`；`eval --policy` 只作用于这一次 | 对象规则、目录追加、行为覆盖、`tp.*` 新行为、`action_mapping` |
| 用户 | `user_custom` | 本次 `user_rules` | 五类对象的 allow / ask / deny |
| 授权 | `user_grant` | 本次 `grants` 或 `Host.grants()` 回调 | 精确资源的 allow |

内置行为不可删除；覆盖只改 `risk`、`auto_intent`、`user_grantable`，`when` 与展示名保持内置表，覆盖后仍算内置层。用户自定义对象规则恒可沉淀 grant（`user_grantable` 强制 true）；内置与三方规则默认 `user_grantable=false`。对象规则有 `enabled`（默认 true），关掉不参与匹配。

### 4.2 目录（catalogs）

目录随规则集保存；用户规则不能追加目录。内置目录已有 `kind`；三方追加写成字符串列表或 `{entries: [...]}`，不能写 `kind`、不能清空内置条目。按操作系统拆分的目录，裁决时取 `entries` 加当前 OS 那一列。

| 目录 | kind | 内置初值 | 谁使用 | 追加语义 |
|---|---|---|---|---|
| `protectedFiles` | path | posix：`/etc/passwd`、`/etc/shadow`、`/etc/sudoers`、`/etc/ssh/sshd_config`、`/boot/**`、`/etc/sudoers.d/**`；windows：`C:/Windows/System32/**`、`C:/Windows/SysWOW64/**`、`bootmgr` | 写、删受保护文件 | 加严 |
| `protectedReadFiles` | path | posix：`/etc/shadow`、`/etc/sudoers`、`/etc/sudoers.d/**`；windows：`SAM`、`SYSTEM`、`SECURITY` 注册表配置单元 | 读受保护文件 | 加严 |
| `sensitiveFiles` | glob | `.ssh`、`.env`、密钥与云凭据等 12 条 glob | 读写删敏感文件、外发附带敏感文件 | 加严 |
| `userFiles` | user | 空；运行时并入 workspace root 与 trusted_dirs | 用户文件区读写删 | **放宽** |
| `systemPrefixes` | prefix | posix：`/etc`、`/usr`、`/bin`、`/sbin`、`/lib`、`/lib64`、`/opt`、`/boot`、`/root`、`/var`；windows：`C:/Windows`、`C:/Program Files`、`C:/Program Files (x86)` | 系统目录新建文件 | 加严 |
| `nativeToolsDenyList` | program | posix：`sudo`、`su`、`pkexec`、`doas`；windows：`sc`、`reg`、`regedt32`、`regini`、`schtasks`、`netsh`、`wmic`、`diskpart`、`bcdedit`、`vssadmin` | 启动时生成 `nativeTools.deny` | 加严 |
| `nativeToolsAskList` | program | posix 空；windows：`certutil`、`bitsadmin`、`mshta`、`wscript`、`cscript`、`rundll32`、`regsvr32` | 启动时生成 `nativeTools.ask` | 加严 |
| `allowlist_hosts` | host | 空 | `net.*.allowlist` 与名单外网络行为 | **放宽** |
| `allowlist_cidrs` | cidr | 空 | 同上 | **放宽** |
| `privilege_argv0` | program | `sudo`、`pkexec`、`doas`、`runas`、`gsudo` | 分类前提权标记 | 加严 |
| `interpreter_sinks` | program | `bash`、`sh`、`zsh`、`pwsh`、`powershell`、`cmd`、`iex` | 管道目标算远程脚本 | 加严 |

- `/var/tmp` 不算系统前缀，`/var/log` 算；shell 与解释器不进 `nativeToolsAskList`（常规执行通道，由行为规则覆盖，三方可自行追加）。
- 三方新目录必须 `{kind, entries}`，`kind` 限 `glob`/`host`/`cidr` 且 `entries` 非空，名字不得与内置目录相同；`prefix`/`path`/`program`/`user` 只属于内置目录。
- `builtin_denylist_hosts`、`builtin_denylist_cidrs`、`user_denylist_hosts`、`user_denylist_cidrs` 四个名字出现即失败。内置不携带拒绝端点；拒绝主机由三方或用户的 domain deny 写出。
- allowlist 为空时 `net.*.allowlist` 不命中：连接走 `net.connect.unlisted`，GET/HEAD 走 `net.fetch.get`，其余外发走 `net.egress`。三方要放行某个主机，把该主机追加进注册规则集的 `allowlist_hosts`。
- 审计脱敏、意图核对与适配器使用 `load_builtin_policy()`（`builtin/policy.py` 从 `builtin_catalogs()` 构建的改名视图：`sensitive_globs`、`privilege_argv0`、`interpreter_sinks`、`allowlist_*`、`system_critical`、`system_prefixes`）。运行时 `when` 在 `builtin/rules.py`。

### 4.3 行为规则

字段：`id`、`risk`、`when`、`note`；可选 `auto_intent`、`user_grantable`。规则上不写 `action`，动作由风险档换算：

| 风险 | 默认动作 |
|---|---|
| `none`、`low` | allow |
| `medium`、`high` | ask |
| `critical` | deny |

三方 `action_mapping` 可把五档分别改成 allow/ask/deny，未声明的档保持默认；用户规则不能带。

**floor（降档底线）**：覆盖内置 id 时 `risk` 不得低于 floor；未列出的规则 floor = 默认风险。开放降档的 15 条：

| 行为 | 默认风险 | floor |
|---|---|---|
| `fs.write.outside`、`fs.delete.outside`、`fs.write.system_new`、`net.egress`、`schedule.create` | medium | low |
| `git.force_push` | medium | none |
| `fs.read.userFiles`、`fs.write.userFiles`、`fs.delete.userFiles`、`net.fetch.get`、`net.connect.unlisted` | low | none |
| `fs.read.nonsensitive_outside`、`net.connect.allowlist`、`net.fetch.allowlist`、`net.egress.allowlist` | none | none |

不可降档：`fs.read.sensitiveFiles` ≥ high；`privilege.escalate`、`fs.device.raw_write` ≥ critical；其余未开放规则 ≥ 自己的默认风险。

**auto_intent**：只有结果仍是 medium 且动作仍是 ask、且该规则 `auto_intent` 为真时进入意图核对；通过后内置行为落位置 10（内置 allow），三方 `tp.*` 行为落位置 9（三方 allow）——放行不改变归属层。内置 medium 默认开启，三方新增默认关闭。none/low/high/critical 即使被映射成 ask 也不进入意图核对。

**user_grantable**：默认 false。为 false 的 ask 不提供「总是允许」，之后携带的 grant 也不压过它。

**when 词汇表**（加载时按 effect 闭集校验，`PolicyError` 不留到裁决期）：

| effect | 允许的键 |
|---|---|
| `process.exec` | `argv0`、`argv_prefix`、`argv_contains`、`argv_has_any`、`argv_has_any_prefix`、`shell_meta.privilege`、`shell_meta.obfuscated`、`shell_meta.interpreter_sink` |
| `fs.read` | `path.scope`、`path.in_catalog`、`path.glob_any`、`path_kind`、`exists` |
| `fs.write` | 读的键 + `device_class` |
| `fs.delete` | 读的键 + `force`、`bulk` |
| `net.connect` | `endpoint.in_any_catalog` |
| `net.fetch` | connect 的键 + `method` |
| `net.egress` | fetch 的键 + `secret_like`、`local_file_attached`、`local_files.glob_any` |
| `privilege.escalate`、`schedule.create` | 只有 `effect` |

形状规则：顶层各键同时成立；`any` 每支内部同时成立、一支成立即可，支里省略 `effect` 时继承外层，顶层只有 `any` 时每支必须自带 `effect`；`effect` 写成列表时其余键必须对每种类型合法。否定只有 `not`（值为一个条件对象，其中不能再写 `effect` 或 `not`）；`endpoint.not_in_any_catalog` 与 `path.in_catalog: {not: ...}` 不再接受。布尔键只接受 true/false（缺失算 false）；`exists` 接受 true/false/null 或其列表；`path.scope` 为 `workspace`/`outside`；`method` 不区分大小写；`argv0` 等程序名比较不区分大小写（`normalize_program`），参数类键不区分大小写。`path.glob_any` 与 `local_files.glob_any` 既可写目录名，也可直接写内联 glob 列表；`endpoint.in_any_catalog` 既可写目录名，也可写内联 `{hosts, cidrs}`（`matchers/behavior.py` 的 `_glob_patterns`/`_endpoint_in`）。

三方新行为：id 必须 `tp.` 开头，带非空 `note`、`risk`、`when`，id 与内置或三方重复即失败。行为规则的 argv 来自 shell argv；对象 command 规则不读这组 argv。

### 4.4 内置行为清单

29 条静态规则（`builtin/rules.py` 的 `_WHENS`）+ 裁决期合成的 `exec.unobserved`，按默认风险从高到低：

| id | 风险 | 展示名 | 命中 |
|---|---|---|---|
| `privilege.escalate` | critical | 提权执行 | effect 为 `privilege.escalate`，或 `process.exec` 带提权标记 |
| `fs.delete.protectedFiles` | critical | 删除受保护文件 | 删除 `protectedFiles` |
| `fs.device.raw_write` | critical | 写入裸磁盘或卷 | 写 raw_disk 或 volume |
| `net.egress.secret` | critical | 外发敏感数据 | 外发像密钥，或附带命中 `sensitiveFiles` 的本地文件 |
| `fs.write.protectedFiles` | high | 写入受保护文件 | 写 `protectedFiles`，且文件存在或未知 |
| `fs.read.protectedReadFiles` | high | 读取受保护文件 | 读 `protectedReadFiles` |
| `fs.read.sensitiveFiles` | high | 读取敏感文件 | 读 `sensitiveFiles` |
| `fs.write.sensitiveFiles` | high | 写入敏感文件 | 写 `sensitiveFiles` |
| `fs.delete.sensitiveFiles` | high | 删除敏感文件 | 删 `sensitiveFiles` |
| `fs.delete.outside_force` | high | 强制删除工作区外的文件 | 工作区外且 `force` |
| `fs.device` | high | 访问设备或命名管道 | 读或写 device、named_pipe |
| `fs.delete.bulk` | high | 批量删除文件 | `bulk` |
| `exec.unobserved` | high | 命令无法完整解析且没有运行时拦截 | 事件级合成：规范化 failed/partial 且无 `execution.intercept`；`user_grantable=false` |
| `shell.obfuscated` | medium | 执行混淆命令 | `shell_meta.obfuscated` |
| `exec.remote_script` | medium | 执行远程脚本 | `shell_meta.interpreter_sink` |
| `fs.write.system_new` | medium | 在系统目录中新建文件 | 路径在 `systemPrefixes` 且 `exists=false` |
| `fs.write.outside` | medium | 写入工作区外的文件 | 工作区外且不在 `protectedFiles` |
| `fs.delete.outside` | medium | 删除工作区外的文件 | 工作区外且非强制 |
| `net.egress` | medium | 向外发送数据 | 外发且端点不在 allowlist |
| `schedule.create` | medium | 创建定时任务 | `schedule.create` |
| `git.force_push` | medium | 强制推送 | `git` + `push` + 强制标记 |
| `fs.read.userFiles` | low | 读取用户文件 | 读 `userFiles` |
| `fs.write.userFiles` | low | 写入用户文件 | 写 `userFiles` |
| `fs.delete.userFiles` | low | 删除用户文件 | 删 `userFiles` |
| `net.fetch.get` | low | 从外部读取数据 | GET/HEAD 且端点不在 allowlist |
| `net.connect.unlisted` | low | 连接未列入名单的网络端点 | 连接且端点不在 allowlist |
| `fs.read.nonsensitive_outside` | none | 读取工作区外的非敏感文件 | 读工作区外路径 |
| `net.connect.allowlist` | none | 连接允许名单中的网络端点 | 连接 allowlist |
| `net.fetch.allowlist` | none | 拉取允许名单中的网络端点 | 拉取 allowlist |
| `net.egress.allowlist` | none | 向外发送到允许名单中的网络端点 | 外发到 allowlist |

提权标记与解释器标记在分类前由目录算好（`privilege_argv0`、`chmod u+s`/`chown root` 参数、`interpreter_sinks` 管道目标）。单独启动 python/powershell 而无管道目标不算远程脚本。`nativeTools.deny/ask` 是 `decide()` 时按事件 OS 生成的内置对象规则，默认 `user_grantable=false`，AskList 的 ask 位于位置 5。

### 4.5 对象规则

对象五类：`file`、`domain`、`command`、`agentTools`、`nativeTools`；动作 allow/ask/deny；用户与三方都可写；grant 只能 allow 且匹配面更窄。空 `ops` 对普通对象表示全部操作，对 grant 非法（file/domain grant 必须恰好一个操作）。

| 对象 | 普通规则 | grant |
|---|---|---|
| file | `pattern` glob（相对 workspace root 或绝对）；读/写/删分别配置 | 恰好一个 op + 字面 `path`；文件名里的 `*`、`[` 是字面字符 |
| domain | `hosts` 与 `cidrs` 至少一个非空；主机按模式、IP 按网段 | 恰好一个 op + 一个精确主机或 IP；不能写 CIDR 与 `*` |
| command | `match` 按空白 token 与命令行比较；独立 `*` 跳过一个位置；token0 走 `normalize_program` | `tokens` 整段精确相等，不含 `*`；优先 `command_tokens`，否则 `command_line` |
| agentTools | 只比较 `action.raw.name`，不看参数；事件级匹配 | 一个工具名 |
| nativeTools | 程序名；有映像时用映像，否则 argv0 | 一个程序名；只消去同名且可沉淀的 nativeTools ask |

程序名比较（`normalize_program`）：反斜杠换斜杠取末段、大小写不敏感、仅事件 OS 为 windows 时去 `.exe`；完整映像路径只进审计，不作匹配键。command 分词用 `str.split()`（引号不合并），段按 `&&`/`||`/`;`/`|` 切开。**前缀 deny 可被参数顺序绕开**（`git -C . push` 对 `git push`、`rm -r -f` 对 `rm -rf`），需要稳定拦截时用行为规则；command 对象规则适合 allow 与 ask。没有命令行原文时 command allow 不匹配（记 `missing_command_line`），deny/ask 可按 shell argv 低置信匹配；agentTools allow 不放行该调用产生的 effect；native 侧 `create_process` 用被创建进程映像做 nativeTools 匹配，命令行 argv0 与发起方 `process.image` 不参与，不一致时记 `image_command_mismatch`。

### 4.6 grant

grant 是精确资源的 allow。宿主持有字节、有效期与撤销；引擎每次只接收宿主传来的列表并核对 `subject_id`（不一致剔除并记 `grant_rejected`；接受的记 `grant_accepted`）。`mac` 是非法字段，携带即整份请求失败。

建议 grant 在最终动作为 ask 时生成（编号 `suggested-0`、`suggested-1`；带 `subject_id` 与 `provenance{decision_id=事件id, approved_at=事件时间或空, via=hitl}`，不带 `action`/`mac`）。可沉淀条件：

- 用户自定义 ask 恒可沉淀；
- 内置与三方 ask 仅 `user_grantable=true` 可沉淀；
- 某一部分只要还有一条 `user_grantable=false` 的 ask，就不生成建议并丢弃该部分上的 user_grant 命中（已携带的 grant 压不过不可沉淀的 ask）；
- `exec.unobserved` 不可沉淀，只抑制自己那一部分的 grant。

nativeTools grant 批准后放行该程序名后续每次启动（审批界面须明示），但只消去同名且可沉淀的 nativeTools ask，同一次启动上的 command ask 与行为 ask 仍在。

### 4.7 十级优先级与聚合

每一部分（事件级、每个 effect）在自己的命中里取位置数字最小的一条；同一数字上行为命中先于对象命中。

| 位置 | 来源与动作 |
|---|---|
| 1 | 三方 deny |
| 2 | 内置 deny（含 nativeToolsDenyList、critical 行为） |
| 3 | 用户 deny |
| 4 | user_grant allow（精确资源；nativeTools grant 不占此位） |
| 5 | 内置 ask（各风险档、nativeTools.ask、`exec.unobserved`） |
| 6 | 三方 ask（行为与对象；同一数字上行为先给出原因） |
| 7 | 用户 ask |
| 8 | 用户 allow（压不过位置 5、6） |
| 9 | 三方 allow |
| 10 | 内置 allow（行为换算，含意图核对通过后的内置 medium） |

无命中的部分是 undetermined，引擎不合成内置 allow。各部分先按启动配置改写 undetermined，再按 deny > ask > undetermined > allow 聚合。`unmatched=none` 时某一部分的 allow 不能盖住另一部分尚未改写的 undetermined。

### 4.8 意图核对（`core/intent.py`）

`allows_auto(event, policy)`：`user_intent.text` 必须逐一蕴含**全部** effects，任一不满足即不通过。前置条件：`auto_intent` 能力开启、`normalization.status=ok`、text 与 effects 非空。纯文本匹配，不调用模型：

- exec：带提权标记直接不通过；混淆命令须原文出现在 text；force-push 须有 force 词 + push 动词；解释器管道须「远程脚本/curl/wget/iex/| bash」或 URL 出现；普通命令须 argv 整串出现，或命令名 + 执行动词且无额外 flag；
- fs：路径不得在敏感/受保护目录，且路径被 text 点名，或在 workspace 范围内 + 对应读写删动词（内置中英文动词表）；
- net：host/url/ip 出现在 text；schedule：须有定时动词。

注意：意图核对使用内置策略**快照**（`load_builtin_policy()`），读不到规则集追加的目录——三方扩目录不影响意图判定。

### 4.9 unmatched

宿主启动时设定（`evaluate(..., unmatched=...)` / `serve --unmatched`），取值 `none`/`allow`/`ask`/`deny`，默认 `none`。只改写裁决结果已是 undetermined 的部分，发生在聚合之前；不进入 DecisionRequest、事件或规则集，规则集更新不能修改。`none` 时 native 通道由宿主把 undetermined 收成可执行动作后再回答 hook，审计同时记录 PDP 结果与宿主最终动作。

### 4.10 用户可见说明（`advice.user_visible`）

纳入哪些段：最终 deny 只留胜出 deny；最终 ask 留每个仍为 ask 的部分（事件级在前）；最终 allow 只留胜出 allow；undetermined 无命中可展示。

- `summary`：各段类型短语按出现顺序去重、「、」连接，再接动作后缀（`需要授权`/`已拒绝`/`已放行`）。行为规则用展示名（内置表或三方 `note`）；对象规则用对象操作短语（文件读取、网络连接、命令执行…）。
- `content`：每段对象用「，」连接，不去重。命令优先 `command_tokens` 空格连接，其次 `command_line`，再次 shell argv。
- `risk`：纳入段中行为命中（覆盖后、`action_mapping` 前）的最高风险；对象规则不参与；无行为风险为「无风险」。

grant 胜出时：summary「命中已批准的具体资源，已放行」，content 为该资源，risk「无风险」。`unmatched` 改写时 summary 分别是「没有命中规则，需要宿主决定 / 需要授权 / 已拒绝 / 已放行」，content 空、risk 无风险。`model_call` 直通 allow「模型调用已放行」。

---

## 5. 一次裁决的完整流程

三条入口在校验事件之前分开，之后共用匹配、优先级与聚合。`agent-pdp eval` 与进程内 `evaluate()` 不查任务；回环 PDP 与 `Decide` 只裁决已打开的任务。

```mermaid
flowchart TD
  start[工具调用或 原生操作] --> entry{入口}

  entry -->|evaluate 或 agent-pdp eval| parse[解析 DecisionRequest]
  entry -->|POST /v1/evaluate| auth[核对 evaluate 凭证]
  entry -->|Decide| callback[回调 Host.user_rules 与 Host.grants]

  auth -->|凭证缺失或错误| unauth[HTTP 401]
  auth -->|凭证通过| parse
  parse -->|格式错误| badReq[deny：invalid_ruleset 或 missing_subject]
  parse -->|隔离 PDP| task[按 ruleset_id、subject_id、task_id 取已打开任务]
  parse -->|eval 与进程内| event[校验事件]
  task -->|没有规则集或任务未打开| taskDeny[deny：missing_ruleset、unknown_ruleset 或 unknown_task]
  task --> subject[核对 grant 的 subject_id]
  callback -->|回调失败或非法| hostDeny[deny：host_context_unavailable]
  callback --> subject
  subject --> event

  event -->|事件非法| badEvent[deny：invalid_event]
  event -->|model_call| modelAllow[allow]
  event -->|可裁决| match[事件级与每个 effect 分别匹配]

  match --> rank[每部分取优先级数字最小的命中]
  rank --> rewrite[unmatched 只改写 undetermined]
  rewrite --> agg[按 deny、ask、undetermined、allow 聚合]
  agg --> ask{最终动作是 ask}
  ask -->|是| grants[为可沉淀部分生成建议 grant]
  ask -->|否| envelope[agent-decision/v1]
  grants --> envelope

  envelope --> settle{是否经过 Decide}
  settle -->|否| done[决定交还宿主]
  settle -->|ask 且有 HITL| window[打开审批窗口]
  settle -->|ask 且无 HITL 或任务已关闭| denyNow[改为 deny]
  window -->|批准| once[放行这一次]
  window -->|拒绝| denyNow
  settle -->|allow 或 deny| done
  once --> done
  denyNow --> done
```

要点：

1. 解析 DecisionRequest，格式错误在此结束（CLI 退出码 2）。
2. 隔离 PDP 核对规则集与任务；进程内 `evaluate()` 使用调用方传入的规则集，缺省为内置规则。`eval --policy` 只替换这一次的三方规则集。
3. 校验事件：非法 deny（`invalid_event`）；`model_call` 直通 allow；原生操作 夹带规则字段即 deny。
4. 四层规则进同一次匹配；`nativeTools` 名单按事件 OS 展开；shell_meta 标记在匹配前盖到 effect 上。
5. 事件级与每个 effect 分别匹配，各取优先级最小命中。
6. `unmatched` 只改写 undetermined，聚合序 deny > ask > undetermined > allow。
7. 最终 ask 时为可沉淀部分生成建议 grant。
8. `Decide` 结算 ask：无 HITL、任务已关闭或审批拒绝 → deny；相同 in-flight ask 共用一个审批门；批准只放行这一次，跨调用放行只能靠宿主保存的 grant。没有跨调用的答案缓存。

---

## 6. 规则集与任务生命周期

### 6.1 规则集（`agent-pdp/v1`）

| 字段 | 内容 |
|---|---|
| `rules` | 三方对象规则（≤500 条） |
| `catalogs` | 内置目录追加，或带 `kind` 的新目录（每目录 ≤2000 条） |
| `behavior_rules` | 内置 id 的覆盖，或 `tp.*` 新行为（≤500 条） |
| `action_mapping` | 五个风险档 → allow/ask/deny |

文档为 UTF-8 JSON，≤1 MiB。注册返回随机 128 位 `ruleset_id`（`secrets.token_hex(16)`）、版本 1 与指纹（规范 JSON 的 SHA-256）。更新必须带 `expected_version`，整体替换；版本不符 409（`version_conflict`）；校验失败保留旧版本。引擎不落盘规则集，重启后句柄失效返回 `unknown_ruleset`，不退回只用内置规则。

### 6.2 加严与放宽

更新先做语义比较（`core/ruleset_diff.py`）：任一项放宽使整次更新算放宽；无法证明更严也算放宽。

- 对象规则同一匹配面：deny 严于 ask 严于 allow；列表字段纯追加/删除证明包含关系；command 的 `match` 更长命中面更小；glob 文本改写或动作与匹配面同变算放宽。
- 新增启用的 deny/ask 为加严，新增 allow 为放宽；删除反向。
- `user_grantable` false→true 放宽，true→false 加严（先于匹配面比较）。
- 内置行为风险升高加严、降低放宽；`auto_intent` 关闭加严、开启放宽。
- 新增 `tp.*`：有效动作 deny/ask 加严，allow 放宽。
- 目录追加：第 4.2 节表中标「加严」的目录追加为加严；`userFiles` 与 allowlist 的追加为放宽。三方新目录（`tp` 类）的追加按引用它的行为分类——引用它的行为全部为 deny/ask 则算加严，混合或无法判定算放宽。

加严立即作用于进行中的任务（任务绑定直接指向新版本）；放宽只作用于之后打开的任务。`runtime_relax=deny` 时（高安全部署，只能经直接构造 `RulesetRegistry` 传入）放宽更新被拒绝。

### 6.3 任务绑定

绑定键 `(ruleset_id, subject_id, task_id)`；`task_id` 由宿主生成，引擎不读事件里的任务标识。重复打开 409（`task_id_in_use`）；未打开就裁决 `unknown_task`；关闭必须带齐三元组。空闲超时默认 30 分钟（`_sweep` 按单条绑定计算）；无任务引用且非 current 的旧版本由 `_gc` 回收。

---

## 7. 接口设计

### 7.1 Python API

**进程内裁决**（`policy_engine.evaluate`）：

```python
evaluate(request: dict, *, ruleset: dict | Ruleset | None = None,
         audit_path: str | None = None, unmatched: str = "none") -> dict
```

只接受 DecisionRequest。`ruleset` 为 `agent-pdp/v1` 文档时叠加内置加载；为已加载 `Ruleset` 时沿用其 unmatched。`audit_path` 指定时每次裁决追加一条 JSONL 审计（见 10）。`PolicyError` → deny（`invalid_ruleset`）。

**任务结算**（`policy_engine.server.Decide`）：

```python
Decide(host: Host, *, source: dict, registry: RulesetRegistry,
       ruleset_id: str, subject_id: str, task_id: str,
       isolated: bool = False, delete_threshold: int = 20)
```


**宿主协议**（`policy_engine.server.host.Host`，`Protocol`）：

| 方法 | 返回 | 说明 |
|---|---|---|
| `user_intent()` | `dict \| None` | 本次任务的用户原话 |
| `workspace()` | `dict` | `root`、`trusted_dirs`、`os` |
| `capabilities()` | `dict` | `hitl`、`auto_intent` |
| `request_approval(decision, event)` | `bool` | 打开审批窗口；True 放行这一次 |
| `user_rules()` | `list[dict] \| VersionedRules` | 该主体的自定义规则 |
| `grants()` | `list[dict] \| VersionedRules` | 该主体的精确 grant |

`VersionedRules(version, items)`：宿主缓存标签，两回调版本都与上次一致时 Decide 复用已编译规则与请求指纹，不再计算指纹、不重复审计 grant；版本变化或返回普通列表则重新加载。版本不能是 bool；返回类型非法该条 record deny（`host_context_unavailable`）。

**注册表**（`RulesetRegistry`）：`register` / `update` / `status` / `close` / `open_task` / `close_task` / `resolve`（按三元组取已打开任务的绑定）/ `evaluate_request`；`audit` 列表属性为内存审计流。

**进程守卫**（`intercepts.native_call`）：



### 7.2 HTTP API（回环 PDP）

| 方法与路径 | 凭证 | 结果 |
|---|---|---|
| `GET /v1/health` | 无 | 200 `{"status":"ok"}` |
| `POST /v1/rulesets` | control | 201 `{ruleset_id, version, fingerprint}` |
| `PUT /v1/rulesets/{id}` | control | 正文恰为 `{expected_version, ruleset}`；200 返回版本、指纹、`classification`、`changes` |
| `GET /v1/rulesets/{id}` | control | 版本、指纹、`updated_at`、`task_count`；不返回规则内容 |
| `DELETE /v1/rulesets/{id}` | control | 200 `{"status":"closed"}` |
| `POST /v1/tasks` | control | 正文恰为三元组；200 返回钉住的版本 |
| `POST /v1/tasks/close` | control | 同一组字段；200 `{"status":"closed"}` |
| `POST /v1/evaluate` | evaluate | DecisionRequest；任务必须已打开 |

状态码：401 `unauthorized`；404 `not_found`；400 `too_large`（>1 MiB）/`invalid_json`/`invalid_ruleset`/`invalid_task`；409 `version_conflict`/`unknown_ruleset`/`runtime_relax`/`task_id_in_use`。`/v1/reload` 不存在。控制请求可带 `X-Agent-PDP-Caller` 审计标签。`serve()` 也可显式传入两份凭证（必须两枚且不同）；缺省时自动生成。

### 7.3 CLI

```text
agent-pdp eval --policy ruleset.yaml
agent-pdp serve --host 127.0.0.1 --port 0 --unmatched none
```

`eval` 从 stdin 读 DecisionRequest，`action=allow` 退出码 0，否则 2（stderr 打 user_visible.summary 或 winner_rule_id，stdout 打决定 JSON）。`--policy` 是这一次的 `agent-pdp/v1` 规则集，可省略。`serve` 不接收规则文件，也不接收凭证参数，凭证单行 JSON 打到 stderr 供父进程从管道读取。三方规则在启动后经 `/v1/rulesets` 注册。`--unmatched` 取 none/allow/ask/deny，默认 none。

### 7.4 适配器

| 入口 | 作用 |
|---|---|
| `policy_engine/events/envelope.py` · `build_event` | 组装 `agent-event/v1`：缺省 id `evt_<uuid4>`、UTC 时间、`host_capabilities{hitl,auto_intent}=true`、`execution{plane=host, provider=host, intercept=false, escaped=false}` |
| `policy_engine/events/command_effects.py` · `normalize_command` | 命令规范化（**绝不执行命令**）：混淆检测（PowerShell `-encodedcommand`/`-enc` 不透明编码、解码管道进 shell、`\x`+eval/iex、`[char]`+eval、空引号、`${IFS}`、token 内 2 处以上反斜杠转义）→ 剥 `cmd /c`、`pwsh/powershell -Command/-c` 外壳（命令本身是不透明编码时不剥）→ 按 `&& \|\| ; \|` 分段，检测引号不平衡/heredoc/未展开替换，产出 ok/partial/failed → 每段一个 `process.exec`（带 shell_meta），重定向→fs 读写，`cd` 更新后续 cwd，删除工具→fs.delete（force、bulk=false），网络工具→net.*，管道 sink 追加 `__compound__` 合成 effect；`stamp_tokens` 时给每段盖 `command_tokens`；内嵌脚本最多读一层、须在 workspace/trusted_dirs 内、≤256 KiB，内嵌参数带 `-encodedcommand`/`-enc` 时直接 partial |
| `intercepts/tool_call/adapters/jiuwenswarm/tool_call.py` · `tool_call_to_event` | 工具名 `-`→`_` 后 casefold 分派：shell 类/带 command 的未知工具走命令规范化；read/write/delete 生成单个 fs effect（force 取 `args.force`）；fetch 按方法与载荷分 `net.fetch`/`net.egress`；注入 workspace、execution、`source.framework=jiuwenswarm` |
| `intercepts/tool_output/adapters/jiuwenswarm/tool_result.py` · `tool_result_text` | 从工具结果提取待检文本：纯字符串直接用；字典依次取 `content`/`output`/`text`/`result` 键；其余为空串 |
| `intercepts/tool_output/inspect.py` · `inspect` | 异步检测入口（见 2.2 路径 C）：文本 + `tool_name` 组成 `GuardrailContext{event=tool_output}`，交 detection 后端（默认 `RuleBasedPromptInjectionBackend`，`backend=` 可注入），返回 `RiskAssessment` 软信号 |

---

## 8. Windows 防护（Python 侧）

唯一受保护启动入口为 ProcessGuard.spawn()。构造参数为 session_id、host、delete_mode（默认 recover）和 approval_timeout_s（默认 120）。host 提供 policy_snapshot、confirm、save_grant 与 audit。快照必须包含 revision 和 config，任务规则启用时还需 ruleset 与 tasks。规则及授权按版本、主体、任务和资源范围校验。

```python
from agent_shield import ProcessGuard


async def execute(host, argv):
    async with ProcessGuard(session_id="session", host=host) as guard:
        process = await guard.spawn(
            argv, task_id="task", tool_call_id="call", tool_name="shell",
        )
        return await process.wait()
```

spawn 支持 cwd、env、stdio、channel、timeout_s 和结构化 approval_receipt。返回对象提供 pid、execution_id、returncode、wait、communicate 与 cancel。根进程退出后仍保护后代，直到 Job 为空、取消、超时或关闭会话。会话关闭保留清理失败的 Job，允许重试清理。

一次逻辑操作最多出现一次合并确认。策略或成员身份在审批期间变化时重新判定。任务删除计数由所有 execution 共用，在裁决前预留，仅确认成功后累计。拒绝和确定失败释放预留，未知保留至执行收尾，重复回报不重复计数。

Windows 管道使用当前用户专属的受保护 DACL，拒绝远程连接。宿主读取管道真实对端 PID，并验证 Job 成员及 PID:创建时间。凭据 API 返回的子进程还须通过调用方句柄和实际父 PID 验证后加入同一 Job。审计保存任务、工具、execution、命中规则、操作资源与从系统读取的进程身份。

## 9. Windows 公共原生实现

源码和构建脚本位于 foundation/agent-security-dll。每种架构只有 agent_security_guard.dll 及构建时生成的协议 13 清单。Hook 后端固定 Microsoft Detours v4.0.1。SDK 校验清单、架构和 SHA-256，并在执行期间固定文件和目录。

| 能力 | 统一实现 |
|---|---|
| 文件访问 | NtCreateFile、NtOpenFile，保留目录、元数据、链接、设备和命名管道语义 |
| 元数据与枚举 | NtQueryAttributesFile、NtQueryFullAttributesFile；目录枚举的底层打开仍受检查 |
| 复合变更 | 复制、重命名、移动、替换、硬链接、符号链接，按源、目标及备份一起裁决 |
| 进程 | CreateProcessInternalW 覆盖 Win32 创建族；凭据 API 显式保护返回的挂起子进程；直接未受管理的 NtCreateUserProcess 拒绝 |
| ShellExecute | W/A 和 ExW/ExA 统一启动实际可执行文件，只接受默认或 open verb，拒绝代理 verb、IDList 和类名启动 |
| 网络 | DNS、Winsock、WinHTTP、WinINet，包含地址、域名、URL 和代理目标 |
| x86 与 x64 | Windows x64 宿主支持两种目标及后代，跨位数加载使用 Detours 的同位数 helper，共用原会话 |
| 删除 | 路径删除、句柄置删除、关闭时删除和重命名覆盖，共用 softdelete 处置器 |

recover 只接受已确认的回收或归档，失败与未知均返回错误。沙箱仅使用绑定的 JiuwenBox 代理，回执丢失按相同操作 ID 查询。permanent 仅在宿主显式配置且本次策略允许时执行。JiuwenBox 独立软删除继续提供 guard_open/guard_close、guard_prepare_process 和 guard_recover_local；独立软删除的宿主授权职责保持原有边界。公共 guard_open/guard_close 以独立持有句柄复用同一执行绑定，最后一个关闭时卸钩并释放 native 状态。Git Bash 独立链路在调试 CREATE_PROCESS 事件中准备子工具导入，失败阻断执行。MSYS 的 unlink、unlinkat、rmdir、remove 同步调用公共回收器，以运行库 errno 返回失败。Token/Logon 的挂起子进程经 OS 父子关系和 Job 核验后，只为实际 TokenUser SID 增加管道客户端 I/O 与初始化事件权限，保留已核验句柄用于后续查询。管道连接仍校验 OS 客户端 PID 和 Job。WithToken 在本机 UAC 过滤令牌下无 DLL 基线返回 1314；完整管理员令牌启用 SeImpersonatePrivilege 后，当前账户 x86/x64 的 allow/deny 四项实测通过，无跳过。产品验收以同一账户的受保护进程树为边界，不要求树内再次切换账户。JiuwenBox 在宿主层用 WithLogon 启动 jbx-sandbox runner 的必要链路继续保留。额外跨账户验收脚手架已删除；凭据创建 API 的安全拦截继续保留，身份核验或 Job 登记失败时拒绝创建。就绪由消息 49 复制仅含 EVENT_MODIFY_STATE 的句柄。

原生 IPC 使用长度受限的二进制帧。操作 40 检查实际程序，42 请求删除授权，43 回报删除处置，45 验证并登记返回的子进程句柄。宿主决定 allow/deny，应用线程等待结果。构建产物仅由脚本生成，源码归档不含 DLL、EXE 或其他编译产物。

## 10. 审计与可观测性

审计有两条互不相通的轨道：

**文件 JSONL**（`policy_engine/audit.py`，仅进程内 `evaluate(audit_path=...)` 使用）：每条记录 `time`（UTC）、`event_id`、`framework`、`session_id`（事件 source）、`action`、`raw_action`、`winner_rule_id`、`tool_raw_name`。追加写、线程锁串行、自动建目录。脱敏：命中密钥特征（AKIA/sk-/api_key=/私钥头）的字符串替换为 `***`；命中敏感 glob 的路径替换为 `<redacted-path>`。默认不开启。

**注册表内存审计**（`RulesetRegistry.audit`，HTTP / Decide 全部操作走这里；无上限、不落盘）：

| 事件 | 字段 |
|---|---|
| 注册 / 更新 / 更新失败 / 注销 | `ruleset_id`、版本、指纹、caller（`X-Agent-PDP-Caller`，缺省空串）、更新分类 |
| 每次 evaluate | 规则集版本与指纹、`subject_id`、`task_id`、`request_id`、事件 id、请求规则指纹、部署模式、`unmatched`、`action`、`raw_action`、`winner_rule_id` |
| 每次 Decide 结算 | mode、ruleset、subject、task、event_id、winner、`raw_action`、`pdp_action`、`action`、unmatched、版本、指纹、请求指纹 + effect 审计 |
| grant | `grant_rejected`（主体不一致）、`grant_accepted`（id、对象、provenance） |
| effect 审计 | 去重后的进程映像、`image_command_mismatch`、`missing_command_line` |

HTTP evaluate 的解析级失败不写注册表审计（只有规则可加载时的 `evaluate_rejected` 会写）。

---

## 11. 安全设计

| # | 威胁 / 要求 | 对策 |
|---|---|---|
| 1 | 宽 allow 翻转 deny / ask | 十级优先级表在代码中固化：deny(1–3) 恒高于 grant(4) 与全部 allow；内置 ask(5)、三方 ask(6) 恒高于用户 allow(8) |
| 2 | 把单条行为风险降到底线以下 | floor 由加载校验保证；整档动作由该规则集的 `action_mapping` 决定；`critical: allow` 不把单条风险降到 floor 以下 |
| 3 | 用户规则夹带 `action_mapping`/`user_grantable`/`source` | 加载即拒绝；宽匹配盖不住内置 ask、三方 ask、敏感文件与受保护写 |
| 4 | `userFiles`/allowlist 追加放宽越界 | 放宽类追加单独审计；落在 `protectedFiles`/`sensitiveFiles` 的路径仍命中高风险行为 |
| 5 | 未知条件键静默不命中 | `when` 词汇表封闭，加载期按 effect 校验，`PolicyError` 不留到裁决期 |
| 6 | 规则注入面 | 三方只经规则集接口进入；`eval --policy` 只作用于这一次。用户规则与 grant 只由已认证宿主经 DecisionRequest 或 Host 回调进入；原生操作 管道不接受任何规则字段（顶层夹带即 `invalid_event`） |
| 7 | 未认证调用 PDP | 回环 only；双凭证分立、内存生成、`hmac.compare_digest`、不落盘；401 不进入裁决，不按空规则裁决 |
| 8 | 规则集更新攻击面（一次更新影响后续所有决定） | 控制通道独立凭证；版本化整体替换 + `expected_version`；语义比较，无法证明更严算放宽且只作用新任务；`runtime_relax` 可禁运行时放宽；更新失败保留旧版本；注册/更新全审计 |
| 9 | 句柄失效降级 | 重启后 `unknown_ruleset`，不退回只用内置规则；宿主回调失败该条 record deny |
| 10 | preauth 旁路 | 事件 schema、请求、Host 协议均不接受 preauth；授权只经独立 `grants` 通道，精确匹配器 |
| 11 | 无命中被当 allow | 先 `undetermined`；`unmatched` 只改写这种部分且不随请求进入；某部分的 allow 盖不住另一部分的 undetermined |
| 12 | grant 跨主体重放 | `subject_id` 核对，不一致剔除并审计；`mac` 字段非法 |
| 13 | TOCTOU（决策与执行间隙路径变化） | native hook 在执行前实时拦截覆盖 host 侧；agent 侧维持审计 |
| 14 | native 管道被远程或他人连接 | 随机管道名 + 本用户 DACL + `PIPE_REJECT_REMOTE_CLIENTS`；连接先绑定六字段身份（`process_instance_id` 抗 PID 复用），record 逐条比对 |
| 15 | 被守护进程逃避 hook | 延迟 hook 补装失败自杀 83；`NtCreateUserProcess` 无条件拒绝；子进程创建必须经 broker 重新注入，失败即杀；守卫自身失败退出 83，Python 侧 fail-closed 不跑裸进程 |

---

## 12. 仓库内的能力分布与预留能力域

`agent_shield` 包（flat 布局，本目录即包根）内已落地的能力分三块：

- **范围外兄弟子包**：`tool_permission/`（工具权限组件 toolguard / fileguard / netguard / hostguard / delguard，对应 W1a / W2 / W3 / W6）与 `detection/`（内容检测，对应 W4）——同包名空间、分开演进，由各自文档描述，pyproject 包清单同时列出它们；
- **沙箱（W5）**：独立交付件 `../jiuwenbox/`（自带 pyproject、FastAPI 服务、Linux / Windows 运行时），与本包分开安装与测试。

对照 §1.1 的五条流：工具执行（含系统层事件）与工具输出已落地（`tool_call`、`native_call`、`tool_output` 三个接入点 + 两个引擎）；用户输入输出、模型输入输出、skill 安装是**预留接入点**（不建空目录，落地时按 `intercepts/<流经点>/` 增设）。敏感数据防护（PII 发现与脱敏）与 skill 安装扫描仍是规划中的能力域，**不再保留占位包**（原 `data_guard`、`prompt_guard`、`extension_guard` 空实现已移除）；提示词注入检测已由 `detection/` 覆盖，后续引擎按需增设，接口边界在设计文档先行约定。

---

## 13. 测试与验证

### 13.1 Python 测试（`agent_shield/tests/`，39 个单测文件覆盖本文档范围 + e2e）

`tests/` 下共有 77 个 `test_*.py`：39 个属于本文档覆盖范围（`intercepts/` 19、`policy_engine/` 17、`schema/` 1，加根目录 `test_import_rules.py` 与 `unit_tests/test_no_detours_git_submodule.py`），其余 38 个属于范围外的 `tool_permission/`（35）与 `detection/`（3）。`conftest.py` 从测试位置向上定位包根（同时含 `schema/agent-event.v1.json` 与 `policy_engine/evaluate.py`），不依赖固定目录层级。单测目录跟着被测包走。

| 测试文件 | 覆盖 |
|---|---|
| `intercepts/dll_guard/test_process_guard_session.py`、`test_runtime_guard_context.py`、`test_runtime_guard_policy.py` | DLL 防护会话生命周期、上下文、策略判定与授权 |
| `intercepts/dll_guard/test_runtime_guard_ipc.py`、`test_runtime_decision_cache.py`、`test_dll_guard_long_requests.py` | 管道帧、决策缓存与长请求 |
| `intercepts/dll_guard/test_dll_guard_compatibility.py`、`test_dll_guard_domains.py`、`test_dll_guard_process.py`、`test_dll_guard_resources.py`、`test_dll_guard_python_execution.py`、`test_runtime_guard_bridge.py`、`test_runtime_guard_shared_config.py` | 兼容性、域名与资源检查、进程注入与 Python 执行路径 |
| `intercepts/tool_call/test_adapters.py` | jiuwen 工具调用转成事件 |
| `intercepts/tool_output/test_inspect.py` | 工具结果提取文本；检测后端对注入样例给出信号 |
| `policy_engine/core/test_decision.py` | 内置层级 → allow/ask/deny 映射 |
| `policy_engine/core/test_adjudication.py` | 十级优先级与 user_visible |
| `policy_engine/builtin/test_rules.py` | 内置规则判定（含 nativeTools 目录按程序名） |
| `policy_engine/matchers/test_command.py` | 规范分词器（Windows 剥 .exe、allow 需命令行） |
| `policy_engine/core/test_envelope.py` | evaluate_event 与建议 grant、preauth 非法 |
| `policy_engine/core/test_orchestrator.py` | when 匹配、action mapping、grant 精确性、nativeTools image 优先 argv0 |
| `policy_engine/core/test_ruleset.py` | 规则集/用户规则/grant 加载与闭集校验 |
| `policy_engine/core/test_behavior_schema.py` | 行为规则子句形状校验（PolicyError） |
| `policy_engine/core/test_evaluate.py` | 风险评级矩阵 |
| `policy_engine/core/test_intent.py` | 中风险仅当用户话语覆盖全部 effect 才免确认 |
| `policy_engine/core/test_risk_grade.py` | 多 effect 取最严 |
| `policy_engine/events/test_command_effects.py` | 命令归一：sudo、force push、远程脚本、混淆、cd 改删除路径、token 盖章 |
| `policy_engine/server/test_decide.py` | Decide 的 ask 结算、重复 ask 合并、grant 主体、审计 |
| `policy_engine/server/test_http.py` | 回环 PDP CLI/HTTP（退出码、凭据、审计） |
| `policy_engine/server/test_registry.py` | 注册表版本、语义更新、任务 pin |
| `policy_engine/test_audit.py` | 文件审计脱敏密钥与敏感路径 |
| `policy_engine/builtin/test_policy.py` | 每条内置规则有 hit/miss、floor 不可降 |
| `schema/test_schema_contracts.py` | schema 接受 PDP/适配器实际产物 |
| `policy_engine/_factory.py` | 测试事件构造器（非测试） |
| `policy_engine/server/support.py` | Decide 测试用的假 Host（非测试） |


范围外测试（属 `tool_permission/` 与 `detection/`，由各自文档描述）：`tests/tool_permission/`（根下 `test_permission_*.py`、`test_deletion_guard.py`、`test_sandbox_projection.py`、`test_w1b_w2_engine_pipeline.py`，及 `toolguard/`、`fileguard/`、`hostguard/`、`netguard/` 子目录）与 `tests/detection/`——与本表 39 个单测互不重叠，共用同一个 `conftest.py`。`tests/test_import_rules.py` 守 jiuwenbox 等外部项目的导入规则，留在 `tests/` 根下。

### 13.2 原生验收

build-windows.ps1 -BuildTestClient 构建两种位数的 probe、x64 API client 和 x86 直接会话客户端。ProcessGuard.spawn() 的真实验收覆盖两种位数根进程、四种父子位数组合、文件角色、程序规则、网络、删除处置和实际 PID。100 项冻结操作及其期望规则 ID 位于 tests/intercepts/dll_guard/operation_cases.json 与 operation_results.jsonl。身份伪造、管道 DACL、审批生命周期和删除预留结算由统一会话测试覆盖。

---

## 14. 已知限制与演进方向

**语义边界（有意取舍）**：

1. command 对象规则是前缀匹配，deny 可被参数顺序绕开（`git -C . push`）；需要稳定拦截用行为规则。
2. `nativeTools` grant 批准后放行该程序后续所有启动——避免反复确认的取舍，审批界面须明示。
3. 意图核对是纯文本匹配，且使用内置策略快照：三方追加目录不影响意图判定。

**native 覆盖盲区（当前实现）**：

4. 注册表 API 未拦截（当前无注册表 hook）。
5. DNS（`getaddrinfo`）未 hook；socket 级按 IP、HTTP API 级按主机名拦截。
6. 读不存在文件、写父目录缺失、伪设备直接放行不产生 record（性能优化，语义上无风险面）。
7. 当前 SDK 在 Windows x64 宿主上保护 x64 和 WOW64 进程树，ARM64 目标拒绝。

**实现细节限制**：

8. 审计双轨互不相通：注册表审计只在内存（无上限、不落盘）；文件审计仅进程内 `evaluate(audit_path=...)` 路径。
9. `Host` 回调路径的 `user_rules` 没有条数上限（HTTP/eval 路径限 500）。
10. `Decide` 的审批去重键只含 effects 内容：无 effects 的 agentTools 事件级 ask 并发时共用一个审批门。
11. hook 进程内决策串行（`g_decide_lock`）：单个被守护进程的裁决吞吐受一问一答时延限制。
12. SDK 宿主要求 Windows x64；受保护目标支持 x64 与 x86。两种目标共用任务规则和软删除，未受管理的原生创建进程请求返回拒绝。

**演进方向**：数据安全 / 提示词安全 / 扩展安全能力域按需设包落地（见 12）；非 Windows 的 native 守卫；注册表拦截；审计统一与落盘；意图核对接入规则集目录。

---

## 15. 附录

### A. 代码地图

| 路径 | 职责 |
|---|---|
| `policy_engine/evaluate.py` | 公开 `evaluate()`；只接受 DecisionRequest |
| `policy_engine/models/types.py` | `BehaviorRule`、`ObjectRule` 数据类与对象规则校验 |
| `policy_engine/core/envelope.py` | `evaluate_event()`：组装 `agent-decision/v1`，事件校验，建议 grant 的 provenance |
| `policy_engine/core/orchestrator.py` | 编排一次裁决：调用匹配器、抑制不可沉淀的 grant、建议 grant、衔接意图核对 |
| `policy_engine/core/adjudication.py` | 十级优先级、unmatched 改写、聚合、user_visible 拼装 |
| `policy_engine/builtin/rules.py` | 内置 `when` 与目录初值（运行时真源） |
| `policy_engine/builtin/catalog.py` | 默认风险、展示名、目录 kind、禁止的目录名 |
| `policy_engine/core/action_mapping.py` | floor 与 `action_mapping` 换算（`_OPEN_FLOOR` 15 条） |
| `policy_engine/core/ruleset.py` | 四层规则加载、覆盖、目录合并、`decide()`（OS 展开、shell_meta 盖章） |
| `policy_engine/core/behavior_schema.py` | 行为规则子句的加载期形状校验 |
| `policy_engine/matchers/behavior.py` | 行为规则的 `when` 对一个 effect 是否成立 |
| `policy_engine/matchers/dispatch.py` | 按 object 类型分发到文件、域名、命令或工具匹配 |
| `policy_engine/matchers/tools.py` | agentTools / nativeTools 是否命中 |
| `policy_engine/matchers/command.py` | 分词、程序名、提权信号、命令规则匹配 |
| `policy_engine/core/request.py` | DecisionRequest 校验（500/2000 上限、grant 禁字段） |
| `policy_engine/core/grants.py` | grant 主体核对（`grant_rejected`） |
| `policy_engine/core/ruleset_diff.py` | 规则集更新的加严/放宽语义比较 |
| `policy_engine/core/user_visible.py` | 用户可见短语与 content 片段 |
| `policy_engine/server/registry.py` | 注册表：版本、指纹、任务绑定、空闲超时、内存审计、effect 审计 |
| `policy_engine/server/http.py` / `cli.py` | 回环 HTTP 与 `agent-pdp` |
| `policy_engine/server/decide.py` | `Decide.settle`、审批门、删除计数 |
| `policy_engine/server/host.py` | `Host` 协议与 `VersionedRules` |
| `policy_engine/events/` | 工具调用和 原生操作 共用的事件构造 |
| `intercepts/tool_call/adapters/jiuwenswarm/` | jiuwen 工具调用 → 事件与 effect |
| `intercepts/tool_output/inspect.py` | 异步检测入口：工具结果文本 → detection 后端 → `RiskAssessment`（见 2.2 路径 C） |
| `intercepts/tool_output/adapters/jiuwenswarm/tool_result.py` | 从工具结果提取待检文本 |
| `foundation/agent-security-dll/native/windows/` | `agent_security_guard.dll` 的 hook、注入、网络与文件快照实现 |
| `foundation/agent-security-dll/scripts/build-windows.ps1` | DLL 构建与 manifest 生成 |
| `policy_engine/core/intent.py` | 意图核对（纯文本） |
| `policy_engine/errors.py` | `PolicyError`：规则或 when 加载失败 |
| `policy_engine/builtin/policy.py` | `Policy` / `load_builtin_policy`（目录改名视图） |
| `policy_engine/matchers/paths.py` | 路径归一化、glob→regex、系统前缀/关键文件判定 |
| `policy_engine/matchers/network.py` | 主机模式与 CIDR 匹配 |
| `policy_engine/audit.py` | 文件 JSONL 审计与脱敏。内存审计在注册表 |
| `policy_engine/events/command_effects.py` | 命令转成 effect。分词在 `matchers/command.py` |
| `foundation/agent-security-dll/scripts/build-windows.ps1` | MSVC + Detours 构建（含单测门禁；Detours 经 `DETOURS_ROOT` / 外置 checkout，非 submodule） |
| `foundation/agent-security-dll/native/windows/process/hooks.cpp` | Detours hook、ask、trash 删除、子进程 spawn |
| `foundation/agent-security-dll/native/windows/guard/message_framing.c` | 帧编解码与 spec 白名单 |
| `foundation/agent-security-dll/tests/probe.cpp` | 集成测试靶 |
| `native/.../python/` | 两套 Guard 的公共二进制分发包 `agent-security-dll` |
| `schema/` | 现行 JSON Schema |

### B. 错误码总表

| 错误码 | 产生位置 | 行为 |
|---|---|---|
| `invalid_ruleset` | 请求/规则加载失败 | deny；CLI 退出 2；HTTP 400 |
| `missing_subject` | 缺主体 | 进程内 deny；隔离 PDP 401（响应无 `action`） |
| `missing_ruleset` | 回环 PDP 缺 `ruleset_id` | deny |
| `unknown_ruleset` | 规则集不存在/已注销 | deny；HTTP 409 |
| `unknown_task` | 任务未打开 | deny / 构造 `Decide` 失败 |
| `invalid_event` | 事件非法或 record 夹带规则字段 | deny |
| `host_context_unavailable` | 宿主回调失败/非法 | 该条 record deny |
| `process_identity_mismatch` | 原生操作 身份不符或未绑定 | allow=false |
| `GuardPlatformError` | DLL 防护：非 Windows x64 | 抛异常，不创建执行 |
| `GuardBundleMissingError` / `GuardBundleError` | DLL 防护：DLL 或 manifest 缺失/校验不过 | 抛异常，不创建执行 |
| `GuardStartupError`（含 `GuardPipeError`、`GuardInjectionError`） | DLL 防护：管道或注入失败 | 抛异常；注入失败时挂起进程被终止 |
| `GuardPolicyDenied` | DLL 防护：程序启动策略拒绝 | 杀掉挂起进程并抛异常，不退回裸执行 |
| `version_conflict` / `runtime_relax` / `task_id_in_use` | 注册表 | HTTP 409 |
| `too_large` / `invalid_json` / `invalid_task` / `unauthorized` / `not_found` | HTTP | 400 / 401 / 404 |

### C. 打包与版本

| 包 | 内容 |
|---|---|
| `agent-shield` 0.1.0（根 `pyproject.toml`） | Python ≥3.11；flat 布局（`package-dir` 把本目录映射为 `agent_shield`）；描述为「behavior policy, intercepts, tool permission, and content detection」；依赖 `PyYAML>=6`、`tree-sitter>=0.25,<0.26`、`tree-sitter-bash`、`tree-sitter-pwsh`、`tree-sitter-batch`（方言 AST 为硬依赖，不再回退字符扫描）；`dll-guard` extra 增加 `tld` 与 Windows 专用的 `agent-security-dll==0.3.2`；dev extras：`pytest>=8.0`、`pytest-asyncio>=0.24`、`pytest-cov>=5.0`、`ruff>=0.6`、`jsonschema>=4`、`tld`、`requests`、`cryptography`；入口点 `agent-pdp = agent_shield.policy_engine.server.cli:main`；package-data 含 `py.typed` 与 `tool_permission/runtime/defaults.yaml`。包清单同时列出 `detection`、`tool_permission.*` 与 `intercepts.native_call.dll_guard`（见 12） |

`jiuwenbox` 为独立包（自带 `pyproject.toml`、FastAPI 服务、Linux / Windows 运行时），与 `agent_shield` 分开安装与测试；`execution.plane=sandbox` 不代表调用运行在其中，也不降低风险档。
