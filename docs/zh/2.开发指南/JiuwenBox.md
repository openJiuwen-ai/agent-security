# JiuwenBox

JiuwenBox（包名 `jiuwenbox`）是一个沙箱服务。它用 FastAPI 管理沙箱的创建、停止、文件传输和命令执行，把 Agent 发起的命令放进受策略约束的环境里运行。

安装、启动参数、策略字段和完整 HTTP 接口以 [jiuwenbox/README_CN.md](../../../jiuwenbox/README_CN.md) 与 [jiuwenbox_server_api.md](../../../jiuwenbox/docs/jiuwenbox_server_api.md) 为准。

---

## 1. 它解决什么问题

Agent 执行命令时，默认拥有和宿主进程差不多的权限：能读 `~/.ssh`，能写 `/etc`，能连任意地址，也能删除工作区外的文件。只靠命令文本检查不够，因为命令可以混淆、可以拼接，也可以启动子进程绕过。

JiuwenBox 的做法是换一个执行环境：命令不直接在宿主机上跑，而是在沙箱里跑；沙箱能看到哪些目录、能连哪些地址、能不能删除，由策略文件决定。策略之外的请求直接失败，不会悄悄降级成裸进程。

## 2. 一次沙箱使用流程

典型流程如下：

1. **启动服务。** 安装后运行 `jiuwenbox-server`，默认监听 `0.0.0.0:8321`；也可以改用 Unix Domain Socket。
2. **创建沙箱。** 调用 `POST /api/v1/sandboxes`，可以指定 `sandbox_id`、`env`、`policy` 和 `sandbox_runtime`。创建成功后返回 `phase=ready` 的沙箱引用。
3. **执行命令或传文件。** 用 `POST /api/v1/sandboxes/{id}/exec` 同步执行，或用 `exec_background` 启动后台任务；文件和目录通过 `upload`、`download`、`files`、`search` 操作。
4. **按需做文件条件替换。** 用 `file-snapshot` 读取文件，或按期望的 SHA-256 做 compare-and-swap 写入。
5. **停止或删除。** 用 `stop`、`restart` 控制生命周期，用 `DELETE` 删除沙箱。

用 CLI 表达就是：

```bash
jiuwenbox health
ID=$(jiuwenbox sandbox create | jq -r .id)
jiuwenbox sandbox exec "$ID" -- python3 -c 'print("hi")'
jiuwenbox sandbox upload "$ID" ./data.csv /tmp/data.csv
jiuwenbox sandbox rm "$ID" --yes
```

## 3. 代码怎么分

| 目录 | 职责 |
| --- | --- |
| `jiuwenbox/src/jiuwenbox/server` | 服务：生命周期、策略加载、审计、路由、运行时选择 |
| `jiuwenbox/src/jiuwenbox/server/runtime` | 运行时适配层：`bubblewrap` 与 `windows` 两套实现，`conch` 为保留名称 |
| `jiuwenbox/src/jiuwenbox/supervisor` | 把策略翻译成隔离措施：bwrap、Landlock、seccomp、cgroup、网络，以及 Windows 的 `win_*` 模块 |
| `jiuwenbox/src/jiuwenbox/native` | Windows 软删除 DLL 等原生组件 |
| `jiuwenbox/src/jiuwenbox/models` | 策略、沙箱和接口的数据模型 |
| `jiuwenbox/src/jiuwenbox/proxy` | 推理请求的隐私代理，负责路由和密钥注入 |
| `jiuwenbox/src/jiuwenbox/configs` | 随包提供的策略样例 |

策略样例包括 `default-policy.yaml`、`code-agent-policy.yaml`、`enterprise-policy.yaml`、`inference-policy.yaml`、`java-policy.yaml` 和 `windows-policy.yaml`。未设置 `JIUWENBOX_POLICY_PATH` 时，服务使用包内的 `default-policy.yaml`。

## 4. 运行时怎么选

| 优先级 | 来源 |
| --- | --- |
| 1 | 创建请求里的 `sandbox_runtime` |
| 2 | 环境变量 `JIUWENBOX_RUNTIME_PROFILE` |
| 3 | 平台默认：Windows 用 `windows`，Linux 用 `bubblewrap` |

`conch` 预留给 AgentOS 云端后端，需要显式指定且依赖对应 SDK；当前仓库没有该适配器，指定后会直接失败，不会退回其它运行时。

`GET /api/v1/capabilities` 会报告每个运行时的可用性和能力集，包括本地 PID、后台任务、快速文件 IO、递归搜索、文件 ACL、进程树约束、出站过滤和软删除。调用方应在部署前先探测，不要把某种能力当成所有运行时都支持。

## 5. Linux 上的隔离

Linux 运行时用 bubblewrap 启动沙箱进程。策略还可以叠加：

- **文件系统**：`read_only`、`read_write`、`bind_mounts`、`directories`、`files` 和 `device` 决定沙箱能看到哪些路径。
- **命名空间**：user、pid、ipc、cgroup、uts 可以分别打开或复用。
- **Landlock**：`best_effort` 在支持时启用，`hard_requirement` 在不支持时直接让启动失败。
- **seccomp**：按 x86_64 / arm64 配置要拦截的系统调用。
- **网络**：`isolated` 模式创建独立网络命名空间，通过 veth uplink 连接宿主机，并在沙箱 netns 内安装 egress / ingress 规则；`host` 模式共享宿主机网络，不安装这些规则。
- **cgroup**：可选限制内存、CPU 和进程数。

并发创建沙箱时，jiuwenbox 会等待 xtables 锁，避免 iptables 竞争导致创建失败。需要跑 JavaScript 时，环境里要有 nodejs。

## 6. Windows 上的隔离

Windows 运行时面向 Windows x64，首次使用需要管理员完成账户、WFP 和 ACL 安装。隔离由几层共同完成：

| 层 | 作用 |
| --- | --- |
| 受限令牌 | 用 `jbx-sandbox` 账户两跳启动进程，沙箱进程不继承服务端权限 |
| Job Object | 限制内存、CPU 速率和进程数，关闭 Job 时终止整棵进程树 |
| WFP | 按沙箱用户 SID 阻断出站，只放行回环代理端口 |
| 回环代理 | HTTP CONNECT / SOCKS5 代理，按策略过滤域名、IP 和端口 |
| NTFS ACL | 为沙箱用户设置允许/拒绝读写；策略里的 `read_only` 转成 `deny_write` |
| 软删除 | `JIUWENBOX_SOFT_DELETE=1` 时删除先进回收站，失败转到同卷归档目录 |

`windows-policy.yaml` 使用独立的 `windows` 配置块：`filesystem` 下是 ACL 允许/拒绝列表与 `tool_paths`，`proxy` 下是端口范围，`network.mode` 取 `wfp_loopback_proxy` 或 `disabled`，`resource` 下是内存、CPU 和进程数上限。Linux 专有的 `process`、`namespace`、`capabilities`、`landlock`、`syscall`、`cgroup` 和 `network.uplink` 在 Windows 上会被忽略。

## 7. 策略怎么生效

服务启动时加载一份根策略。创建沙箱时，请求里的 `policy` 可以按 `policy_mode` 覆盖或追加：

- `override`：用请求里的策略替换根策略。
- `append`：在根策略上追加目录、路径或网络规则。

已存在的沙箱会继续使用创建时写入的策略，修改启动策略文件需要重启服务。`GET /api/v1/policies/{sandbox_id}` 可以查看某个沙箱当前生效的策略。

## 8. 接口与部署形态

| 入口 | 说明 |
| --- | --- |
| REST API | `/health`、`/api/v1/sandboxes/*`、`/api/v1/policies/*`、`/api/v1/timeout`、`/api/v1/proxies/*` |
| 能力探测 | `GET /api/v1/capabilities` 报告可用运行时及其能力 |
| 文件快照 | `POST /api/v1/sandboxes/{id}/file-snapshot` 在沙箱内读取文件，或按期望状态做原子替换 |
| CLI | `jiuwenbox` 命令封装常用接口，支持 `http://` 与 `unix:///` |
| MCP | `/mcp`（Streamable HTTP），当前提供 `sandbox_run_command` |
| 传输 | TCP 或 Unix Domain Socket，由 `JIUWENBOX_LISTEN` 选择 |
| 认证 | 设置 `JIUWENBOX_API_TOKEN` 后所有端点要求 Bearer token |
| 仅代理模式 | 策略只配置 `inference_privacy_proxies` 且 `listen_port > 0` 时，跳过沙箱子系统，只提供代理 |

`file-snapshot` 有两种操作。`read` 返回文件是否存在、SHA-256 与大小，路由再附 `content_base64`；`compare_replace` 要求同时给出 `options.expected_exists` 与 `options.expected_content_sha256`，在同一把锁下比较后，用临时文件加原子替换发布。冲突返回 `conflict`，锁超时返回 `lock_timeout`，写入传输失败返回 `outcome_unknown` 且不应重放。路径必须是绝对路径，不能经过符号链接或重解析点；单文件上限 256 MiB。该能力目前由 bubblewrap 运行时实现，其它运行时返回 `unsupported`。

## 9. 和本仓库其它组件的关系

JiuwenBox 是独立服务。Agent SSAS 不负责创建沙箱；agent-shield 也不启动这个服务，它的 Windows 原生防护与服务端沙箱是两套独立机制。调用方自己持有沙箱地址，按 README 和接口文档管理沙箱。
