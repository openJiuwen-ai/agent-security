# daily_vuln_bot

每日扫描 GitHub `openJiuwen-ai` 全部 public 仓默认分支的 Scorecard 漏洞，补全包名/引入位置，并（可选）向 GitCode 对应仓创建**保密安全 Issue**（`security_hole=true`）。

逻辑对齐根目录 [gitleaks_report_issue.py](../gitleaks_report_issue.py) 的 full 模式。

## 流程

1. **Scorecard 扫描**：逐仓生成 `reports/daily/<stamp>/scorecard/<repo>__default-<branch>.json`
   - 可选：浅克隆 + osv-scanner 补全「引入位置」（`--skip-clone` 跳过）
2. **汇总**：仅保留 Critical / High / Medium → `vulns.json`、`vuln-detail.csv`、`issue_drafts/`
3. **上报**（`--report`）：
   - **去重**：翻页拉取该仓 **open** 状态 issue（已关闭的不参与去重，关闭即不再跟踪），
     正文首行 HTML 注释 `<!-- osv-fingerprint: openJiuwen/<repo>@<branch>:<OSV_ID> -->`
     精确命中、或标题含 `OSV:<ID>`（兼容旧版 issue）即跳过；
     拉取失败则**整仓跳过**，宁可不上报也不重复建单
   - **负责人**：`openJiuwen/community` 仓库 `sigs/<sig>/sig-info.yaml` 中 `repositories`
     对应本仓的 **第一个 `maintainers.atomgit_id`**；SIG 名不按 `sig-<repo>` 约定时
     （如 `DataSwarm` → `sig-dataswarm`）通过 `repositories` 反查；未找到则不指定负责人
   - 创建时 POST 带 `assignee`；响应里负责人未生效则 PATCH
     `/repos/{owner}/{repo}/issues/{number}` 补齐（对齐 gitleaks）；带负责人被 403 时
     去掉负责人重试并打印原因（PAT 无指派权限 / 负责人非仓库成员）

## 模块

| 文件 | 职责 |
| --- | --- |
| `config.py` | 路径、org/owner、等级、`FP_MARK`、token 读取 |
| `scan.py` | 列仓库、跑 Scorecard（docker）、提取 OSV id、浅克隆 |
| `enrich.py` | OSV 元数据 + osv-scanner 结果 → `VulnRow` |
| `osv_util.py` | osv.dev 查询 / 等级 / 缓存 |
| `gitcode.py` | 统一 `api()`、SIG 解析（`load_sig_index` / `resolve_assignee`）、远程指纹去重、创建保密 issue |
| `report.py` | 指纹、标题/正文、草稿、`report_plan()` 上报 |
| `__main__.py` | 串流程：扫描 → 汇总 → 上报 |

## 环境变量

- `GITHUB_AUTH_TOKEN`（或 `GITHUB_TOKEN` / `GH_TOKEN`）：GitHub API + Scorecard + clone，必填
- `GITCODE_TOKEN`（或 `ATOMGIT_TOKEN`）：GitCode PAT。`--report` 必填；不传时仅扫描 + 草稿，责任人列留空
- `GITCODE_LABELS`：可选，逗号分隔标签（标签需已存在于仓库）
- `DRY_RUN=true`：等价 `--dry-run`
- `GITCODE_REPORT_CONTACT`：可选，报告人联系方式
- 本机需 Docker：`ghcr.io/ossf/scorecard:latest`、`ghcr.io/google/osv-scanner:latest`

## 常用命令

在 `Security` 根目录：

```bash
# 只扫描 + 写 JSON/CSV/草稿，不上传（默认）
python -m daily_vuln_bot

# 只扫个别仓；跳过 clone 更快
python -m daily_vuln_bot --repos agent-dx jiuwenswarm --skip-clone

# 带 --report 但不真正 POST：先看远程去重结果与将要提交的内容
python -m daily_vuln_bot --repos agent-security --report --dry-run

# 实际创建保密 Issue（去重 + SIG 负责人）
python -m daily_vuln_bot --repos agent-security --max-new-issues 5 --report

# 单条漏洞测试（走同一套去重链路）
python test_report_one_vuln.py --check     # 只查远程是否已上报
python test_report_one_vuln.py --submit    # 已上报则跳过
```

退出码：`0` 通过；`1` 有 issue 创建失败 / 去重拉取失败；`2` 配置错误。

## 产物

`reports/daily/<时间戳>/`

- `scorecard/*.json`：每仓 Scorecard 原始结果
- `vulns.json`：待上报漏洞（含指纹、等级、包、位置、负责人、SIG、标题）
- `vuln-detail.csv`
- `issue_drafts/`：每条 Issue 的标题/正文草稿 + `index.json`
- `report-results.json`：`--report` 时每条的状态（`created` / `skipped_existing` / `dry_run` / `error` / `skipped_fetch_failed`）
- `summary.json`

## 定时任务

```powershell
.\register-daily-task.ps1              # 仅扫描 + 草稿
.\register-daily-task.ps1 -WithReport  # 自动上报
```

## 相关脚本

- `followup_vuln_issues.py`：按 Issue 正文（`分支` / `责任人` / `受影响包` / `引入位置`）汇总跟催。注意负责人现在是 SIG 的 `atomgit_id`，不再是「姓名 工号」格式。
- `gitleaks_report_issue.py`：密钥泄露扫描 + 建单（本包上报逻辑的参考实现）。
