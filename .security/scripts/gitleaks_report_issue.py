#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""gitleaks 扫描 + GitCode 安全漏洞 issue 自动创建（CI 流水线用）

放置位置：仓库内任意子目录（二级目录如 ci/scripts/gitleaks_report_issue.py 亦可），
脚本自动向上查找 .git 定位仓库根；扫描源与报告输出均以仓库根为基准，与执行时所在
目录无关。

三种用途（GITLEAKS_MODE 选择，默认 full）：
  a. full    定时全量扫描：发现泄露 -> 按指纹去重后自动创建保密 issue（负责人取
             community SIG 维护者），流水线不因泄露失败；仅 issue 创建失败时退出码 1。
  b. pr      PR 扫描：只扫描本次 PR 的提交（base..HEAD）；发现泄露时在仓库根生成
             JSON 报告作为流水线产物，退出码 1 使流水线不通过；不创建 issue。
  c. release 发版扫描：扫描指定分支（RELEASE_BRANCH，缺省当前检出分支）全部历史；
             发现泄露时生成 JSON 报告产物，退出码 1 使流水线不通过；不创建 issue。

CI 环境变量：
  GITCODE_TOKEN      full 模式必填，GitCode 个人访问令牌（请配置为 CI Secret，切勿写入仓库）
  GITLEAKS_MODE      可选，full（默认）| pr | release
  GITLEAKS_SOURCE    可选，仓库根目录覆盖；缺省自动向上查找 .git
  GITLEAKS_REPORT    可选，JSON 报告路径（相对路径基于仓库根），默认 gitleaks-report.json
  GITLEAKS_CMD       可选，gitleaks 可执行文件名/路径，默认 gitleaks
  --- pr 模式 ---
  PR_BASE_REF        可选，PR 目标分支（如 main）；未设时依次尝试
                     CI_MERGE_REQUEST_TARGET_BRANCH_NAME / GITHUB_BASE_REF / CHANGE_TARGET
  PR_BASE_SHA        可选，PR base 的 commit SHA（优先于 PR_BASE_REF）
  --- release 模式 ---
  RELEASE_BRANCH     可选，要扫描的分支；缺省扫描当前检出分支
  --- full 模式（issue 上报相关）---
  GITCODE_REPO       可选，"owner/repo"；缺省从 git remote origin 自动解析
  GITCODE_SIG        可选，SIG 名称覆盖，默认 sig-{repo}
  GITCODE_COMMUNITY_REPO  可选，SIG 定义所在仓库，默认 openJiuwen/community
  GITCODE_LABELS     可选，逗号分隔的标签（标签需已存在于仓库）
  DRY_RUN            可选，true 时只打印将要提交的 issue，不真正调用创建接口

退出码：0 通过；1 发现泄露（pr/release）或 issue 创建失败（full）；2 配置/环境错误。

用法示例（脚本放在仓库子目录内即可，CI 中在任意目录执行）：

  a. 定时任务：全量扫描 + 自动建保密 issue（发现泄露不挡流水线）
     # GITCODE_TOKEN 由 CI Secret 注入
     python ci/scripts/gitleaks_report_issue.py

  b. PR 流水线：只扫本次 PR 的全部提交（含多个 commit，base..HEAD），
     发现泄露则产出报告并使流水线失败
     # checkout 需完整历史（如 fetch-depth: 0）；无需 GITCODE_TOKEN
     GITLEAKS_MODE=pr PR_BASE_REF=main python ci/scripts/gitleaks_report_issue.py
     # 产物：仓库根 gitleaks-report.json（可用 GITLEAKS_REPORT 改名）
     # base 无法从 CI 变量推断时，显式设置 PR_BASE_REF=目标分支 或 PR_BASE_SHA=base提交

  c. 发版流水线：扫描指定分支全部历史，发现泄露则产出报告并使流水线失败
     GITLEAKS_MODE=release RELEASE_BRANCH=main python ci/scripts/gitleaks_report_issue.py
     # 不设 RELEASE_BRANCH 则扫描当前检出分支；产物同上
"""

import base64
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_BASE = "https://api.gitcode.com/api/v5"
DEFAULT_COMMUNITY_REPO = "openJiuwen/community"

FP_MARK = "gitleaks-fingerprint:"  # 写入 issue 正文的去重标记（HTML 注释，渲染不可见）


def log(msg):
    print(msg, flush=True)


def api(method, path, token, params=None, payload=None):
    """调用 GitCode OpenAPI，返回 (http_status, 解析后的数据或原始错误串)。"""
    url = f"{API_BASE}{path}"
    if params:
        url += "?" + urlencode(params)
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = Request(url, data=data, method=method)
    req.add_header("PRIVATE-TOKEN", token)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8") or "{}"
            return resp.status, json.loads(raw)
    except HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:  # 网络异常等
        return -1, str(e)


def find_repo_root():
    """定位仓库根：脚本可能放在二级子目录，向上逐级查找 .git。"""
    env = os.environ.get("GITLEAKS_SOURCE", "").strip()
    if env:
        return Path(env).resolve()
    here = Path(__file__).resolve().parent
    for p in (here, *here.parents):
        if (p / ".git").exists():
            return p
    log("[WARN] 向上未找到 .git，使用当前工作目录作为扫描根")
    return Path.cwd()


def resolve_report_path(root):
    """报告路径：绝对路径原样使用；相对路径基于仓库根（方便流水线挂产物）。"""
    raw = os.environ.get("GITLEAKS_REPORT", "").strip() or "gitleaks-report.json"
    p = Path(raw)
    return p if p.is_absolute() else (root / p)


def detect_repo():
    """返回 (owner, repo)。优先 GITCODE_REPO 环境变量，否则解析 origin 远端地址。"""
    env_repo = os.environ.get("GITCODE_REPO", "").strip().strip("/")
    if env_repo:
        parts = env_repo.split("/")
        if len(parts) == 2:
            return parts[0], parts[1]
        log(f"[ERROR] GITCODE_REPO 格式应为 owner/repo，当前为: {env_repo}")
        sys.exit(2)

    try:
        out = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True, text=True, check=True,
        )
        url = out.stdout.strip()
    except Exception:
        log("[ERROR] 无法确定目标仓库：请设置 GITCODE_REPO=owner/repo，或在 git 仓库内运行")
        sys.exit(2)

    m = re.search(r"gitcode\.com[/:]([^/]+)/([^/]+?)(?:\.git)?/?$", url)
    if not m:
        log(f"[ERROR] origin 远端不是 gitcode.com 地址: {url}，请设置 GITCODE_REPO=owner/repo")
        sys.exit(2)
    return m.group(1), m.group(2)


def current_branch():
    """当前分支：优先 CI 环境变量，其次 git 命令。"""
    for var in ("CI_COMMIT_REF_NAME", "CI_COMMIT_BRANCH", "GIT_BRANCH",
                "GITHUB_REF_NAME", "BUILD_SOURCEBRANCHNAME"):
        v = os.environ.get(var, "").strip()
        if v:
            return v.removeprefix("refs/heads/")
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True, text=True,
        )
        b = out.stdout.strip()
        if b and b != "HEAD":
            return b
    except Exception:
        pass
    return "未知"


def git_fetch(root, ref):
    """best-effort 拉取远端 ref，供 log-opts 使用；失败仅告警。"""
    proc = subprocess.run(["git", "fetch", "origin", ref],
                          capture_output=True, text=True, cwd=str(root))
    if proc.returncode != 0:
        log(f"[WARN] git fetch origin {ref} 失败（浅克隆场景请将 checkout 设为完整历史）: "
            f"{proc.stderr.strip()[-300:]}")


def pr_log_opts(root):
    """PR 模式：只扫描本次 PR 提交（base..HEAD）。"""
    base_sha = os.environ.get("PR_BASE_SHA", "").strip()
    if base_sha:
        return f"{base_sha}..HEAD"

    base_ref = os.environ.get("PR_BASE_REF", "").strip()
    if not base_ref:
        for var in ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "GITHUB_BASE_REF",
                    "CHANGE_TARGET", "CI_COMMIT_TARGET_BRANCH"):
            v = os.environ.get(var, "").strip()
            if v:
                base_ref = v
                log(f"[*] 从 {var} 获取 PR 目标分支: {v}")
                break
    if not base_ref:
        log("[ERROR] pr 模式无法确定 PR 目标分支：请设置 PR_BASE_REF 或 PR_BASE_SHA")
        sys.exit(2)

    git_fetch(root, base_ref)
    return f"origin/{base_ref}..HEAD"


def release_log_opts(root, branch):
    """release 模式：扫描指定分支全部历史；缺省扫描当前检出分支。"""
    want = os.environ.get("RELEASE_BRANCH", "").strip()
    if not want or want == branch:
        if want:
            log(f"[*] RELEASE_BRANCH 与当前检出分支一致，扫描当前分支全部历史")
        return None
    git_fetch(root, want)
    return f"origin/{want}"


def run_gitleaks(root, report_path, log_opts=None):
    """执行 gitleaks 扫描，返回退出码。"""
    cmd = os.environ.get("GITLEAKS_CMD", "gitleaks")
    exe = [cmd, "detect", "--source", str(root), "--no-banner",
           "--report-format", "json", "--report-path", str(report_path)]
    if log_opts:
        exe += ["--log-opts", log_opts]
    log(f"[*] 执行扫描: {' '.join(exe)}")
    try:
        proc = subprocess.run(exe, capture_output=True, text=True)
    except FileNotFoundError:
        log(f"[ERROR] 未找到 gitleaks 命令（{cmd}），请先安装并在 PATH 中")
        return -1
    if proc.stderr:
        log(proc.stderr.strip()[-2000:])
    return proc.returncode


def load_findings(report_path):
    """读取 gitleaks JSON 报告，返回 findings 列表；报告不存在返回 None。"""
    p = Path(report_path)
    if not p.exists():
        return None
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return []
    data = json.loads(text)
    return data if isinstance(data, list) else []


def collect_existing_fingerprints(token, owner, repo):
    """翻页拉取仓库全部 issue，从正文中提取已上报的指纹集合，用于去重。"""
    fps = set()
    page = 1
    while page <= 100:
        code, data = api("GET", f"/repos/{owner}/{repo}/issues", token,
                         params={"state": "all", "per_page": "100", "page": str(page)})
        if code != 200 or not isinstance(data, list):
            if page == 1:
                log(f"[WARN] 获取已有 issue 失败（HTTP {code}），本次不做去重: {data}")
            break
        if not data:
            break
        for it in data:
            body = it.get("body") or ""
            fps.update(re.findall(re.escape(FP_MARK) + r"\s*(\S+)", body))
        page += 1
    return fps


def fetch_file(token, owner, repo, path, ref="main"):
    """通过 contents 接口拉取仓库文件文本；失败返回 None。"""
    code, data = api("GET", f"/repos/{owner}/{repo}/contents/{path}", token,
                     params={"ref": ref})
    if code != 200 or not isinstance(data, dict):
        return None
    content = data.get("content", "")
    try:
        if data.get("encoding") == "base64":
            return base64.b64decode(content).decode("utf-8")
        return content
    except Exception:
        return None


def parse_maintainers(yaml_text):
    """极简 YAML 解析：仅提取顶层 maintainers 块中的 atomgit_id（忽略 committers 等）。"""
    ids = []
    in_maintainers = False
    for line in yaml_text.splitlines():
        top = re.match(r"^([A-Za-z][\w-]*)\s*:", line)  # 顶层键（列 0，排除 "- xxx" 列表项）
        if top:
            in_maintainers = top.group(1) == "maintainers"
            continue
        if in_maintainers:
            m = re.match(r"^\s*-?\s*atomgit_id\s*:\s*(.+?)\s*$", line)
            if m:
                ids.append(m.group(1).strip("\"'"))
    return ids


def parse_repositories(yaml_text):
    """极简 YAML 解析：提取顶层 repositories 块中的 owner/repo 条目。"""
    out = []
    in_r = False
    for line in yaml_text.splitlines():
        top = re.match(r"^([A-Za-z][\w-]*)\s*:", line)
        if top:
            in_r = top.group(1) == "repositories"
            continue
        if in_r:
            m = re.match(r"^\s*-\s*([\w.-]+/[\w.-]+)\s*$", line)
            if m:
                out.append(m.group(1))
    return out


def resolve_assignees(token, owner, repo):
    """issue 负责人列表：解析 community SIG 的 maintainers.atomgit_id；失败返回空列表（不设默认负责人）。"""
    comm_owner, comm_repo = DEFAULT_COMMUNITY_REPO.split("/")
    full = f"{owner}/{repo}"
    sig = os.environ.get("GITCODE_SIG", "").strip() or f"sig-{repo}"

    text = fetch_file(token, comm_owner, comm_repo, f"sigs/{sig}/sig-info.yaml")
    if text is not None:
        ids = parse_maintainers(text)
        if ids:
            log(f"[*] 已解析 {sig} 维护者: {', '.join(ids)}")
            return ids

    # SIG 名不遵循 sig-{repo} 约定时（如 DataSwarm->sig-dataswarm），反查各 SIG 的 repositories
    code, data = api("GET", f"/repos/{comm_owner}/{comm_repo}/contents/sigs", token,
                     params={"ref": "main"})
    if code == 200 and isinstance(data, list):
        for d in data:
            if d.get("type") != "dir" or d.get("name") == sig:
                continue
            t = fetch_file(token, comm_owner, comm_repo, f"sigs/{d['name']}/sig-info.yaml")
            if t and full in parse_repositories(t):
                ids = parse_maintainers(t)
                if ids:
                    log(f"[*] 反查命中 {d['name']} 维护者: {', '.join(ids)}")
                    return ids

    log(f"[WARN] {full} 未找到对应 SIG 维护者，本次不指定负责人")
    return []


def escape_cell(text):
    """markdown 表格单元格转义。"""
    return str(text or "").replace("|", "\\|").replace("\n", " ").strip()


def build_issue(finding, branch, full_repo):
    """按用户要求拼装标题与正文（不含泄露内容本身）。"""
    rule = escape_cell(finding.get("RuleID")) or "未知规则"
    fp = escape_cell(finding.get("Fingerprint"))
    commit = escape_cell(finding.get("Commit"))
    date = escape_cell(finding.get("Date")) or "未知"
    author = escape_cell(finding.get("Author")) or "未知"
    email = escape_cell(finding.get("Email"))
    committer = f"{author} <{email}>" if email else author
    file_loc = f"{escape_cell(finding.get('File'))}:{finding.get('StartLine', '?')}"
    message = escape_cell(finding.get("Message")) or "（无提交信息）"
    desc = escape_cell(finding.get("Description"))

    title = f"<安全漏洞>:疑似{rule}规则的泄露"

    body = f"""<!-- {FP_MARK} {fp} -->

## CVE 编号
`{rule}` 规则（gitleaks RuleID）

## 严重程度
未知（Unknown）

## 解决办法
仓库负责人判断是否需要吊销，还是误报。如果属于误报，增加仓库级别的 `.gitleaksignore` 文件，把误报项的指纹填写进去，当再次扫描时可以降低噪音。

如确认为误报，将下方指纹加入仓库根目录的 `.gitleaksignore`：

```
{fp}
```

## 泄露详情
| 项目 | 内容 |
| --- | --- |
| 仓库 | {full_repo} |
| 指纹 (Fingerprint) | `{fp}` |
| 提交时间 | {date} |
| 提交人 | {committer} |
| 分支 | {branch} |
| Commit ID | `{commit}` |
| 文件位置 | {file_loc} |
| 提交信息 | {message} |
| 检测描述 | {desc} |

> 本 issue 由 CI 流水线中的 gitleaks 扫描脚本自动创建，属于保密 issue（security_hole），修复前社区用户不可见。
"""
    return title, body


def gate_fail(findings, report_path):
    """pr/release 模式：打印摘要并让流水线失败。"""
    log(f"[*] 扫描报告产物: {report_path}")
    if not findings:
        log("[OK] 扫描完成，未发现泄露，流水线通过")
        return
    log(f"[FAIL] 发现 {len(findings)} 条疑似泄露，流水线不通过（退出码 1）")
    for f in findings[:20]:
        log(f"  - {f.get('RuleID')} | {f.get('File')}:{f.get('StartLine')}"
            f" | commit {str(f.get('Commit'))[:8]} | 指纹 {f.get('Fingerprint')}")
    if len(findings) > 20:
        log(f"  ... 其余 {len(findings) - 20} 条见报告文件")
    sys.exit(1)


def main():
    mode = os.environ.get("GITLEAKS_MODE", "full").strip().lower() or "full"
    if mode not in ("full", "pr", "release"):
        log(f"[ERROR] GITLEAKS_MODE 仅支持 full/pr/release，当前: {mode}")
        sys.exit(2)

    root = find_repo_root()
    report_path = resolve_report_path(root)
    branch = current_branch()
    log(f"[*] 模式: {mode} | 仓库根: {root} | 分支: {branch}")

    log_opts = None
    if mode == "pr":
        log_opts = pr_log_opts(root)
    elif mode == "release":
        log_opts = release_log_opts(root, branch)

    rc = run_gitleaks(root, report_path, log_opts)
    findings = load_findings(report_path)
    if findings is None:
        log(f"[ERROR] 扫描失败且无报告文件（gitleaks 退出码 {rc}）；"
            f"浅克隆场景请将 checkout 设为完整历史（fetch-depth: 0）")
        sys.exit(2)
    # 退出码仅作日志：0=无泄露；非零=发现泄露或异常，以报告文件内容为准（不同版本退出码不同）

    if mode in ("pr", "release"):
        gate_fail(findings, report_path)
        return

    # ---------- full 模式：定时扫描 + issue 自动上报 ----------
    token = os.environ.get("GITCODE_TOKEN", "").strip()
    if not token:
        log("[ERROR] 请通过环境变量 GITCODE_TOKEN 提供 GitCode 个人访问令牌")
        sys.exit(2)

    owner, repo = detect_repo()
    assignees = resolve_assignees(token, owner, repo)
    assignee_str = ",".join(assignees)
    labels = os.environ.get("GITCODE_LABELS", "").strip()
    dry_run = os.environ.get("DRY_RUN", "").strip().lower() in ("1", "true", "yes")

    log(f"[*] 目标仓库: {owner}/{repo} | 负责人: {assignee_str or '无（SIG 未解析到维护者）'}"
        + (" | DRY_RUN" if dry_run else ""))

    if not findings:
        log("[OK] 扫描完成，未发现泄露")
        return

    # 按指纹去重（同一次报告中可能出现重复指纹）
    uniq = {}
    for f in findings:
        fp = f.get("Fingerprint")
        if fp:
            uniq.setdefault(fp, f)
    log(f"[*] 扫描发现 {len(findings)} 条，按指纹去重后 {len(uniq)} 条")

    existing = collect_existing_fingerprints(token, owner, repo)
    todo = [f for fp, f in uniq.items() if fp not in existing]
    skipped = len(uniq) - len(todo)
    if skipped:
        log(f"[*] 跳过已上报过的指纹 {skipped} 条")

    if not todo:
        log("[OK] 所有泄露均已上报过，无需新建 issue")
        return

    created = failed = 0
    for f in todo:
        title, body = build_issue(f, branch, f"{owner}/{repo}")
        payload = {
            "repo": repo,
            "title": title,
            "body": body,
            "security_hole": "true",  # 保密 issue：修复前社区用户不可见
        }
        if assignees:
            # 创建接口的 assignee 只认单个，多负责人靠创建后 PATCH 补齐
            payload["assignee"] = assignees[0]
        if labels:
            payload["labels"] = labels

        if dry_run:
            log("-" * 60)
            log(f"[DRY_RUN] 标题: {title}")
            log(f"[DRY_RUN] 负责人: {assignee_str}")
            log(f"[DRY_RUN] 正文:\n{body}")
            continue

        code, resp = api("POST", f"/repos/{owner}/issues", token, payload=payload)
        if code in (200, 201) and isinstance(resp, dict):
            created += 1
            number = resp.get("number")
            log(f"[OK] 已创建 issue #{number}: {resp.get('html_url', title)}")
            if len(assignees) > 1 and number:
                pcode, presp = api(
                    "PATCH", f"/repos/{owner}/{repo}/issues/{number}", token,
                    payload={"assignee": assignee_str})
                if pcode == 200:
                    log(f"[OK] 已补齐全部负责人: {assignee_str}")
                else:
                    log(f"[WARN] 补齐多负责人失败（HTTP {pcode}），"
                        f"issue #{number} 仅保留 {assignees[0]}: {presp}")
        else:
            failed += 1
            log(f"[ERROR] 创建 issue 失败（HTTP {code}）: {title} -> {resp}")
        time.sleep(0.3)  # 轻微限速

    log("-" * 60)
    log(f"[*] 完成: 新建 {created} 个 issue，失败 {failed} 个")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
