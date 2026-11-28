"""漏洞 → GitCode 保密 issue：指纹去重、负责人（SIG 第一个 maintainer）、正文拼装与上报。"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .config import (
    DEFAULT_MAX_NEW_ISSUES,
    FP_MARK,
    GITCODE_OWNER,
    LEVEL_RANK,
    gitcode_token,
    report_contact,
)
from .enrich import VulnRow
from .gitcode import (
    collect_existing_fingerprints,
    create_security_issue,
    issue_has_assignee,
    issue_html_url,
    patch_issue_assignee,
    resolve_assignee,
)


def log(msg):
    print(msg, flush=True)


SEVERITY_LABEL = {
    "Critical": "严重（Critical）",
    "High": "高（High）",
    "Medium": "中等（Moderate）",
    "Low": "低（Low）",
    "Unknown": "未知(Unknown)",
}

NO_ASSIGNEE = "未匹配（SIG 未找到维护者）"


def fingerprint(repo: str, branch: str, osv_id: str, owner: str = GITCODE_OWNER) -> str:
    """去重指纹：owner/repo@branch:OSV_ID，写入 issue 正文 HTML 注释。"""
    return f"{owner}/{repo}@{branch}:{osv_id}"


def osv_marker(osv_id: str) -> str:
    return f"OSV:{osv_id}"


def _short_pkg(pkg: str) -> str:
    """取首个包名@version，去掉 ecosystem / 多余项。"""
    pkg = (pkg or "").strip().replace("\n", " ")
    if not pkg:
        return ""
    first = pkg.split(";")[0].strip()
    # "anyio@4.13.0 (PyPI)" -> "anyio@4.13.0"
    if " (" in first:
        first = first.split(" (", 1)[0].strip()
    if len(first) > 40:
        first = first[:37] + "..."
    return first


def issue_title(row: VulnRow) -> str:
    """短标题：<安全漏洞>: [等级] 包名 OSV:编号。"""
    pkg = _short_pkg(row.受影响包)
    parts = [f"<安全漏洞>: [{row.漏洞等级}]"]
    if pkg:
        parts.append(pkg)
    parts.append(osv_marker(row.漏洞编号))
    return " ".join(parts)


def issue_body(row: VulnRow, assignee: str | None = None, sig: str | None = None) -> str:
    """
    Issue 正文：CVE / 影响程度 / 补丁 / 解决方法 / 参考资料 / CWE / 严重程度 / 报告人。
    首行为去重指纹（HTML 注释）；字段便于 followup_vuln_issues.py 解析。
    """
    pkg = row.受影响包 or "（扫描未解析到包名，见 OSV）"
    path = row.引入位置 or "（扫描未定位到 lockfile/manifest，见 OSV 声明）"
    sev = SEVERITY_LABEL.get(row.漏洞等级, SEVERITY_LABEL["Unknown"])
    owner_text = assignee or NO_ASSIGNEE
    if assignee and sig:
        owner_text += f"（{sig} 第一个维护者）"
    impact = (
        f"第三方依赖安全风险（Scorecard/OSV）。\n"
        f"- 仓库：{GITCODE_OWNER}/{row.仓名}\n"
        f"- 分支：{row.分支}\n"
        f"- 责任人：{owner_text}\n"
        f"- 受影响包：{pkg}\n"
        f"- 引入位置：{path}\n"
        f"- 描述：{row.漏洞描述 or '（无）'}"
    )
    patch = (
        f"将受影响包升级到 OSV 标明的修复版本，并更新相关 lockfile/manifest"
        f"（如 `{path}`）。参考：https://osv.dev/{row.漏洞编号}"
    )
    workaround = "暂无通用临时缓解；请评估业务路径是否实际使用受影响 API。"
    refs = f"https://osv.dev/{row.漏洞编号}"
    # 保留网页抓包中的段落间距，便于平台渲染
    return (
        f"<!-- {FP_MARK} {fingerprint(row.仓名, row.分支, row.漏洞编号)} -->\n\n"
        f"### CVE 编号\n            \n{row.漏洞编号}\n"
        f"### 影响程度\n            \n{impact}\n"
        f"### 补丁\n            \n{patch}\n"
        f"### 解决方法\n            \n{workaround}\n"
        f"### 参考资料\n            \n{refs}\n"
        f"### 常见弱点枚举（CWE）\n            \n\n"
        f"### 严重程度\n            \n{sev}\n"
        f"### 报告人信息\n            \n{report_contact()}\n"
    )


@dataclass
class ReportPlanItem:
    key: str  # 去重指纹
    row: VulnRow
    title: str
    body: str
    assignee: str | None
    sig: str | None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "repo": self.row.仓名,
            "branch": self.row.分支,
            "osv_id": self.row.漏洞编号,
            "level": self.row.漏洞等级,
            "package": self.row.受影响包,
            "location": self.row.引入位置,
            "assignee": self.assignee,
            "sig": self.sig,
            "title": self.title,
        }


def sort_rows(rows: list[VulnRow]) -> list[VulnRow]:
    return sorted(
        rows,
        key=lambda r: (
            LEVEL_RANK.get(r.漏洞等级, 9),
            r.仓名.lower(),
            r.漏洞编号,
        ),
    )


def build_items(
    rows: list[VulnRow],
    sig_index: dict | None = None,
    max_new: int = DEFAULT_MAX_NEW_ISSUES,
) -> list[ReportPlanItem]:
    """按等级排序、截断 max_new，逐条解析负责人并拼装标题/正文。"""
    sig_index = sig_index or {}
    cache: dict[str, tuple] = {}
    items: list[ReportPlanItem] = []
    for r in sort_rows(rows):
        if len(items) >= max_new:
            break
        if r.仓名 not in cache:
            cache[r.仓名] = resolve_assignee(r.仓名, sig_index)
        assignee, sig = cache[r.仓名]
        items.append(
            ReportPlanItem(
                key=fingerprint(r.仓名, r.分支, r.漏洞编号),
                row=r,
                title=issue_title(r),
                body=issue_body(r, assignee, sig),
                assignee=assignee,
                sig=sig,
            )
        )
    return items


def write_drafts(items: list[ReportPlanItem], out_dir: Path) -> Path:
    """Write issue drafts for manual testing; does NOT call GitCode API."""
    drafts = out_dir / "issue_drafts"
    drafts.mkdir(parents=True, exist_ok=True)
    index = []
    for i, item in enumerate(items, 1):
        safe_id = item.row.漏洞编号.replace("/", "_")
        fname = f"{i:03d}_{item.row.仓名}_{safe_id}.md"
        path = drafts / fname
        content = (
            f"<!-- key: {item.key} -->\n"
            f"<!-- assignee: {item.assignee or '(none)'} -->\n"
            f"<!-- DO NOT auto-upload; use --report to POST -->\n\n"
            f"# {item.title}\n\n"
            f"{item.body}\n"
        )
        path.write_text(content, encoding="utf-8")
        d = item.to_dict()
        d["draft"] = path.name
        index.append(d)
    (drafts / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return drafts


def is_reported(item: ReportPlanItem, existing: tuple[set[str], set[str]]) -> bool:
    """existing = (fingerprints, osv_ids)；正文指纹精确命中，或标题 OSV 编号命中（兼容旧版）。"""
    fingerprints, osv_ids = existing
    return item.key in fingerprints or item.row.漏洞编号 in osv_ids


def report_plan(
    items: list[ReportPlanItem],
    *,
    token: str | None = None,
    dry_run: bool = False,
    labels: str | None = None,
    sleep_sec: float = 0.5,
) -> list[dict]:
    """
    上报（对齐 gitleaks_report_issue.py 的 full 模式）：
      1. 按仓库分组，翻页拉取该仓全部 issue，从正文提取已上报指纹
      2. 跳过已上报指纹；拉取失败则整仓跳过（避免去重失效造成重复）
      3. 创建保密 issue（security_hole=true）；带负责人被 403 时去掉负责人重试
    返回每条结果：status ∈ created / skipped_existing / dry_run / error / skipped_fetch_failed
    """
    token = token or gitcode_token()
    if not token:
        raise RuntimeError("GITCODE_TOKEN is required for --report")

    by_repo: dict[str, list[ReportPlanItem]] = {}
    for it in items:
        by_repo.setdefault(it.row.仓名, []).append(it)

    results: list[dict] = []
    for repo, repo_items in by_repo.items():
        existing = collect_existing_fingerprints(token, GITCODE_OWNER, repo)
        if existing is None:
            log(f"[WARN] {repo}: 无法获取已有 issue，为避免重复本次跳过 {len(repo_items)} 条")
            results += [
                {"key": it.key, "repo": repo, "status": "skipped_fetch_failed"}
                for it in repo_items
            ]
            continue

        todo = [it for it in repo_items if not is_reported(it, existing)]
        skipped = len(repo_items) - len(todo)
        if skipped:
            log(f"[*] {repo}: 跳过已上报 {skipped} 条")
            results += [
                {"key": it.key, "repo": repo, "status": "skipped_existing"}
                for it in repo_items if is_reported(it, existing)
            ]
        if not todo:
            log(f"[OK] {repo}: 全部已上报，无需新建")
            continue

        for it in todo:
            if dry_run:
                log("-" * 60)
                log(f"[DRY_RUN] {repo} | 负责人: {it.assignee or '无'} | 标题: {it.title}")
                log(f"[DRY_RUN] 正文:\n{it.body}")
                results.append(
                    {
                        "key": it.key,
                        "repo": repo,
                        "status": "dry_run",
                        "assignee": it.assignee,
                        "title": it.title,
                    }
                )
                continue

            code, resp = create_security_issue(
                token, GITCODE_OWNER, repo, it.title, it.body,
                assignee=it.assignee, labels=labels,
            )
            if code == 403 and it.assignee:
                log(f"[WARN] {repo}: 带负责人 {it.assignee} 创建被拒（HTTP 403），改为不指定负责人重试")
                code, resp = create_security_issue(
                    token, GITCODE_OWNER, repo, it.title, it.body, labels=labels
                )
            if code in (200, 201) and isinstance(resp, dict):
                number = resp.get("number") or resp.get("iid") or resp.get("id")
                html = resp.get("html_url") or issue_html_url(repo, number)
                assignee_applied = issue_has_assignee(resp, it.assignee)
                # 对齐 gitleaks：创建接口未带上负责人时，PATCH 补齐
                if it.assignee and not assignee_applied and number:
                    pcode, presp = patch_issue_assignee(
                        token, GITCODE_OWNER, repo, number, it.assignee
                    )
                    assignee_applied = pcode == 200 and issue_has_assignee(presp, it.assignee)
                    if assignee_applied:
                        log(f"[OK] {repo}: issue #{number} 已补齐负责人 {it.assignee}")
                    else:
                        log(f"[WARN] {repo}: issue #{number} 补齐负责人失败（HTTP {pcode}）: "
                            f"{str(presp)[:300]}")
                if it.assignee and not assignee_applied:
                    log(f"[WARN] {repo}: issue #{number} 负责人未生效（PAT 无指派权限，"
                        f"或 {it.assignee} 非仓库成员）")
                log(f"[OK] {repo}: 已创建 issue #{number} -> {html}")
                results.append(
                    {
                        "key": it.key,
                        "repo": repo,
                        "status": "created",
                        "issue_number": number,
                        "html_url": html,
                        "assignee": it.assignee,
                        "assignee_applied": assignee_applied,
                        "title": it.title,
                    }
                )
            else:
                log(f"[ERROR] {repo}: 创建失败（HTTP {code}）: {it.title} -> {str(resp)[:300]}")
                results.append(
                    {
                        "key": it.key,
                        "repo": repo,
                        "status": "error",
                        "http": code,
                        "error": str(resp)[:500],
                        "title": it.title,
                    }
                )
            time.sleep(sleep_sec)  # 轻微限速

    return results
