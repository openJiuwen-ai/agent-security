"""每日 Scorecard 扫描 + GitCode 保密 issue 上报。

流程（对齐 gitleaks_report_issue.py 的 full 模式）：
  1. 列出 GitHub org 全部 public 仓 → 逐仓跑 Scorecard，生成
     reports/daily/<stamp>/scorecard/<repo>__default-<branch>.json；
     （可选）浅克隆 + osv-scanner 补全引入位置
  2. 汇总 Critical/High/Medium → vulns.json / vuln-detail.csv / issue_drafts/
  3. --report：按仓库拉取全部 issue 做指纹去重 → 负责人取 community SIG
     第一个 maintainer → 创建保密 issue（security_hole=true）

退出码：0 通过；1 有 issue 创建失败/去重拉取失败；2 配置/环境错误。
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from datetime import datetime
from pathlib import Path

from .config import (
    DEFAULT_MAX_NEW_ISSUES,
    GITHUB_ORG,
    GITCODE_COMMUNITY_REPO,
    REPORTS_DIR,
    REPORT_LEVELS,
    env_flag,
    github_token,
    gitcode_token,
)
from .enrich import VulnRow, build_rows, rows_to_dicts
from .gitcode import load_sig_index, resolve_assignee
from .report import (
    build_items,
    report_plan,
    write_drafts,
)
from .scan import (
    list_public_repos,
    run_scorecard,
    scorecard_vuln_ids,
    shallow_clone,
)


CSV_FIELDS = [
    "仓名",
    "分支",
    "责任人",
    "漏洞编号",
    "漏洞等级",
    "受影响包",
    "引入位置",
    "漏洞描述",
]


def log(msg):
    print(msg, flush=True)


def write_csv(rows: list[VulnRow], path: Path, assignees: dict[str, str | None] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_FIELDS, extrasaction="ignore")
        w.writeheader()
        for d in rows_to_dicts(rows):
            d = dict(d)
            d["责任人"] = (assignees or {}).get(d["仓名"]) or d.get("责任人") or ""
            w.writerow({k: d.get(k, "") for k in CSV_FIELDS})


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Daily Scorecard/OSV scan for openJiuwen-ai public repos; "
            "optionally create GitCode private security issues."
        )
    )
    p.add_argument(
        "--org",
        default=GITHUB_ORG,
        help=f"GitHub org (default: {GITHUB_ORG})",
    )
    p.add_argument(
        "--repos",
        nargs="*",
        default=None,
        help="Limit to these repo names (default: all public)",
    )
    p.add_argument(
        "--skip-clone",
        action="store_true",
        help="Skip git clone / osv-scanner (package path may be OSV-only)",
    )
    p.add_argument(
        "--max-new-issues",
        type=int,
        default=DEFAULT_MAX_NEW_ISSUES,
        help=f"Max new issues per run (default: {DEFAULT_MAX_NEW_ISSUES})",
    )
    p.add_argument(
        "--labels",
        default=os.environ.get("GITCODE_LABELS", "").strip() or None,
        help="Comma-separated GitCode labels (labels must exist; env GITCODE_LABELS)",
    )
    p.add_argument(
        "--report",
        action="store_true",
        help=(
            "Actually POST private security issues to GitCode (dedup by fingerprint, "
            "assignee = first SIG maintainer). Default is OFF: only write JSON/CSV/drafts."
        ),
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="With --report: check remote dedup & print what would be posted, no POST",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    dry_run = bool(args.dry_run) or env_flag("DRY_RUN")
    do_report = bool(args.report) and not dry_run

    if not github_token():
        log("[ERROR] 请设置 GITHUB_AUTH_TOKEN（或 GITHUB_TOKEN / GH_TOKEN）")
        return 2
    token = gitcode_token()
    if args.report and not token:
        log("[ERROR] --report 需要 GITCODE_TOKEN（GitCode 个人访问令牌 PAT）")
        return 2

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    out_dir = REPORTS_DIR / stamp
    sc_dir = out_dir / "scorecard"
    osv_dir = out_dir / "osvscanner"
    sc_dir.mkdir(parents=True, exist_ok=True)
    osv_dir.mkdir(exist_ok=True)

    mode = "上报" if do_report else ("DRY_RUN" if args.report else "仅扫描 + 草稿")
    log(f"[out] {out_dir}")
    log(f"[mode] {mode} | levels: {', '.join(REPORT_LEVELS)}")

    # ---------- 1. Scorecard 扫描 → 每仓 JSON ----------
    repos = list_public_repos(org=args.org, only=args.repos)
    log(f"[repos] {len(repos)}")

    all_rows: list[VulnRow] = []
    for ref in repos:
        sc_path = sc_dir / f"{ref.name}__default-{ref.default_branch}.json"
        result = run_scorecard(ref.full_name, sc_path)
        ids = scorecard_vuln_ids(result)
        log(f"  {ref.name}@{ref.default_branch}: {len(ids)} OSV ids")
        if not ids:
            continue

        clone_path = None
        if not args.skip_clone:
            try:
                clone_path = shallow_clone(ref.name, ref.default_branch, org=args.org)
            except Exception as e:
                log(f"  clone failed: {e}")

        rows = build_rows(
            repo=ref.name,
            branch=ref.default_branch,
            osv_ids=ids,
            clone_path=clone_path,
            scan_out_dir=osv_dir,
        )
        log(f"  kept {len(rows)} Critical/High/Medium")
        all_rows.extend(rows)

    # ---------- 2. 负责人（SIG 第一个 maintainer）→ 汇总产物 ----------
    sig_index = load_sig_index(token) if token else {}
    if not token:
        log("[WARN] 无 GITCODE_TOKEN：跳过 SIG 负责人解析，责任人列留空")

    items = build_items(all_rows, sig_index, max_new=args.max_new_issues)
    # 责任人按全部命中仓库解析（含被 max_new 截断的行），供 CSV 使用
    assignees = {
        repo: resolve_assignee(repo, sig_index)[0] for repo in sorted({r.仓名 for r in all_rows})
    }
    missing = sorted(r for r, a in assignees.items() if not a)
    if missing:
        log(f"[WARN] 以下仓库在 {GITCODE_COMMUNITY_REPO} 未找到 SIG 维护者，issue 不指定负责人: {', '.join(missing)}")

    csv_path = out_dir / "vuln-detail.csv"
    write_csv(all_rows, csv_path, assignees)
    log(f"[csv] {csv_path} rows={len(all_rows)}")

    vulns_path = out_dir / "vulns.json"
    vulns_path.write_text(
        json.dumps(
            {
                "stamp": stamp,
                "org": args.org,
                "rows_total": len(all_rows),
                "planned_issues": len(items),
                "vulns": [it.to_dict() for it in items],
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    log(f"[json] {vulns_path} planned={len(items)}")

    drafts_dir = write_drafts(items, out_dir)
    log(f"[drafts] {len(items)} planned issues under {drafts_dir}")

    summary = {
        "stamp": stamp,
        "org": args.org,
        "repos_scanned": [r.name for r in repos],
        "rows_total": len(all_rows),
        "levels": list(REPORT_LEVELS),
        "planned_issues": len(items),
        "assignees": assignees,
        "report_upload": do_report,
        "dry_run": args.report and not do_report,
        "csv": str(csv_path),
        "vulns_json": str(vulns_path),
        "drafts": str(drafts_dir),
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    # ---------- 3. 上报（去重 + 负责人）----------
    if not args.report:
        log(
            "[report] skipped upload (default). "
            "Review vulns.json / issue_drafts/, then re-run with --report to POST."
        )
        return 0

    log(f"[report] {'DRY_RUN: ' if dry_run else ''}uploading private security issues...")
    results = report_plan(items, token=token, dry_run=dry_run, labels=args.labels)
    (out_dir / "report-results.json").write_text(
        json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    created = sum(1 for r in results if r.get("status") == "created")
    skipped = sum(1 for r in results if r.get("status") == "skipped_existing")
    failed = sum(1 for r in results if r.get("status") in ("error", "skipped_fetch_failed"))
    log(
        f"[report] created={created} skipped_existing={skipped} "
        f"failed={failed} / planned={len(items)}"
    )
    return 1 if (do_report and failed) else 0


if __name__ == "__main__":
    raise SystemExit(main())
