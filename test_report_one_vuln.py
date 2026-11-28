#!/usr/bin/env python3
"""
单条漏洞上报测试脚本（默认只打印草稿，不上传；--submit 走与主流程相同的去重链路）。

示例数据：
  agent-security | develop | PYSEC-2026-4320 | Critical
  | certifi@2026.7.22 / 2026.2.25 (PyPI) | agent_ssas/uv.lock; jiuwenbox/uv.lock
用法：
  python test_report_one_vuln.py                      # 打印草稿
  $env:GITCODE_TOKEN = "<个人访问令牌 PAT>"
  python test_report_one_vuln.py --check              # 查远程是否已上报（不创建）
  python test_report_one_vuln.py --submit             # 已上报则跳过，否则创建
  python test_report_one_vuln.py --submit --assignee fujilie   # 指定负责人（覆盖 SIG 解析）

去重：issue 正文首行 HTML 注释 `<!-- osv-fingerprint: owner/repo@branch:OSV_ID -->` 精确命中，
      或标题含 `OSV:<id>`（兼容旧版 issue）。--check/--submit 会翻页拉取该仓 open issue
      比对，命中则不重复创建；已关闭的不参与去重；拉取失败则不做任何操作。
"""

from __future__ import annotations

import argparse
import json
import sys

from daily_vuln_bot.config import GITCODE_OWNER, gitcode_token
from daily_vuln_bot.enrich import VulnRow
from daily_vuln_bot.gitcode import collect_existing_fingerprints, load_sig_index, resolve_assignee
from daily_vuln_bot.report import build_items, fingerprint, report_plan


# 固定测试样本
SAMPLE = VulnRow(
    仓名="agent-security",
    分支="develop",
    责任人="",
    漏洞编号="PYSEC-2026-4320",
    漏洞等级="Critical",
    受影响包="certifi@2026.7.22 (PyPI); certifi@2026.2.25 (PyPI)",
    引入位置="agent_ssas/uv.lock; jiuwenbox/uv.lock",
    漏洞描述="certifi bundles emSign root CAs with compromised intermediate CA keys",
)


def main() -> int:
    p = argparse.ArgumentParser(description="Test one private security issue on GitCode")
    p.add_argument("--submit", action="store_true", help="POST to GitCode (skips if fingerprint exists)")
    p.add_argument("--check", action="store_true", help="Only check remote dedup, never POST")
    p.add_argument(
        "--assignee",
        default="",
        help="GitCode username for 负责人（可选；缺省取 community SIG 第一个 maintainer）。无指派权限时可留空",
    )
    args = p.parse_args()

    token = gitcode_token()
    if (args.submit or args.check) and not token:
        print("ERROR: set GITCODE_TOKEN (personal access token) first", file=sys.stderr)
        return 2

    sig_index = load_sig_index(token) if token else {}
    assignee, sig = resolve_assignee(SAMPLE.仓名, sig_index)
    if args.assignee.strip():
        assignee, sig = args.assignee.strip(), "(手动指定)"
        sig_index = {
            f"{GITCODE_OWNER}/{SAMPLE.仓名}".lower(): {"sig": sig, "maintainers": [assignee]}
        }
    item = build_items([SAMPLE], sig_index, max_new=1)[0]

    print("=== draft ===")
    print(f"repo:      {GITCODE_OWNER}/{SAMPLE.仓名}")
    print(f"key:       {item.key}")
    print(f"assignee:  {item.assignee or '(none)'}" + (f"  [{item.sig}]" if item.sig else ""))
    print(f"title:     {item.title}")
    print("--- body ---")
    print(item.body)
    print("--- end ---")

    if not args.submit and not args.check:
        print("\n[ok] dry-run only. Use --check to verify remote dedup, --submit to POST.")
        return 0

    existing = collect_existing_fingerprints(token, GITCODE_OWNER, SAMPLE.仓名)
    if existing is None:
        print("[skip] 无法获取该仓已有 issue，为避免重复不做任何操作", file=sys.stderr)
        return 1
    fingerprints, osv_ids = existing
    key = fingerprint(SAMPLE.仓名, SAMPLE.分支, SAMPLE.漏洞编号)
    if key in fingerprints:
        print(f"[skip] 已上报过（正文指纹命中）: {key}")
        return 0
    if SAMPLE.漏洞编号 in osv_ids:
        print(f"[skip] 已上报过（标题 OSV 编号命中，兼容旧版 issue）: OSV:{SAMPLE.漏洞编号}")
        return 0
    print(f"[dedup] 远程未命中（该仓已有指纹 {len(fingerprints)} 个 / 标题 OSV {len(osv_ids)} 个）")

    if not args.submit:
        print("[ok] --check only: 可以创建（未 POST）")
        return 0

    print("\n[submit] POSTing via OpenAPI /api/v5/.../issues (security_hole=true)...")
    results = report_plan([item], token=token, dry_run=False)
    print(json.dumps(results, ensure_ascii=False, indent=2))
    r = results[0] if results else {}
    if r.get("status") == "created":
        print(f"\n[ok] created: {r.get('html_url')}")
        return 0
    if r.get("status") == "skipped_existing":
        print("\n[skip] 已上报过")
        return 0
    print(f"\n[fail] {r.get('status')}: {r.get('error', '')}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
