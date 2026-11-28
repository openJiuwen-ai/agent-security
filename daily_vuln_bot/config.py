from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "reports" / "daily"
LOCAL_DAILY = ROOT / "local-repos" / "daily"
OSV_CACHE_PATH = ROOT / "results" / "daily_osv_cache.json"

GITHUB_ORG = "openJiuwen-ai"
GITCODE_OWNER = "openJiuwen"
GITCODE_API = "https://api.gitcode.com/api/v5"

# SIG 定义仓库：sigs/<sig>/sig-info.yaml 的 maintainers 第一个作为 issue 负责人
GITCODE_COMMUNITY_REPO = "openJiuwen/community"
COMMUNITY_REF = "main"

SKIP_REPOS = {".github"}

SCORECARD_IMAGE = "ghcr.io/ossf/scorecard:latest"
OSV_SCANNER_IMAGE = "ghcr.io/google/osv-scanner:latest"

REPORT_LEVELS = ("Critical", "High", "Medium")
LEVEL_RANK = {"Critical": 0, "High": 1, "Medium": 2}

DEFAULT_MAX_NEW_ISSUES = 50
# 写入 issue 正文的去重标记（HTML 注释，渲染不可见），后接 owner/repo@branch:OSV_ID
FP_MARK = "osv-fingerprint:"

DEFAULT_REPORT_CONTACT = "openJiuwen-security-bot"


def github_token() -> str:
    return (
        os.environ.get("GITHUB_AUTH_TOKEN")
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("GH_TOKEN")
        or ""
    ).strip()


def gitcode_token() -> str:
    """GitCode 个人访问令牌 PAT（环境变量 GITCODE_TOKEN，兼容 ATOMGIT_TOKEN）。"""
    return (
        os.environ.get("GITCODE_TOKEN")
        or os.environ.get("ATOMGIT_TOKEN")
        or ""
    ).strip()


def report_contact() -> str:
    return (
        os.environ.get("GITCODE_REPORT_CONTACT")
        or DEFAULT_REPORT_CONTACT
    ).strip()


def env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() in ("1", "true", "yes")
