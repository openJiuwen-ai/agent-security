from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .config import (
    GITHUB_ORG,
    LOCAL_DAILY,
    SCORECARD_IMAGE,
    SKIP_REPOS,
    github_token,
)


@dataclass
class RepoRef:
    name: str
    full_name: str
    default_branch: str
    html_url: str


@dataclass
class ScorecardVulnHit:
    repo: str
    branch: str
    osv_ids: list[str] = field(default_factory=list)
    raw_path: str = ""


def _gh_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "OpenJiuwen-DailyVulnBot",
    }


def list_public_repos(
    org: str = GITHUB_ORG,
    token: str | None = None,
    only: list[str] | None = None,
) -> list[RepoRef]:
    token = token or github_token()
    if not token:
        raise RuntimeError("GITHUB_AUTH_TOKEN / GITHUB_TOKEN / GH_TOKEN is required")
    headers = _gh_headers(token)
    only_set = {x.lower() for x in (only or [])}
    repos: list[RepoRef] = []
    page = 1
    while True:
        url = (
            f"https://api.github.com/orgs/{org}/repos"
            f"?per_page=100&type=public&page={page}"
        )
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=60) as resp:
            batch = json.loads(resp.read().decode("utf-8"))
        if not batch:
            break
        for r in batch:
            name = r.get("name") or ""
            if name in SKIP_REPOS or r.get("archived"):
                continue
            if only_set and name.lower() not in only_set:
                continue
            repos.append(
                RepoRef(
                    name=name,
                    full_name=r.get("full_name") or f"{org}/{name}",
                    default_branch=r.get("default_branch") or "main",
                    html_url=r.get("html_url") or f"https://github.com/{org}/{name}",
                )
            )
        if len(batch) < 100:
            break
        page += 1
    repos.sort(key=lambda x: x.name.lower())
    return repos


def extract_osv_ids(details) -> list[str]:
    ids: list[str] = []
    seen = set()
    for d in details or []:
        s = str(d)
        found = None
        m = re.search(r"osv\.dev/(\S+)", s)
        if m:
            found = m.group(1).rstrip(".,)")
        else:
            for pat in (
                r"(GHSA-[0-9A-Za-z-]+)",
                r"(CVE-\d{4}-\d+)",
                r"(CGA-[0-9A-Za-z-]+)",
                r"(PYSEC-\d{4}-\d+)",
                r"(GO-\d{4}-\d+)",
            ):
                m = re.search(pat, s)
                if m:
                    found = m.group(1)
                    break
        if found and found not in seen:
            seen.add(found)
            ids.append(found)
    return ids


def run_scorecard(
    full_name: str,
    out_file: Path,
    token: str | None = None,
) -> dict | None:
    token = token or github_token()
    out_file.parent.mkdir(parents=True, exist_ok=True)
    mount = str(out_file.parent.resolve())
    file_name = out_file.name
    cmd = [
        "docker",
        "run",
        "--rm",
        "--user",
        "0:0",
        "-e",
        f"GITHUB_AUTH_TOKEN={token}",
        "-v",
        f"{mount}:/out",
        SCORECARD_IMAGE,
        f"--repo=github.com/{full_name}",
        "--format=json",
        f"--output=/out/{file_name}",
        "--show-details",
        "--file-mode=archive",
    ]
    print(f"[Scorecard] {full_name}", flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if not out_file.is_file() or out_file.stat().st_size == 0:
        print(f"  scorecard failed exit={proc.returncode}", flush=True)
        if proc.stderr:
            print("  stderr:", proc.stderr[:300], flush=True)
        return None
    try:
        return json.loads(out_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("  invalid scorecard JSON", flush=True)
        return None


def scorecard_vuln_ids(result: dict | None) -> list[str]:
    if not result:
        return []
    for c in result.get("checks") or []:
        if c.get("name") == "Vulnerabilities":
            return extract_osv_ids(c.get("details"))
    return []


def shallow_clone(
    repo: str,
    branch: str,
    org: str = GITHUB_ORG,
    dest_root: Path | None = None,
    token: str | None = None,
) -> Path:
    dest_root = dest_root or LOCAL_DAILY
    dest_root.mkdir(parents=True, exist_ok=True)
    safe = branch.replace("/", "_").replace("\\", "_").replace(":", "_")
    dest = dest_root / f"{repo}__{safe}"
    token = token or github_token()
    url = f"https://x-access-token:{token}@github.com/{org}/{repo}.git"
    if (dest / ".git").is_dir():
        print(f"[git] update {repo}@{branch}", flush=True)
        subprocess.run(
            ["git", "-C", str(dest), "config", "core.longpaths", "true"],
            check=False,
        )
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", "1", "origin", branch],
            check=False,
            capture_output=True,
            text=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "-B", branch, "FETCH_HEAD"],
            check=False,
            capture_output=True,
            text=True,
        )
        return dest

    if dest.exists():
        # leftover incomplete dir
        import shutil

        shutil.rmtree(dest, ignore_errors=True)

    print(f"[git] clone {repo}@{branch}", flush=True)
    code = subprocess.run(
        [
            "git",
            "-c",
            "core.longpaths=true",
            "clone",
            "--depth",
            "1",
            "--branch",
            branch,
            url,
            str(dest),
        ],
        capture_output=True,
        text=True,
    )
    if code.returncode != 0:
        raise RuntimeError(
            f"git clone failed {repo}@{branch}: {code.stderr[-400:]}"
        )
    return dest
