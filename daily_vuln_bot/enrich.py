from __future__ import annotations

import json
import subprocess
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from .config import OSV_SCANNER_IMAGE, REPORT_LEVELS
from .osv_util import enrich_ids


@dataclass
class VulnRow:
    仓名: str
    分支: str
    责任人: str  # 上报阶段由 SIG 第一个 maintainer 填充（report.build_items）
    漏洞编号: str
    漏洞等级: str
    受影响包: str
    引入位置: str
    漏洞描述: str = ""


def run_osv_scanner(
    repo_path: Path, out_json: Path, timeout_sec: int = 600
) -> dict:
    mount = str(repo_path.resolve())
    err_path = out_json.with_suffix(".err.txt")
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{mount}:/src",
        OSV_SCANNER_IMAGE,
        "scan",
        "source",
        "-r",
        "/src",
        "--no-resolve",
        "--format",
        "json",
    ]
    out_json.parent.mkdir(parents=True, exist_ok=True)
    with out_json.open("w", encoding="utf-8") as out_f, err_path.open(
        "w", encoding="utf-8"
    ) as err_f:
        try:
            proc = subprocess.run(
                cmd, stdout=out_f, stderr=err_f, text=True, timeout=timeout_sec
            )
            code = proc.returncode
        except subprocess.TimeoutExpired:
            err_f.write(f"\nTIMEOUT after {timeout_sec}s\n")
            return {"_timeout": True, "_exit": -1}
    text = out_json.read_text(encoding="utf-8-sig").strip()
    if not text:
        return {"_empty": True, "_exit": code}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"_invalid": True, "_exit": code}
    data["_exit"] = code
    return data


def _normalize_path(p: str) -> str:
    p = p.replace("\\", "/")
    if p.startswith("/src/"):
        return p[len("/src/") :]
    if p == "/src":
        return "."
    return p


def index_scanner_results(data: dict) -> dict[str, list[dict]]:
    idx: dict[str, list[dict]] = defaultdict(list)
    for result in data.get("results") or []:
        source = (result.get("source") or {}).get("path") or ""
        src = _normalize_path(str(source))
        for pkg in result.get("packages") or []:
            meta = pkg.get("package") or {}
            name = meta.get("name") or ""
            version = meta.get("version") or ""
            ecosystem = meta.get("ecosystem") or ""
            id_sets: list[set[str]] = []
            for v in pkg.get("vulnerabilities") or []:
                ids = {str(v.get("id") or "")}
                ids.update(str(a) for a in (v.get("aliases") or []))
                ids.discard("")
                if ids:
                    id_sets.append(ids)
            for g in pkg.get("groups") or []:
                ids = {str(x) for x in (g.get("ids") or [])}
                ids.update(str(a) for a in (g.get("aliases") or []))
                ids.discard("")
                if ids:
                    id_sets.append(ids)
            seen_fs: set[frozenset[str]] = set()
            for ids in id_sets:
                fs = frozenset(ids)
                if fs in seen_fs:
                    continue
                seen_fs.add(fs)
                loc = {
                    "package": name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "path": src,
                }
                for i in ids:
                    if loc not in idx[i]:
                        idx[i].append(loc)
    return idx


def format_locs(locs: list[dict], limit: int = 5) -> tuple[str, str]:
    if not locs:
        return "", ""
    pkgs: list[str] = []
    paths: list[str] = []
    for loc in locs[:limit]:
        pkg = loc.get("package") or ""
        ver = loc.get("version") or ""
        eco = loc.get("ecosystem") or ""
        path = loc.get("path") or ""
        if pkg:
            item = f"{pkg}@{ver}" if ver else pkg
            if eco:
                item = f"{item} ({eco})"
            pkgs.append(item)
        if path:
            paths.append(path)
    extra = f" …(+{len(locs) - limit})" if len(locs) > limit else ""
    return "; ".join(dict.fromkeys(pkgs)), "; ".join(dict.fromkeys(paths)) + extra


def build_rows(
    repo: str,
    branch: str,
    osv_ids: list[str],
    clone_path: Path | None,
    scan_out_dir: Path,
) -> list[VulnRow]:
    meta = enrich_ids(osv_ids)

    loc_idx: dict[str, list[dict]] = {}
    if clone_path and clone_path.is_dir():
        out_json = scan_out_dir / f"{repo}__{branch.replace('/', '_')}_osvscanner.json"
        print(f"[osv-scanner] {repo}@{branch}", flush=True)
        data = run_osv_scanner(clone_path, out_json)
        if not data.get("_empty") and not data.get("_invalid") and not data.get("_timeout"):
            loc_idx = index_scanner_results(data)
        else:
            print(f"  osv-scanner skip flags={ {k: data.get(k) for k in ('_empty','_invalid','_timeout') if data.get(k)} }", flush=True)

    rows: list[VulnRow] = []
    for vid in osv_ids:
        m = meta.get(vid) or {}
        level = m.get("level") or "Unknown"
        if level not in REPORT_LEVELS:
            continue
        locs = list(loc_idx.get(vid) or [])
        pkgs, paths = format_locs(locs)
        if not pkgs:
            fb = m.get("package_fallback") or ""
            if fb:
                pkgs = fb + " [OSV声明]"
        rows.append(
            VulnRow(
                仓名=repo,
                分支=branch,
                责任人="",
                漏洞编号=vid,
                漏洞等级=level,
                受影响包=pkgs,
                引入位置=paths,
                漏洞描述=m.get("description") or "",
            )
        )
    return rows


def rows_to_dicts(rows: list[VulnRow]) -> list[dict]:
    return [asdict(r) for r in rows]
