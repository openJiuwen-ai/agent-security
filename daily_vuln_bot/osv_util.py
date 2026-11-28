from __future__ import annotations

import json
import math
import re
import ssl
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from .config import OSV_CACHE_PATH

CTX = ssl.create_default_context()
SEVERITY_WORDS = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "MODERATE": "Medium",
    "LOW": "Low",
}


def cvss3_base(vector: str) -> float | None:
    m = re.match(r"CVSS:3\.[01]/(.+)", vector.strip())
    if not m:
        return None
    parts = dict(p.split(":") for p in m.group(1).split("/") if ":" in p)
    av = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac = {"L": 0.77, "H": 0.44}
    pr_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_c = {"N": 0.85, "L": 0.68, "H": 0.5}
    ui = {"N": 0.85, "R": 0.62}
    cia = {"N": 0.0, "L": 0.22, "H": 0.56}
    try:
        scope = parts["S"]
        pr = pr_c[parts["PR"]] if scope == "C" else pr_u[parts["PR"]]
        exploitability = 8.22 * av[parts["AV"]] * ac[parts["AC"]] * pr * ui[parts["UI"]]
        isc_base = 1 - (
            (1 - cia[parts["C"]]) * (1 - cia[parts["I"]]) * (1 - cia[parts["A"]])
        )
        if scope == "U":
            impact = 6.42 * isc_base
        else:
            impact = 7.52 * (isc_base - 0.029) - 3.25 * (isc_base - 0.02) ** 15
        if impact <= 0:
            return 0.0
        score = (
            min(impact + exploitability, 10.0)
            if scope == "U"
            else min(1.08 * (impact + exploitability), 10.0)
        )
        return math.ceil(score * 10) / 10
    except Exception:
        return None


def level_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def fetch_osv(vid: str) -> dict:
    url = f"https://api.osv.dev/v1/vulns/{vid}"
    req = urllib.request.Request(url, headers={"User-Agent": "OpenJiuwen-DailyVulnBot"})
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=40) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return {"_error": f"http:{e.code}"}
    except Exception as e:
        return {"_error": str(e)}


def parse_level(doc: dict) -> tuple[str | None, list[str]]:
    ds = doc.get("database_specific") or {}
    sev = ds.get("severity")
    if isinstance(sev, str) and sev.upper() in SEVERITY_WORDS:
        return SEVERITY_WORDS[sev.upper()], []
    for s in doc.get("severity") or []:
        score_str = str(s.get("score") or "")
        if score_str.upper().startswith("CVSS:"):
            sc = cvss3_base(score_str)
            if sc is not None:
                return level_from_score(sc), []
        try:
            return level_from_score(float(score_str)), []
        except ValueError:
            pass
        for k, v in SEVERITY_WORDS.items():
            if k in score_str.upper():
                return v, []
    for aff in doc.get("affected") or []:
        for blob in (
            aff.get("database_specific") or {},
            aff.get("ecosystem_specific") or {},
        ):
            sev = blob.get("severity")
            if isinstance(sev, str) and sev.upper() in SEVERITY_WORDS:
                return SEVERITY_WORDS[sev.upper()], []
    aliases = list(doc.get("aliases") or []) + list(doc.get("related") or [])
    return None, [str(a) for a in aliases]


def summary_of(doc: dict) -> str:
    s = (doc.get("summary") or "").strip()
    if s:
        return re.sub(r"\s+", " ", s)
    details = (doc.get("details") or "").strip()
    if details:
        return re.sub(r"\s+", " ", details.split("\n", 1)[0]).strip()[:300]
    return ""


def osv_package_fallback(doc: dict) -> str:
    parts: list[str] = []
    for a in doc.get("affected") or []:
        pkg = a.get("package") or {}
        name = pkg.get("name") or ""
        eco = pkg.get("ecosystem") or ""
        if not name:
            continue
        fixed = []
        for rg in a.get("ranges") or []:
            for ev in rg.get("events") or []:
                if "fixed" in ev:
                    fixed.append(str(ev["fixed"]))
        s = name
        if eco:
            s += f" ({eco})"
        if fixed:
            s += " fixed:" + ",".join(fixed[:2])
        parts.append(s)
    return "; ".join(list(dict.fromkeys(parts))[:5])


def load_cache(path: Path | None = None) -> dict:
    p = path or OSV_CACHE_PATH
    if p.is_file():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}


def save_cache(cache: dict, path: Path | None = None) -> None:
    p = path or OSV_CACHE_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")


def resolve_meta(vid: str, cache: dict, depth: int = 0) -> tuple[str, str, str]:
    """Return (level, description, package_fallback)."""
    doc = cache.get(vid)
    if doc is None or (isinstance(doc, dict) and doc.get("_error")):
        doc = fetch_osv(vid)
        cache[vid] = doc
    if not doc or doc.get("_error"):
        return "Unknown", "", ""
    desc = summary_of(doc)
    pkg = osv_package_fallback(doc)
    level, aliases = parse_level(doc)
    if level:
        return level, desc, pkg
    if depth >= 2:
        return "Unknown", desc, pkg
    ordered = sorted(
        aliases,
        key=lambda x: (
            0 if x.startswith("GHSA-") else 1 if x.startswith("CVE-") else 2,
            x,
        ),
    )
    for a in ordered:
        if a not in cache or (cache[a] or {}).get("_error"):
            cache[a] = fetch_osv(a)
        lvl, d2, p2 = resolve_meta(a, cache, depth + 1)
        if lvl != "Unknown":
            return lvl, desc or d2, pkg or p2
        if not desc and d2:
            desc = d2
        if not pkg and p2:
            pkg = p2
    return "Unknown", desc, pkg


def enrich_ids(ids: list[str], cache: dict | None = None, workers: int = 12) -> dict[str, dict]:
    cache = cache if cache is not None else load_cache()
    need = [i for i in ids if i not in cache or (cache[i] or {}).get("_error")]
    if need:
        print(f"[OSV] fetch {len(need)}/{len(ids)}", flush=True)

        def one(vid: str):
            return vid, fetch_osv(vid)

        done = 0
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(one, v): v for v in need}
            for fut in as_completed(futs):
                vid, doc = fut.result()
                cache[vid] = doc
                done += 1
                if done % 50 == 0 or done == len(need):
                    print(f"  osv {done}/{len(need)}", flush=True)
                    save_cache(cache)

    # prefetch aliases (one wave)
    alias_need: set[str] = set()
    for vid in ids:
        doc = cache.get(vid) or {}
        if not doc or doc.get("_error"):
            continue
        level, aliases = parse_level(doc)
        if level:
            continue
        for a in aliases:
            if a not in cache or (cache[a] or {}).get("_error"):
                alias_need.add(a)
    if alias_need:
        print(f"[OSV] alias fetch {len(alias_need)}", flush=True)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {ex.submit(fetch_osv, a): a for a in alias_need}
            for fut in as_completed(futs):
                a = futs[fut]
                cache[a] = fut.result()
        save_cache(cache)

    meta: dict[str, dict] = {}
    for vid in ids:
        level, desc, pkg = resolve_meta(vid, cache)
        meta[vid] = {"level": level, "description": desc, "package_fallback": pkg}
    save_cache(cache)
    return meta
