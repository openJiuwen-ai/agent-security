"""GitCode OpenAPI 封装（对齐 gitleaks_report_issue.py 的调用方式）。

- api(): 统一请求，返回 (http_status, 数据或错误串)
- SIG 索引：解析 community 仓库 sigs/<sig>/sig-info.yaml，取 repositories 对应的
  maintainers（保持 yaml 顺序），第一个即 issue 负责人
- 远程去重：翻页拉取仓库 open issue，从正文/标题提取已上报标记
- create_security_issue(): 创建保密 issue（security_hole=true）
"""

from __future__ import annotations

import base64
import json
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .config import (
    COMMUNITY_REF,
    FP_MARK,
    GITCODE_API,
    GITCODE_COMMUNITY_REPO,
    GITCODE_OWNER,
    gitcode_token,
)

ISSUE_LIST_MAX_PAGES = 100


def log(msg):
    print(msg, flush=True)


def api(method, path, token, params=None, payload=None):
    """调用 GitCode OpenAPI，返回 (http_status, 解析后的数据或原始错误串)。"""
    url = f"{GITCODE_API}{path}"
    if params:
        url += "?" + urlencode(params)
    data = (
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if payload is not None
        else None
    )
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


# ---------------------------------------------------------------------------
# SIG 负责人解析
# ---------------------------------------------------------------------------

def fetch_file(token, owner, repo, path, ref=COMMUNITY_REF):
    """通过 contents 接口拉取仓库文件文本；失败返回 None。"""
    code, data = api(
        "GET", f"/repos/{owner}/{repo}/contents/{path}", token, params={"ref": ref}
    )
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
    """极简 YAML 解析：提取 repositories 块中的 owner/repo 条目。"""
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


def list_sig_dirs(token):
    """列出 community 仓库 sigs/ 下的 SIG 目录名；失败返回空列表。"""
    owner, repo = GITCODE_COMMUNITY_REPO.split("/")
    code, data = api(
        "GET", f"/repos/{owner}/{repo}/contents/sigs", token,
        params={"ref": COMMUNITY_REF},
    )
    if code != 200 or not isinstance(data, list):
        log(f"[WARN] 获取 SIG 目录失败（HTTP {code}）: {str(data)[:200]}")
        return []
    return [d["name"] for d in data if d.get("type") == "dir" and d.get("name")]


def load_sig_index(token=None):
    """
    一次性拉取全部 SIG 定义，返回 {"owner/repo"(小写): {"sig": 名, "maintainers": [...]}}。
    同一仓库被多个 SIG 声明时取先出现的那个。
    """
    token = token or gitcode_token()
    if not token:
        return {}
    owner, repo = GITCODE_COMMUNITY_REPO.split("/")
    index: dict[str, dict] = {}
    for sig in list_sig_dirs(token):
        text = fetch_file(token, owner, repo, f"sigs/{sig}/sig-info.yaml")
        if not text:
            continue
        ids = parse_maintainers(text)
        if not ids:
            continue
        for full in parse_repositories(text):
            index.setdefault(full.lower(), {"sig": sig, "maintainers": ids})
    log(f"[*] SIG 索引: {len(index)} 个仓库 / {len(set(v['sig'] for v in index.values()))} 个 SIG")
    return index


def resolve_assignee(repo, sig_index, owner=GITCODE_OWNER):
    """返回 (第一个 maintainer 的 atomgit_id 或 None, sig 名或 None)。"""
    ent = (sig_index or {}).get(f"{owner}/{repo}".lower())
    if not ent:
        return None, None
    return ent["maintainers"][0], ent["sig"]


# ---------------------------------------------------------------------------
# Issue 去重 / 创建
# ---------------------------------------------------------------------------

def collect_existing_fingerprints(token, owner, repo):
    """
    翻页拉取仓库 **open** 状态 issue（已关闭的不参与去重：关闭即视为不再跟踪，
    下次扫描若仍命中会重新建单），收集已上报标记：
      - 正文 HTML 注释指纹 owner/repo@branch:OSV_ID（新版，精确到分支）
      - 标题中的 OSV:ID（兼容旧版 issue，不含分支信息，同仓同 OSV 即视为已上报）
    返回 (fingerprints, osv_ids)；任一页失败返回 None：调用方应跳过该仓，
    避免因去重失效而重复建单。
    """
    fps: set[str] = set()
    osv_ids: set[str] = set()
    page = 1
    while page <= ISSUE_LIST_MAX_PAGES:
        code, data = api(
            "GET", f"/repos/{owner}/{repo}/issues", token,
            params={"state": "open", "per_page": "100", "page": str(page)},
        )
        if code != 200 or not isinstance(data, list):
            log(f"[WARN] {owner}/{repo}: 拉取 issue 第 {page} 页失败（HTTP {code}）: {str(data)[:200]}")
            return None
        if not data:
            break
        for it in data:
            body = it.get("body") or it.get("description") or ""
            fps.update(re.findall(re.escape(FP_MARK) + r"\s*(\S+)", body))
            osv_ids.update(re.findall(r"OSV:([A-Za-z0-9_.:-]+)", it.get("title") or ""))
        if len(data) < 100:
            break
        page += 1
    return fps, osv_ids


def create_security_issue(token, owner, repo, title, body, assignee=None, labels=None):
    """创建保密 issue；返回 (http_status, 响应 dict 或错误串)。"""
    payload = {
        "repo": repo,
        "title": title,
        "body": body,
        "security_hole": "true",  # 保密 issue：修复前社区用户不可见
    }
    if assignee:
        payload["assignee"] = assignee
    if labels:
        payload["labels"] = labels
    return api("POST", f"/repos/{owner}/issues", token, payload=payload)


def patch_issue_assignee(token, owner, repo, number, assignee):
    """创建后补齐负责人（对齐 gitleaks：PATCH /repos/{owner}/{repo}/issues/{number}）。"""
    return api(
        "PATCH", f"/repos/{owner}/{repo}/issues/{number}", token,
        payload={"assignee": assignee},
    )


def issue_has_assignee(resp, assignee):
    """判断创建/更新响应里负责人是否已生效（兼容 assignee 对象 / assignees 列表两种返回）。"""
    if not isinstance(resp, dict) or not assignee:
        return False
    want = assignee.lower()
    names = set()
    for x in resp.get("assignees") or []:
        names.add((x.get("username") or x.get("name") or x.get("login") or "") if isinstance(x, dict) else str(x))
    a = resp.get("assignee")
    if isinstance(a, dict):
        names.add(a.get("username") or a.get("name") or a.get("login") or "")
    elif a:
        names.add(str(a))
    return want in {n.lower() for n in names if n}


def issue_html_url(repo, number, owner=GITCODE_OWNER):
    return f"https://gitcode.com/{owner}/{repo}/issues/{number}"
