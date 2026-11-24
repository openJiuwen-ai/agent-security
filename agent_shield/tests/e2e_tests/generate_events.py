"""Write 100 agent-event/v1 bodies for the loopback evaluate endpoint."""

from __future__ import annotations

import json
from pathlib import Path

from agent_shield.tests.net_addrs import METADATA
from agent_shield.tests.stdio import log_line

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "evaluate_events.json"
WORKSPACE = "C:/Users/me/proj"


def event(effects: list[dict] | None = None, **overrides) -> dict:
    body = {
        "spec": "agent-event/v1",
        "id": "evt_pending",
        "time": "2026-10-20T00:00:00Z",
        "source": {"framework": "jiuwenswarm", "session_id": "e2e", "agent_id": "leader"},
        "workspace": {"root": WORKSPACE, "trusted_dirs": ["D:/shared"], "os": "windows"},
        "user_intent": None,
        "action": {
            "category": "tool_call",
            "raw": {"name": "bash", "args": {}},
            "effects": effects or [],
            "normalization": {"status": "ok", "warnings": []},
        },
        "host_capabilities": {"hitl": True, "auto_intent": True},
        "execution": {
            "plane": "host",
            "provider": "host",
            "intercept": False,
            "escaped": False,
            "escape_reason": "",
        },
    }
    if "normalization" in overrides:
        body["action"]["normalization"]["status"] = overrides.pop("normalization")
    if "execution" in overrides:
        body["execution"].update(overrides.pop("execution"))
    if "raw_name" in overrides:
        body["action"]["raw"]["name"] = overrides.pop("raw_name")
    if "category" in overrides:
        body["action"]["category"] = overrides.pop("category")
    body.update(overrides)
    return body


def fs(kind: str, path: str, **extra) -> dict:
    effect = {
        "type": kind,
        "path": path,
        "path_kind": extra.pop("path_kind", "file"),
        "device_class": extra.pop("device_class", None),
    }
    if kind == "fs.delete":
        effect["force"] = extra.pop("force", False)
        effect["bulk"] = extra.pop("bulk", False)
    if "exists" in extra:
        effect["exists"] = extra.pop("exists")
    effect.update(extra)
    return effect


def exec_effect(argv: list[str], **meta) -> dict:
    return {
        "type": "process.exec",
        "argv": argv,
        "cwd": WORKSPACE,
        "shell_meta": {
            "obfuscated": meta.pop("obfuscated", False),
            "unknown_structure": meta.pop("unknown_structure", False),
            "interpreter_sink": meta.pop("interpreter_sink", False),
            "privilege": meta.pop("privilege", False),
        },
        **meta,
    }


def add(cases: list[dict], label: str, body: dict) -> None:
    cases.append({"id": f"{len(cases) + 1:03d}", "label": label, "body": body})


def build() -> list[dict]:
    cases: list[dict] = []
    reads = [
        "README.md",
        "src/app.py",
        "docs/guide.md",
        "tests/test_app.py",
        "package.json",
        "Makefile",
        "LICENSE",
        "src/util.py",
    ]
    for name in reads:
        add(cases, "workspace read", event([fs("fs.read", f"{WORKSPACE}/{name}")]))
    sensitive = [
        f"{WORKSPACE}/.env",
        f"{WORKSPACE}/.env.local",
        f"{WORKSPACE}/.ssh/id_rsa",
        f"{WORKSPACE}/.ssh/id_ed25519",
        f"{WORKSPACE}/secrets/api.pem",
        f"{WORKSPACE}/certs/server.pfx",
        f"{WORKSPACE}/.aws/credentials",
        f"{WORKSPACE}/.kube/config",
        f"{WORKSPACE}/.npmrc",
        f"{WORKSPACE}/.ssh/authorized_keys",
    ]
    for path in sensitive:
        add(cases, "sensitive read", event([fs("fs.read", path)]))
    writes = ["notes.txt", "src/new.py", "out/report.md", "data/table.csv", "src/b.py", "tmp/log.txt"]
    for name in writes:
        add(cases, "workspace write", event([fs("fs.write", f"{WORKSPACE}/{name}", exists=False)]))
    outside = [
        "D:/tmp/a.txt",
        "D:/drop/b.txt",
        "C:/Users/other/c.txt",
        "E:/share/d.txt",
        "C:/temp/e.txt",
        "D:/work/f.txt",
    ]
    for path in outside:
        add(cases, "outside write", event([fs("fs.write", path, exists=False)]))
    for index in range(4):
        add(cases, "system new file", event([fs("fs.write", f"C:/Windows/Temp/new-{index}.txt", exists=False)]))
    for name in ["old.log", "build/out.o", "tmp/cache.db", "dist/app.js"]:
        add(cases, "workspace delete", event([fs("fs.delete", f"{WORKSPACE}/{name}")]))
    for path in ["D:/tmp/old.txt", "C:/Users/other/old.txt", "E:/share/old.txt", "C:/temp/old.txt"]:
        add(cases, "outside delete", event([fs("fs.delete", path, force=False)]))
    for path in ["D:/tmp/locked.txt", "C:/Users/other/locked.txt", "E:/share/locked.txt"]:
        add(cases, "outside force delete", event([fs("fs.delete", path, force=True)]))
    for path in [
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/System32/kernel32.dll",
        "C:/Windows/SysWOW64/ntdll.dll",
    ]:
        add(cases, "system critical delete", event([fs("fs.delete", path)]))
    for name in ["a.tmp", "b.tmp", "c.tmp"]:
        add(cases, "bulk delete", event([fs("fs.delete", f"{WORKSPACE}/{name}", bulk=True)]))
    for argv in (
        ["git", "push", "--force", "origin", "main"],
        ["git", "push", "-f"],
        ["git", "push", "--force-with-lease"],
    ):
        add(cases, "git force push", event([exec_effect(argv)]))
    add(
        cases,
        "git force push entailed",
        event(
            [exec_effect(["git", "push", "--force", "origin", "main"])],
            user_intent={"text": "请强制推送到 origin main"},
        ),
    )
    for argv, privilege in (
        (["sudo", "rm", "-rf", "C:/Windows/System32"], True),
        (["pkexec", "bash"], True),
        (["gsudo", "cmd"], True),
    ):
        add(cases, "privilege", event([exec_effect(argv, privilege=privilege)]))
    add(
        cases,
        "obfuscated intercepted",
        event([exec_effect(["cu''rl", "https://example.com"], obfuscated=True)], execution={"intercept": True}),
    )
    add(
        cases,
        "obfuscated unobserved",
        event(
            [exec_effect(["powershell", "-enc", "QQ=="], obfuscated=True)],
            normalization="partial",
            execution={"intercept": False},
        ),
    )
    add(cases, "remote script", event([exec_effect(["bash"], interpreter_sink=True)]))
    add(
        cases,
        "metadata fetch",
        event([{"type": "net.fetch", "method": "GET", "url": f"http://{METADATA}/latest", "host": METADATA}]),
    )
    add(cases, "localhost connect", event([{"type": "net.connect", "host": "localhost", "port": 80}]))
    add(
        cases,
        "pypi fetch",
        event([{"type": "net.fetch", "method": "GET", "url": "https://pypi.org/simple", "host": "pypi.org"}]),
    )
    add(
        cases,
        "files pypi fetch",
        event(
            [
                {
                    "type": "net.fetch",
                    "method": "GET",
                    "url": "https://files.pypi.org/packages/x",
                    "host": "files.pypi.org",
                }
            ]
        ),
    )
    add(
        cases,
        "unlisted head",
        event([{"type": "net.fetch", "method": "HEAD", "url": "https://example.com/file", "host": "example.com"}]),
    )
    add(cases, "git status", event([exec_effect(["git", "status"])]))
    add(
        cases,
        "pypi head",
        event([{"type": "net.fetch", "method": "HEAD", "url": "https://pypi.org/simple", "host": "pypi.org"}]),
    )
    for host in ("example.com", "github.com", "registry.npmjs.org"):
        add(
            cases,
            "unlisted get",
            event([{"type": "net.fetch", "method": "GET", "url": f"https://{host}/", "host": host}]),
        )
    for host in ("example.com", "github.com"):
        add(cases, "unlisted connect", event([{"type": "net.connect", "host": host, "port": 443}]))
    add(
        cases,
        "plain egress",
        event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://example.com/hook",
                    "host": "example.com",
                    "has_body": True,
                    "secret_like": False,
                }
            ]
        ),
    )
    add(
        cases,
        "secret egress",
        event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://example.com/hook",
                    "host": "example.com",
                    "has_body": True,
                    "secret_like": True,
                }
            ]
        ),
    )
    add(
        cases,
        "sensitive upload",
        event(
            [
                {
                    "type": "net.egress",
                    "method": "POST",
                    "url": "https://example.com/upload",
                    "host": "example.com",
                    "has_body": True,
                    "secret_like": False,
                    "local_file_attached": True,
                    "local_files": [f"{WORKSPACE}/.env"],
                }
            ]
        ),
    )
    add(
        cases,
        "raw disk write",
        event([fs("fs.write", r"\\.\PhysicalDrive0", path_kind="device", device_class="raw_disk")]),
    )
    add(cases, "volume write", event([fs("fs.write", r"\\.\C:", path_kind="device", device_class="volume")]))
    add(cases, "com port write", event([fs("fs.write", r"\\.\COM1", path_kind="device", device_class="other")]))
    add(cases, "pipe read", event([fs("fs.read", r"\\.\pipe\agent", path_kind="named_pipe")]))
    add(cases, "partial without intercept", event([fs("fs.read", f"{WORKSPACE}/README.md")], normalization="partial"))
    add(cases, "failed without intercept", event([fs("fs.read", f"{WORKSPACE}/README.md")], normalization="failed"))
    add(
        cases,
        "partial with intercept",
        event([exec_effect(["bash"], obfuscated=True)], normalization="partial", execution={"intercept": True}),
    )
    add(cases, "schedule", event([{"type": "schedule.create", "name": "nightly"}]))
    add(cases, "outside nonsensitive read", event([fs("fs.read", "D:/public/readme.txt")]))
    add(cases, "trusted dir read", event([fs("fs.read", "D:/shared/notes.txt")]))
    add(
        cases,
        "outside write is not preauthorized",
        event([fs("fs.write", "D:/tmp/covered.txt", exists=False)], raw_name="bash"),
    )
    add(
        cases,
        "sandbox plane keeps force push",
        event([exec_effect(["git", "push", "--force"])], execution={"plane": "sandbox", "intercept": True}),
    )
    add(cases, "model call", event(category="model_call"))
    add(cases, "no effect", event([]))
    add(cases, "invalid empty", {})
    add(cases, "invalid missing id", {**event([fs("fs.read", f"{WORKSPACE}/README.md")]), "id": ""})
    add(
        cases,
        "invalid os",
        event(
            [fs("fs.read", f"{WORKSPACE}/README.md")], workspace={"root": WORKSPACE, "trusted_dirs": [], "os": "macos"}
        ),
    )
    add(
        cases,
        "escaped sandbox",
        event([fs("fs.read", f"{WORKSPACE}/README.md")], execution={"plane": "sandbox", "escaped": True}),
    )
    outside_reads = ["D:/public/a.txt", "D:/public/b.txt", "E:/docs/c.txt", "C:/temp/readme.txt"]
    for path in outside_reads:
        add(cases, "outside read", event([fs("fs.read", path)]))
    system_writes = ["C:/Windows/System32/drivers/etc/hosts", "C:/Windows/SysWOW64/new.dll"]
    for path in system_writes:
        add(cases, "system critical write", event([fs("fs.write", path, exists=True)]))
    if len(cases) != 100:
        raise ValueError(f"expected 100 cases, got {len(cases)}")
    for case in cases:
        body = case["body"]
        if isinstance(body, dict) and body.get("spec") == "agent-event/v1" and body.get("id") == "evt_pending":
            body["id"] = f"evt_{case['id']}"
    return cases


def main() -> None:
    cases = build()
    OUT.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log_line(f"wrote {len(cases)} cases to {OUT}")


if __name__ == "__main__":
    main()
