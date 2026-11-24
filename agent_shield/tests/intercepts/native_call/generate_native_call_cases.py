"""Write 100 native-record/v1 bodies for a behavior-policy batch."""

from __future__ import annotations

import json
from pathlib import Path

from agent_shield.tests.net_addrs import CLOUDFLARE_DNS, PUBLIC_DNS
from agent_shield.tests.stdio import log_line

HERE = Path(__file__).resolve().parent
OUT = HERE / "native_call_cases.json"
WORKSPACE = "C:/Users/me/proj"

PROCESS = {
    "pid": 4200,
    "tid": 4212,
    "parent_pid": 3100,
    "process_instance_id": "4200:134214912000000000",
    "image": "C:/Program Files/PowerShell/7/pwsh.exe",
    "command_line": "pwsh -File build.ps1",
    "identity": {"user_sid": "S-1-5-21-1", "integrity_level": "medium"},
}


def record(category: str, kind: str, access: str, resources: list[dict]) -> dict:
    return {
        "spec": "native-record/v1",
        "request_id": "",
        "operation_id": "",
        "time": "2026-11-05T02:00:00Z",
        "process": dict(PROCESS),
        "operation": {"category": category, "kind": kind, "access": access, "resources": resources},
        "cause": {"tool_call_id": "call_native_batch", "name": "bash"},
    }


def file_op(kind: str, access: str, path: str, role: str = "subject", **extra) -> dict:
    resource = {"path": path, "role": role}
    resource.update(extra)
    return record("file", kind, access, [resource])


def pair(kind: str, source: str, target: str) -> dict:
    return record(
        "file",
        kind,
        "write",
        [
            {"path": source, "role": "source"},
            {"path": target, "role": "target"},
        ],
    )


def connect(host: str | None, ip: str | None, port: int) -> dict:
    return record("network", "connect", "connect", [{"role": "peer", "host": host, "ip": ip, "port": port}])


def execute(image: str, command_line: str) -> dict:
    return record(
        "process",
        "create_process",
        "execute",
        [{"role": "image", "image": image, "command_line": command_line}],
    )


def add(cases: list[dict], label: str, body: dict) -> None:
    cases.append({"label": label, "body": body})


def build() -> list[dict]:
    cases: list[dict] = []
    reads = [
        "src/app.py",
        "src/main.py",
        "src/util.py",
        "src/config.py",
        "src/api.py",
        "src/models.py",
        "README.md",
        "LICENSE",
        "docs/design.md",
        "docs/readme.md",
        "tests/test_app.py",
        "package.json",
        "pyproject.toml",
        "src/pkg/__init__.py",
        "src/pkg/service.py",
        "tests/conftest.py",
        "docs/api.md",
        "src/cli.py",
        "scripts/build.ps1",
        "src/logging.py",
        "src/errors.py",
        "tests/test_api.py",
    ]
    for name in reads:
        add(cases, "workspace read", file_op("open", "read", f"{WORKSPACE}/{name}"))

    writes = [
        "src/out.py",
        "src/generated.py",
        "src/new_module.py",
        "docs/notes.md",
        "build/note.txt",
        "tmp/log.txt",
        "tests/test_new.py",
        "src/pkg/extra.py",
        "docs/changelog.md",
        "tmp/cache.json",
    ]
    for name in writes:
        add(cases, "workspace write", file_op("create", "write", f"{WORKSPACE}/{name}", "target", exists=False))

    for index in range(1, 9):
        add(cases, "workspace delete", file_op("delete", "delete", f"{WORKSPACE}/tmp/old-{index}.txt", "target"))

    add(cases, "workspace mkdir", file_op("mkdir", "write", f"{WORKSPACE}/src/pkg", "target", exists=False))
    add(cases, "workspace mkdir", file_op("mkdir", "write", f"{WORKSPACE}/tests/fixtures", "target", exists=False))
    add(cases, "workspace copy", pair("copy", f"{WORKSPACE}/src/app.py", f"{WORKSPACE}/src/app.copy.py"))
    add(cases, "workspace move", pair("move", f"{WORKSPACE}/tmp/log.txt", f"{WORKSPACE}/tmp/log-old.txt"))
    add(cases, "workspace symlink", pair("symlink", f"{WORKSPACE}/src/app.py", f"{WORKSPACE}/src/app.link.py"))
    add(cases, "workspace hardlink", pair("hardlink", f"{WORKSPACE}/README.md", f"{WORKSPACE}/README.link.md"))

    for path in [
        f"{WORKSPACE}/.env",
        f"{WORKSPACE}/.env.local",
        f"{WORKSPACE}/secrets/id_rsa",
        f"{WORKSPACE}/keys/server.pem",
        f"{WORKSPACE}/.ssh/authorized_keys",
        f"{WORKSPACE}/.kube/config",
        f"{WORKSPACE}/.npmrc",
        "C:/Users/me/.aws/credentials",
    ]:
        add(cases, "sensitive read", file_op("open", "read", path))

    for path in [
        "C:/Windows/System32/kernel32.dll",
        "C:/Windows/System32/ntdll.dll",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/SysWOW64/ntdll.dll",
        "C:/Windows/System32/config/SAM",
        "C:/Windows/System32/cmd.exe",
    ]:
        add(cases, "system critical delete", file_op("delete", "delete", path, "target"))

    for path in [
        "C:/Windows/Temp/agent-new.dll",
        "C:/Windows/System32/newfilter.sys",
        "C:/Program Files/Vendor/new.exe",
        "C:/Windows/System32/drivers/extra.sys",
        "C:/Program Files/Common Files/plant.dll",
        "C:/Windows/Temp/staged.exe",
    ]:
        add(cases, "system write", file_op("create", "write", path, "target", exists=False))

    for path in [
        "C:/Users/other/notes.txt",
        "D:/public/readme.txt",
        "C:/Users/other/docs/guide.md",
        "D:/archive/report.pdf",
        "C:/Temp/shared.txt",
        "C:/Users/other/Desktop/todo.txt",
    ]:
        add(cases, "outside read", file_op("open", "read", path))

    for path in [
        "C:/Users/other/plant.txt",
        "D:/drop/payload.bin",
        "C:/Temp/staged.txt",
        "C:/Users/other/AppData/secret.dat",
        "D:/archive/old.dat",
        "C:/Temp/leftover.log",
    ]:
        add(cases, "outside write", file_op("create", "write", path, "target", exists=False))

    peers = [
        ("files.pythonhosted.org", None, 443),
        ("pypi.org", None, 443),
        ("example.com", None, 443),
        ("example.org", None, 80),
        (None, PUBLIC_DNS, 53),
        (None, CLOUDFLARE_DNS, 443),
        ("localhost", None, 80),
        (None, "127.0.0.1", 443),
    ]
    for host, ip, port in peers:
        add(cases, "network connect", connect(host, ip, port))

    commands = [
        ("git status", "C:/Program Files/Git/cmd/git.exe", "git status"),
        ("git diff", "C:/Program Files/Git/cmd/git.exe", "git diff"),
        ("git log", "C:/Program Files/Git/cmd/git.exe", "git log -1"),
        ("python script", "C:/Python311/python.exe", "python src/app.py"),
        ("pip install", "C:/Python311/python.exe", "pip install requests"),
        ("git force push", "C:/Program Files/Git/cmd/git.exe", "git push --force origin main"),
        (
            "encoded powershell",
            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "powershell -EncodedCommand QQ==",
        ),
        ("privilege escalate", "C:/Windows/System32/sudo.exe", "sudo rm C:/Windows/System32/kernel32.dll"),
        ("runas", "C:/Windows/System32/runas.exe", "runas /user:Administrator cmd.exe"),
        ("curl download", "C:/Windows/System32/curl.exe", "curl https://example.com/tool.ps1 -o tool.ps1"),
    ]
    for label, image, command in commands:
        add(cases, label, execute(image, command))

    add(cases, "pseudo device", file_op("open", "read", "NUL"))
    add(cases, "pseudo device", file_op("open", "read", r"\\.\CON"))
    add(
        cases,
        "raw disk write",
        record(
            "file",
            "device_open",
            "write",
            [{"path": r"\\.\PhysicalDrive0", "role": "subject", "device_class": "raw_disk"}],
        ),
    )
    add(
        cases,
        "named pipe",
        record("file", "pipe_open", "read", [{"path": r"\\.\pipe\other-service", "role": "subject"}]),
    )

    if len(cases) != 100:
        raise ValueError(f"expected 100 records, got {len(cases)}")
    for index, case in enumerate(cases, start=1):
        case["id"] = f"nc-{index:03d}"
        case["body"]["request_id"] = f"req_nc_{index:03d}"
        case["body"]["operation_id"] = f"op_nc_{index:03d}"
    return cases


def main() -> None:
    cases = build()
    OUT.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log_line(f"wrote {len(cases)} records to {OUT}")


if __name__ == "__main__":
    main()
