"""Write 100 native-record/v1 bodies for one sandbox Decide task."""

from __future__ import annotations

import json
from pathlib import Path

from agent_shield.tests.net_addrs import METADATA, PUBLIC_DNS
from agent_shield.tests.stdio import log_line

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "sandbox_records.json"
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


def record(category: str, kind: str, access: str, resources: list[dict], *, process: dict | None = None) -> dict:
    return {
        "spec": "native-record/v1",
        "request_id": "",
        "operation_id": "",
        "time": "2026-10-20T08:00:00Z",
        "process": process or PROCESS,
        "operation": {"category": category, "kind": kind, "access": access, "resources": resources},
    }


def file_op(kind: str, access: str, path: str, role: str = "subject", **extra) -> dict:
    resource = {"path": path, "role": role}
    resource.update(extra)
    return record("file", kind, access, [resource])


def add(cases: list[dict], label: str, body: dict) -> None:
    cases.append({"label": label, "body": body})


def build() -> list[dict]:
    cases: list[dict] = []
    reads = [
        "src/app.py",
        "src/main.py",
        "README.md",
        "docs/design.md",
        "tests/test_app.py",
        "package.json",
        "src/util.py",
        "src/config.py",
        "LICENSE",
        "src/api.py",
        "docs/readme.md",
        "src/models.py",
    ]
    for name in reads:
        add(cases, "workspace read", file_op("open", "read", f"{WORKSPACE}/{name}"))
    writes = ["src/out.py", "build/note.txt", "src/generated.py", "docs/notes.md", "tmp/log.txt", "src/new_module.py"]
    for name in writes:
        add(cases, "workspace write", file_op("create", "write", f"{WORKSPACE}/{name}", "target", exists=False))
    add(cases, "workspace mkdir", file_op("mkdir", "write", f"{WORKSPACE}/src/pkg", "target", exists=False))
    add(cases, "workspace mkdir", file_op("mkdir", "write", f"{WORKSPACE}/tests/fixtures", "target", exists=False))
    add(
        cases,
        "workspace copy",
        record(
            "file",
            "copy",
            "write",
            [
                {"path": f"{WORKSPACE}/src/app.py", "role": "source"},
                {"path": f"{WORKSPACE}/src/app.copy.py", "role": "target"},
            ],
        ),
    )
    add(
        cases,
        "workspace move",
        record(
            "file",
            "move",
            "write",
            [
                {"path": f"{WORKSPACE}/tmp/log.txt", "role": "source"},
                {"path": f"{WORKSPACE}/tmp/log-old.txt", "role": "target"},
            ],
        ),
    )
    add(
        cases,
        "workspace replace",
        record(
            "file",
            "replace",
            "write",
            [
                {"path": f"{WORKSPACE}/src/new_module.py", "role": "source"},
                {"path": f"{WORKSPACE}/src/app.py", "role": "target"},
                {"path": f"{WORKSPACE}/src/app.py.bak", "role": "backup"},
            ],
        ),
    )
    add(
        cases,
        "workspace symlink",
        record(
            "file",
            "symlink",
            "write",
            [
                {"path": f"{WORKSPACE}/src/app.py", "role": "source"},
                {"path": f"{WORKSPACE}/src/app.link.py", "role": "target"},
            ],
        ),
    )
    add(
        cases,
        "workspace hardlink",
        record(
            "file",
            "hardlink",
            "write",
            [
                {"path": f"{WORKSPACE}/README.md", "role": "source"},
                {"path": f"{WORKSPACE}/README.link.md", "role": "target"},
            ],
        ),
    )
    add(cases, "pseudo device", file_op("open", "read", "NUL"))
    add(cases, "pseudo device", file_op("open", "read", r"\\.\CON"))
    for name in ["C:/Users/other/notes.txt", "D:/public/readme.txt", "C:/Users/other/docs/guide.md"]:
        add(cases, "outside read", file_op("open", "read", name))
    for host in ["pypi.org", "files.pythonhosted.org", "upload.pypi.org"]:
        add(
            cases,
            "allowlist connect",
            record("network", "connect", "connect", [{"role": "peer", "host": host, "ip": None, "port": 443}]),
        )
    add(
        cases,
        "unlisted connect",
        record("network", "connect", "connect", [{"role": "peer", "host": "example.com", "ip": None, "port": 443}]),
    )
    add(
        cases,
        "unlisted connect",
        record("network", "connect", "connect", [{"role": "peer", "host": None, "ip": PUBLIC_DNS, "port": 53}]),
    )
    add(
        cases,
        "unlisted connect",
        record("network", "connect", "connect", [{"role": "peer", "host": "example.org", "ip": None, "port": 80}]),
    )
    add(
        cases,
        "process exec",
        record(
            "process",
            "create_process",
            "execute",
            [{"role": "image", "image": "C:/Program Files/Git/cmd/git.exe", "command_line": "git status"}],
        ),
    )
    add(
        cases,
        "process exec",
        record(
            "process",
            "create_process",
            "execute",
            [{"role": "image", "image": "C:/Program Files/Git/cmd/git.exe", "command_line": "git diff"}],
        ),
    )

    secrets = [
        f"{WORKSPACE}/.env",
        f"{WORKSPACE}/.env.local",
        f"{WORKSPACE}/secrets/id_rsa",
        f"{WORKSPACE}/keys/server.pem",
        "C:/Users/me/.aws/credentials",
        f"{WORKSPACE}/.ssh/authorized_keys",
        f"{WORKSPACE}/.kube/config",
        f"{WORKSPACE}/.npmrc",
    ]
    for path in secrets:
        add(cases, "sensitive file", file_op("open", "read", path))
    for path in [
        "C:/Windows/System32/kernel32.dll",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/Windows/SysWOW64/ntdll.dll",
    ]:
        add(cases, "system critical delete", file_op("delete", "delete", path, "target"))
    for path in [
        "C:/Windows/Temp/agent-new.dll",
        "C:/Windows/System32/newfilter.sys",
        "C:/Program Files/Vendor/new.exe",
    ]:
        add(cases, "system new file", file_op("create", "write", path, "target", exists=False))
    for path in ["C:/Users/other/secret.txt", "D:/archive/old.dat", "C:/Temp/leftover.log"]:
        add(cases, "outside delete", file_op("delete", "delete", path, "target"))
    for path in ["C:/Users/other/plant.txt", "D:/drop/payload.bin", "C:/Temp/staged.txt"]:
        add(cases, "outside write", file_op("create", "write", path, "target", exists=False))
    denylist = [
        {"host": None, "ip": METADATA, "port": 80},
        {"host": "metadata.google.internal", "ip": None, "port": 80},
        {"host": "localhost", "ip": None, "port": 80},
        {"host": None, "ip": "127.0.0.1", "port": 443},
        {"host": None, "ip": "::1", "port": 443},
        {"host": None, "ip": METADATA, "port": 443},
    ]
    for peer in denylist:
        add(cases, "denylist connect", record("network", "connect", "connect", [{"role": "peer", **peer}]))
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
        "volume write",
        record("file", "device_open", "write", [{"path": r"\\.\C:", "role": "subject", "device_class": "volume"}]),
    )
    add(
        cases,
        "named pipe",
        record("file", "pipe_open", "read", [{"path": r"\\.\pipe\other-service", "role": "subject"}]),
    )
    add(
        cases,
        "other device",
        record("file", "device_open", "read", [{"path": r"\\.\COM1", "role": "subject", "device_class": "other"}]),
    )
    commands = [
        ("git force push", "C:/Program Files/Git/cmd/git.exe", "git push --force origin main"),
        (
            "encoded powershell",
            "C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
            "powershell -EncodedCommand QQ==",
        ),
        ("privilege escalate", "C:/Windows/System32/sudo.exe", "sudo rm C:/Windows/System32/kernel32.dll"),
        ("runas", "C:/Windows/System32/runas.exe", "runas /user:Administrator cmd.exe"),
    ]
    for label, image, command in commands:
        add(
            cases,
            label,
            record(
                "process", "create_process", "execute", [{"role": "image", "image": image, "command_line": command}]
            ),
        )

    mismatched = dict(PROCESS)
    mismatched["pid"] = 99
    add(cases, "process identity mismatch", file_op("open", "read", f"{WORKSPACE}/src/app.py", process=mismatched))
    wrong_image = dict(PROCESS)
    wrong_image["image"] = "C:/Windows/System32/cmd.exe"
    add(cases, "process identity mismatch", file_op("open", "read", f"{WORKSPACE}/README.md", process=wrong_image))
    wrong_sid = json.loads(json.dumps(PROCESS))
    wrong_sid["identity"]["user_sid"] = "S-1-5-21-999"
    add(cases, "process identity mismatch", file_op("open", "read", f"{WORKSPACE}/LICENSE", process=wrong_sid))
    wrong_integrity = json.loads(json.dumps(PROCESS))
    wrong_integrity["identity"]["integrity_level"] = "high"
    add(
        cases,
        "process identity mismatch",
        file_op("open", "read", f"{WORKSPACE}/package.json", process=wrong_integrity),
    )

    invalid = record("file", "open", "read", [{"path": f"{WORKSPACE}/src/app.py", "role": "subject"}])
    invalid["operation"]["category"] = "socket"
    add(cases, "invalid record", invalid)
    missing = record("file", "open", "read", [{"path": f"{WORKSPACE}/src/app.py", "role": "subject"}])
    del missing["operation"]["resources"]
    add(cases, "invalid record", missing)

    for index in range(1, 23):
        add(cases, "workspace delete", file_op("delete", "delete", f"{WORKSPACE}/tmp/old-{index}.txt", "target"))

    if len(cases) != 100:
        raise ValueError(f"expected 100 records, got {len(cases)}")
    for index, case in enumerate(cases, start=1):
        case["id"] = f"sb-{index:03d}"
        case["body"]["request_id"] = f"req_sb_{index:03d}"
        case["body"]["operation_id"] = f"op_sb_{index:03d}"
    return cases


def main() -> None:
    cases = build()
    OUT.write_text(json.dumps(cases, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    log_line(f"wrote {len(cases)} records to {OUT}")


if __name__ == "__main__":
    main()
