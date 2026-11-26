"""Exercise the installed VM demo and leave its verified instance running."""

import hashlib
import json
from pathlib import Path
import subprocess

from hypershell.config import load_document
from hypershell.console import log_console
from hypershell.runner.client import BoxClient


def _require(condition, message=""):
    if not condition:
        raise AssertionError(message)


BASE = Path("/var/lib/hypershell-managed/u1")
OPTIONS = [
    "--config",
    "/etc/hypershell-demo/admin.yaml",
    "--runtime",
    "/etc/hypershell-demo/runtime.yaml",
    "--user",
    "u1",
]
REPORT = {}


def application_python():
    runtime = load_document("/etc/hypershell-demo/runtime.yaml")
    return str(Path(runtime["source_dir"]) / ".venv/bin/python")


def command(action, *arguments, expected=0):
    result = subprocess.run(
        ["/usr/local/bin/hypershell-demo", action, *OPTIONS, *arguments], capture_output=True, text=True
    )
    _require(result.returncode == expected, (action, result.stdout, result.stderr))
    return json.loads(result.stdout if expected == 0 else result.stderr)


def content(result):
    _require(result["exit_code"] == 0, result)
    payload = json.loads(result["stdout"])
    _require(payload["ok"], payload)
    return payload["content"].strip()


def main():
    desktop = Path("/home/demo/Desktop/sample-data/README.md")
    knowledge = Path("/srv/hypershell-managed/knowledge/guide.txt")
    before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in [desktop, knowledge]}
    state = command("status")
    if state["phase"] == "STOPPED":
        state = command("start", "--request", "/etc/hypershell-demo/request.yaml")
    _require(state["phase"] == "RUNNING")
    REPORT["start"] = state
    client = BoxClient(BASE / "engine.sock")
    sid = state["sandbox_id"]
    probe = """import json,os,pathlib,socket
out={'uid':os.getuid(),'groups':os.getgroups(),'status':pathlib.Path('/proc/self/status').read_text()}
pathlib.Path('/workspace/integration.txt').write_text('WORKSPACE_OK\\n')
out['workspace']=pathlib.Path('/workspace/integration.txt').read_text()
paths = [('desktop', '/home/demo/Desktop/sample-data/README.md'), ('knowledge', '/resources/knowledge/guide.txt')]
for name,path in paths:
 try:
  with open(path,'a') as f:f.write('HS_DENIED_TEST\\n')
  out[name]='UNEXPECTED_WRITE'
 except OSError as exc:out[name]=type(exc).__name__
s=socket.socket();s.settimeout(2);out['unauthorized_connect']=s.connect_ex(('1.1.1.1',443));s.close()
print(json.dumps(out))
"""
    result = client.execute(sid, [application_python(), "-B", "-c", probe])
    _require(result["exit_code"] == 0, result)
    observed = json.loads(result["stdout"])
    _require(observed["uid"] != 0 and observed["groups"] == [])
    _require(observed["workspace"] == "WORKSPACE_OK\n")
    _require(observed["desktop"] == "FileNotFoundError")
    _require(observed["knowledge"] in ("PermissionError", "OSError"))
    _require(observed["unauthorized_connect"] != 0)
    for path, digest in before.items():
        _require(hashlib.sha256(Path(path).read_bytes()).hexdigest() == digest)
    REPORT["boundary"] = observed
    REPORT["host_files_unchanged"] = True
    first = content(
        command(
            "chat",
            "--session",
            "managed-acceptance",
            "Remember code CEDAR582. Reply only MANAGED_OK. Do not use tools.",
        )
    )
    second = content(
        command(
            "chat",
            "--session",
            "managed-acceptance",
            "What code did I ask you to remember? Reply only the code. Do not use tools.",
        )
    )
    _require(first == "MANAGED_OK" and second == "CEDAR582", (first, second))
    REPORT["chat"] = [first, second]
    stopped = command("stop")
    _require(stopped["phase"] == "STOPPED")
    _require(not Path("/var/run/netns", "jbx-" + sid).exists())
    rejected = command("chat", "Must not reach the host instance.", expected=2)
    _require("no host fallback" in rejected["error"]["message"])
    REPORT["stopped_no_fallback"] = True
    restarted = command("start", "--request", "/etc/hypershell-demo/request.yaml")
    _require(restarted["sandbox_id"] != sid)
    restored = content(
        command(
            "chat",
            "--session",
            "managed-acceptance",
            "What was the code I asked you to remember earlier? Reply only the code. Do not use tools.",
        )
    )
    _require(restored == "CEDAR582", restored)
    REPORT["restored"] = restored
    REPORT["final_state"] = command("status")
    (BASE / "verification.json").write_text(json.dumps(REPORT, ensure_ascii=False, indent=2))
    log_console(
        json.dumps({"passed": True, "sandbox_id": restarted["sandbox_id"], "report": str(BASE / "verification.json")})
    )


if __name__ == "__main__":
    main()
