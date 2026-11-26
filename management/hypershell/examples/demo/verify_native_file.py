"""Require a real successful native read_file event from the managed VM app."""

import json
from pathlib import Path
import posixpath
import uuid

from hypershell.console import log_console
from hypershell.runner.client import BoxClient

from verify_vm_demo import BASE, application_python, command, content


def _require(condition, message=""):
    if not condition:
        raise AssertionError(message)


def verify_events(records, marker):
    results = [row for row in records if row.get("event_type") == "chat.tool_result"]
    for row in results:
        # JiuwenSwarm stores tool metadata as top-level fields in history.jsonl.
        if "read_file" in str(row.get("tool_name", "")):
            if row.get("success") is True and marker in json.dumps(row, ensure_ascii=False):
                return {"tool_name": row["tool_name"], "success": True, "marker_seen": True}
    raise AssertionError("no successful native read_file result containing the fixture marker")


def main():
    state = command("status")
    _require(state["phase"] == "RUNNING")
    client = BoxClient(BASE / "engine.sock")
    session = "native-read-" + uuid.uuid4().hex[:12]
    marker = "NATIVE_READ_" + uuid.uuid4().hex
    fixture = posixpath.join("/workspace", f"{session}.txt")
    probe = client.execute(
        state["sandbox_id"],
        [
            application_python(),
            "-B",
            "-c",
            "from pathlib import Path; Path(" + repr(fixture) + ").write_text(" + repr(marker + "\n") + ")",
        ],
    )
    _require(probe["exit_code"] == 0)
    content(
        command(
            "chat",
            "--session",
            session,
            f"Use only the native read_file tool to read {fixture} and return its contents. "
            "Do not use bash, shell, Python or other tools. You must actually call read_file.",
        )
    )
    history = Path("/srv/hypershell-managed/u1/data/agent/sessions") / session / "history.jsonl"
    rows = [json.loads(line) for line in history.read_text().splitlines() if line.strip()]
    report = {
        "passed": True,
        "session": session,
        "sandbox_id": state["sandbox_id"],
        "native_read": verify_events(rows, marker),
    }
    (BASE / "native-file-verification.json").write_text(json.dumps(report, indent=2))
    log_console(json.dumps(report))


if __name__ == "__main__":
    main()
