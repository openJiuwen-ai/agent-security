"""Run each sandbox scenario in a real hooked process and record Decide's response."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from agent_shield.policy_engine.server.decide import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry
from agent_shield.intercepts.native_call import settle_native_record
from agent_shield.intercepts.native_call.launch import ProcessGuardUnavailable, wrap
from agent_shield.tests.stdio import log_line

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
RECORDS = HERE / "sandbox_records.json"
RESULTS = HERE / "sandbox_e2e_results.jsonl"
BIN = ROOT / "native" / "windows-process-guard" / "build"
PROBE = BIN / "probe.exe"
WORKSPACE_PREFIX = "c:/users/me/proj"


class Host:
    def __init__(self, root: Path) -> None:
        self._root = str(root)

    @staticmethod
    def user_intent():
        return {"text": "read the project file"}

    def workspace(self):
        return {"root": self._root, "trusted_dirs": [], "os": "windows"}

    @staticmethod
    def capabilities():
        return {"hitl": False, "auto_intent": True}

    @staticmethod
    def request_approval(decision, event):
        return False

    @staticmethod
    def user_rules():
        return []

    @staticmethod
    def grants():
        return []


class RecordingDecide(Decide):
    def __init__(self, host: Host) -> None:
        registry = RulesetRegistry(unmatched="allow")
        info = registry.register({"spec": "agent-pdp/v1"})
        registry.open_task(info.ruleset_id, "user-a", "task-a")
        super().__init__(
            host,
            source={"framework": "jiuwenswarm", "session_id": "sandbox-e2e", "agent_id": "leader"},
            registry=registry,
            ruleset_id=info.ruleset_id,
            subject_id="user-a",
            task_id="task-a",
        )
        self.captured: list[dict] = []

    def handle_native_record(self, record, *, binding):
        decision = settle_native_record(self, record, binding=binding)
        operation = record.get("operation") if isinstance(record, dict) else {}
        resources = operation.get("resources") if isinstance(operation, dict) else []
        paths = []
        if isinstance(resources, list):
            for item in resources:
                if not isinstance(item, dict):
                    continue
                paths.append(item.get("path") or item.get("image") or item.get("host") or item.get("ip"))
        self.captured.append(
            {
                "kind": operation.get("kind") if isinstance(operation, dict) else None,
                "access": operation.get("access") if isinstance(operation, dict) else None,
                "paths": paths,
                "allow": decision.get("allow"),
                "reason": decision.get("reason"),
                "response": decision,
            }
        )
        return decision


def map_path(path: str, workspace: Path, outside: Path) -> str:
    if path in {"NUL", "CON", "CONIN$", "CONOUT$"} or path.startswith("\\\\"):
        return path
    text = path.replace("\\", "/")
    lower = text.lower()
    prefixes = (
        (WORKSPACE_PREFIX, workspace),
        ("c:/users/other/", outside / "other"),
        ("c:/users/me/.aws/", outside / ".aws"),
        ("c:/temp/", outside / "temp"),
        ("d:/", outside / "d"),
    )
    for needle, dest in prefixes:
        if lower.startswith(needle):
            return str(Path(dest) / text[len(needle):].lstrip("/"))
    return path


def managed(path: str, workspace: Path, outside: Path) -> bool:
    try:
        resolved = Path(path).resolve()
    except OSError:
        return False
    return resolved.is_relative_to(workspace.resolve()) or resolved.is_relative_to(outside.resolve())


def ensure_file(path: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_text("x", encoding="utf-8")


def ensure_parent(path: str) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)


def role_path(resources: list[dict], role: str) -> str | None:
    for item in resources:
        if item.get("role") == role and isinstance(item.get("path"), str):
            return item["path"]
    return None


def prepare(kind: str, resources: list[dict], workspace: Path, outside: Path) -> None:
    paths = [item["path"] for item in resources if isinstance(item.get("path"), str)]
    writable = [path for path in paths if managed(path, workspace, outside)]
    if kind in {"open", "read"}:
        for path in writable:
            ensure_file(path)
    elif kind in {"delete", "rmdir"}:
        for path in writable:
            ensure_file(path)
    elif kind in {"create", "write", "mkdir"}:
        for path in writable:
            ensure_parent(path)
    elif kind in {"copy", "move", "symlink", "hardlink"}:
        source = role_path(resources, "source")
        target = role_path(resources, "target")
        if source and managed(source, workspace, outside):
            ensure_file(source)
        if target and managed(target, workspace, outside):
            ensure_parent(target)
    elif kind == "replace":
        source = role_path(resources, "source")
        target = role_path(resources, "target")
        backup = role_path(resources, "backup")
        if source and managed(source, workspace, outside):
            ensure_file(source)
        if target and managed(target, workspace, outside):
            ensure_file(target)
        if backup and managed(backup, workspace, outside):
            ensure_parent(backup)
            Path(backup).unlink(missing_ok=True)


def probe_args(probe: str, kind: str, access: str, resources: list[dict]) -> list[str]:
    source = role_path(resources, "source")
    target = role_path(resources, "target")
    if kind in {"open", "read"} and resources and isinstance(resources[0].get("path"), str):
        return [probe, "read", resources[0]["path"]]
    if kind == "mkdir" and target:
        return [probe, "mkdir", target]
    if kind in {"create", "write"} and resources and isinstance(resources[0].get("path"), str):
        return [probe, "write", resources[0]["path"]]
    if kind in {"delete", "rmdir"} and resources and isinstance(resources[0].get("path"), str):
        return [probe, "delete", resources[0]["path"]]
    if kind == "copy" and source and target:
        return [probe, "copy", source, target]
    if kind == "move" and source and target:
        return [probe, "move", source, target]
    if kind == "replace" and source and target:
        backup = role_path(resources, "backup")
        return [probe, "replace", source, target, backup] if backup else [probe, "replace", source, target]
    if kind == "symlink" and source and target:
        return [probe, "symlink", source, target]
    if kind == "hardlink" and source and target:
        return [probe, "hardlink", source, target]
    if kind == "connect" and resources:
        peer = resources[0]
        host = peer.get("host") or "-"
        ip = peer.get("ip") or "-"
        port = str(peer.get("port") or 80)
        return [probe, "connect", str(host), str(ip), port]
    if kind == "create_process" and resources:
        image = resources[0].get("image") or "-"
        command = resources[0].get("command_line") or image
        return [probe, "exec", str(image), str(command)]
    if kind in {"device_open", "pipe_open"} and resources and isinstance(resources[0].get("path"), str):
        mode = "write" if access == "write" else "read"
        return [probe, "open", mode, resources[0]["path"]]
    return [probe, "read", "NUL"]


def remap(body: dict, workspace: Path, outside: Path) -> dict:
    operation = json.loads(json.dumps(body["operation"]))
    for item in operation.get("resources") or []:
        if isinstance(item, dict) and isinstance(item.get("path"), str):
            item["path"] = map_path(item["path"], workspace, outside)
    return operation


def primary(kind: str, decisions: list[dict]) -> dict | None:
    for item in decisions:
        if item.get("kind") == kind:
            return item
    return decisions[0] if decisions else None


def main() -> None:
    if not PROBE.is_file():
        raise SystemExit(f"probe is missing: {PROBE}")
    cases = json.loads(RECORDS.read_text(encoding="utf-8"))
    root = Path(tempfile.mkdtemp(prefix="sandbox-e2e-"))
    workspace = root / "proj"
    outside = root / "outside"
    workspace.mkdir()
    outside.mkdir()
    decide = RecordingDecide(Host(workspace))
    rows = []
    for case in cases:
        operation = remap(case["body"], workspace, outside)
        kind = operation.get("kind") or ""
        access = operation.get("access") or ""
        resources = operation.get("resources") if isinstance(operation.get("resources"), list) else []
        note = ""
        if case["label"] == "process identity mismatch":
            note = "hook binds the real process, so this run cannot produce process_identity_mismatch"
        elif case["label"] == "invalid record":
            note = "hook emits a well-formed record, so this run cannot produce invalid_event"
        if resources:
            prepare(kind, resources, workspace, outside)
        argv = probe_args(str(PROBE), kind, access, resources)
        start = len(decide.captured)
        exit_code = None
        error = ""
        try:
            exit_code = wrap(argv, decide=decide, bin_dir=str(BIN), process_timeout_s=25)
        except ProcessGuardUnavailable as exc:
            error = exc.reason
        decisions = decide.captured[start:]
        chosen = primary(kind, decisions)
        row = {
            "id": case["id"],
            "label": case["label"],
            "kind": kind,
            "exit_code": exit_code,
            "error": error,
            "allow": None if chosen is None else chosen["allow"],
            "reason": None if chosen is None else chosen["reason"],
            "decisions": decisions,
            "note": note,
        }
        rows.append(row)
        log_line(
            f"{row['id']} {row['label']} exit={exit_code} allow={row['allow']} reason={row['reason']} {error}",
            flush=True,
        )
    RESULTS.write_text("".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows), encoding="utf-8")
    counts: dict[str, int] = {}
    for row in rows:
        if row["error"]:
            key = f"error {row['error']}"
        elif row["reason"] is None:
            key = f"exit {row['exit_code']} no_decision"
        else:
            key = f"{'allow' if row['allow'] else 'deny'} {row['reason']}"
        counts[key] = counts.get(key, 0) + 1
    log_line(f"workspace {workspace}")
    log_line(f"recorded {len(rows)} runs in {RESULTS}")
    for key in sorted(counts):
        log_line(f"  {key}: {counts[key]}")


if __name__ == "__main__":
    main()
