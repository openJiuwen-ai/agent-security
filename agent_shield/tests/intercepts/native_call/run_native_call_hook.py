"""Run each native-call case inside a hooked process and save Decide's response.

probe.exe performs the real API call. process_guard injects the hook, the hook
asks Decide, and Decide calls the behavior policy engine before the API runs.
"""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent


def _load_sandbox_e2e():
    helper = ROOT / "tests" / "e2e_tests" / "run_sandbox_e2e.py"
    spec = importlib.util.spec_from_file_location("_sandbox_e2e", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_sandbox_e2e = _load_sandbox_e2e()
map_path = _sandbox_e2e.map_path
prepare = _sandbox_e2e.prepare
probe_args = _sandbox_e2e.probe_args
remap = _sandbox_e2e.remap

from agent_shield.policy_engine.server.decide import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry
from agent_shield.intercepts.native_call import settle_native_record
from agent_shield.intercepts.native_call.launch import ProcessGuardUnavailable, wrap
from agent_shield.tests.stdio import log_line

CASES = HERE / "native_call_cases.json"
RESULTS = HERE / "native_call_hook_results.jsonl"
BIN = ROOT / "native" / "windows-process-guard" / "build"
PROBE = BIN / "probe.exe"


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
        registry = RulesetRegistry(unmatched="none")
        info = registry.register({"spec": "agent-pdp/v1"})
        registry.open_task(info.ruleset_id, "user-a", "native-call-hook")
        super().__init__(
            host,
            source={"framework": "other", "session_id": "native-call-hook", "agent_id": "leader"},
            registry=registry,
            ruleset_id=info.ruleset_id,
            subject_id="user-a",
            task_id="native-call-hook",
        )
        self.captured: list[dict] = []

    def handle_native_record(self, record, *, binding):
        decision = settle_native_record(self, record, binding=binding)
        operation = record.get("operation") if isinstance(record, dict) else {}
        resources = operation.get("resources") if isinstance(operation, dict) else []
        paths = []
        if isinstance(resources, list):
            for item in resources:
                if isinstance(item, dict):
                    paths.append(
                        item.get("path")
                        or item.get("image")
                        or item.get("command_line")
                        or item.get("host")
                        or item.get("ip")
                    )
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


def primary(kind: str, decisions: list[dict]) -> dict | None:
    for item in decisions:
        if item.get("kind") == kind:
            return item
    return decisions[0] if decisions else None


def main() -> None:
    if not PROBE.is_file():
        raise SystemExit(f"probe is missing: {PROBE}. Build native/windows-process-guard first.")
    cases = json.loads(CASES.read_text(encoding="utf-8"))
    root = Path(tempfile.mkdtemp(prefix="native-call-hook-"))
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
        if resources and kind not in {"connect", "create_process"}:
            prepare(kind, resources, workspace, outside)
        argv = probe_args(str(PROBE), kind, access, resources)
        start = len(decide.captured)
        exit_code = None
        error = ""
        try:
            exit_code = wrap(argv, decide=decide, bin_dir=str(BIN), process_timeout_s=30)
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
        elif row["allow"] is None:
            key = f"exit {row['exit_code']} no_decision"
        else:
            key = "allow" if row["allow"] else "deny"
        counts[key] = counts.get(key, 0) + 1
    log_line(f"workspace {workspace}")
    log_line(f"recorded {len(rows)} runs in {RESULTS}")
    for key in sorted(counts):
        log_line(f"  {key}: {counts[key]}")


if __name__ == "__main__":
    main()
