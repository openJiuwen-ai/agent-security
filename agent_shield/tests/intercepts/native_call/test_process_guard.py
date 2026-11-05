"""The process guard hooks a real process and fails closed."""

from pathlib import Path

import pytest

from agent_shield.policy_engine.server import Decide
from agent_shield.policy_engine.server.registry import RulesetRegistry
from agent_shield.intercepts.native_call import wrap
from agent_shield.intercepts.native_call import settle_native_record
from agent_shield.tests.net_addrs import METADATA

_BIN = Path(__file__).resolve().parents[3] / "native" / "windows-process-guard" / "build"


class Host:
    def __init__(self, root: str) -> None:
        self._root = root

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


def _binaries_ready() -> bool:
    names = ("process_guard.exe", "process_guard_hook_x64.dll", "process_guard_hook_x86.dll", "probe.exe")
    return all((_BIN / name).is_file() for name in names)


class RecordingDecide(Decide):
    def __init__(self, host: Host) -> None:
        registry = RulesetRegistry(unmatched="allow")
        info = registry.register({"spec": "agent-pdp/v1"})
        registry.open_task(info.ruleset_id, "user-a", "task-a")
        super().__init__(
            host,
            source={"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
            registry=registry,
            ruleset_id=info.ruleset_id,
            subject_id="user-a",
            task_id="task-a",
        )
        self.records: list[dict] = []

    def handle_native_record(self, record, *, binding):
        self.records.append(record)
        return settle_native_record(self, record, binding=binding)


@pytest.mark.skipif(not _binaries_ready(), reason="windows process guard binaries are not built")
def test_process_guard_allows_workspace_read_and_denies_a_ruled_metadata_connect(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hello", encoding="utf-8")
    registry = RulesetRegistry(unmatched="allow")
    info = registry.register(
        {
            "spec": "agent-pdp/v1",
            "rules": [
                {
                    "id": "org.metadata",
                    "object": "domain",
                    "action": "deny",
                    "ops": ["connect"],
                    "cidrs": [f"{METADATA}/32"],
                }
            ],
        }
    )
    registry.open_task(info.ruleset_id, "user-a", "task-a")
    decide = Decide(
        Host(str(tmp_path)),
        source={"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
        registry=registry,
        ruleset_id=info.ruleset_id,
        subject_id="user-a",
        task_id="task-a",
    )
    probe = str(_BIN / "probe.exe")
    assert wrap([probe, "read", str(target)], decide=decide, bin_dir=str(_BIN), process_timeout_s=60) == 0
    assert wrap([probe, "connect", "metadata"], decide=decide, bin_dir=str(_BIN), process_timeout_s=60) == 5


@pytest.mark.skipif(not _binaries_ready(), reason="windows process guard binaries are not built")
def test_process_guard_child_inherits_tool_cause(tmp_path):
    target = tmp_path / "note.txt"
    target.write_text("hello", encoding="utf-8")
    decide = RecordingDecide(Host(str(tmp_path)))
    probe = str(_BIN / "probe.exe")
    cause = {"tool_call_id": "call_7f3", "name": "bash"}
    assert (
        wrap(
            [probe, "read", str(target)],
            decide=decide,
            bin_dir=str(_BIN),
            process_timeout_s=60,
            tool_call_id="call_7f3",
            tool_name="bash",
        )
        == 0
    )
    assert decide.records
    assert all(record.get("cause") == cause for record in decide.records)
    decide.records.clear()
    assert (
        wrap(
            [probe, "exec", probe, f"{probe} read {target}"],
            decide=decide,
            bin_dir=str(_BIN),
            process_timeout_s=60,
            tool_call_id="call_7f3",
            tool_name="bash",
        )
        == 0
    )
    kinds = [record.get("operation", {}).get("kind") for record in decide.records]
    assert "create_process" in kinds
    assert "open" in kinds
    assert all(record.get("cause") == cause for record in decide.records)
