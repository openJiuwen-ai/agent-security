"""Operation roles and effects passed to the unified task policy."""

from agent_shield.intercepts.native_call.dll_guard.events import operation_to_event
from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.tests.net_addrs import PUBLIC_DNS


def _windows_context() -> dict:
    return {
        "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
        "source": {"framework": "jiuwenswarm"},
    }


def test_native_record_keeps_tool_cause_beside_native_name():
    event = operation_to_event(
        {
            "category": "file",
            "kind": "open",
            "access": "read",
            "resources": [{"path": "C:/Users/me/proj/a.txt", "role": "subject"}],
        },
        {
            "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
            "source": {"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
        },
        cause={"tool_call_id": "call_7f3", "name": "bash"},
    )
    assert event["cause"] == {"tool_call_id": "call_7f3", "name": "bash"}
    assert event["action"]["raw"]["name"] == "native"
    assert event["source"] == {
        "framework": "jiuwenswarm",
        "session_id": "sess",
        "agent_id": "leader",
    }
    assert "cause" not in event["source"]


def test_native_connect_does_not_invent_a_get():
    event = operation_to_event(
        {
            "category": "network",
            "kind": "connect",
            "access": "connect",
            "resources": [{"ip": PUBLIC_DNS, "port": 443, "host": None}],
        },
        _windows_context(),
    )
    kinds = [effect["type"] for effect in event["action"]["effects"]]
    assert kinds == ["net.connect"]


def test_copy_is_one_event_with_read_and_write():
    event = operation_to_event(
        {
            "category": "file",
            "kind": "copy",
            "access": "write",
            "resources": [
                {"path": "C:/Users/me/proj/a.txt", "role": "source"},
                {"path": "D:/other/b.txt", "role": "target"},
            ],
        },
        _windows_context(),
    )
    kinds = [effect["type"] for effect in event["action"]["effects"]]
    assert kinds == ["fs.read", "fs.write"]
    result = evaluate_event(event)
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "fs.write.outside"


def test_create_process_stamps_image_and_warns_on_program_mismatch():
    event = operation_to_event(
        {
            "category": "process",
            "kind": "create_process",
            "access": "execute",
            "resources": [
                {
                    "role": "image",
                    "image": "C:\\Windows\\System32\\reg.exe",
                    "command_line": "notepad.exe notes.txt",
                    "argv": ["C:\\Windows\\System32\\reg.exe", "notes.txt"],
                }
            ],
        },
        _windows_context(),
    )
    execs = [effect for effect in event["action"]["effects"] if effect["type"] == "process.exec"]
    assert execs[0]["image"].endswith("reg.exe")
    assert execs[0]["command_tokens"][0].lower().endswith("reg.exe")
    assert execs[0]["command_line"] == "notepad.exe notes.txt"
    assert "image_command_mismatch" in event["action"]["normalization"]["warnings"]


def test_compound_command_keeps_tokens_on_each_segment():
    event = operation_to_event(
        {
            "category": "process",
            "kind": "create_process",
            "access": "execute",
            "resources": [
                {
                    "role": "image",
                    "image": "C:\\Windows\\System32\\cmd.exe",
                    "command_line": "git status && rm -rf C:\\tmp\\a",
                }
            ],
        },
        _windows_context(),
    )
    execs = [
        effect for effect in event["action"]["effects"] if effect.get("type") == "process.exec"
    ]
    assert [effect["command_tokens"][0] for effect in execs] == ["git", "rm"]


def test_parent_process_image_does_not_mark_file_effects():
    event = operation_to_event(
        {
            "category": "file",
            "kind": "delete",
            "access": "delete",
            "resources": [{"path": "C:/Users/me/proj/a.txt", "role": "target"}],
        },
        _windows_context(),
    )
    assert event["action"]["effects"][0]["type"] == "fs.delete"
    assert "image" not in event["action"]["effects"][0]
