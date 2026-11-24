"""native record conversion and the decision it produces."""

from agent_shield.policy_engine.core.envelope import evaluate_event
from agent_shield.intercepts.native_call import ProcessBinding, native_record_to_event, settle_native_record
from agent_shield.tests.policy_engine.server.support import FakeHost, decide
from agent_shield.tests.net_addrs import PUBLIC_DNS


def _windows_context() -> dict:
    return {
        "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
        "source": {"framework": "jiuwenswarm"},
    }


def _binding() -> ProcessBinding:
    return ProcessBinding(10, 9, "10:100", r"C:\Windows\System32\cmd.exe", "S-1-5-21-1", "medium")


def test_native_workspace_write_allows_and_protected_delete_denies():
    host = FakeHost()
    task = decide(host)
    binding = _binding()
    write = {
        "spec": "native-record/v1",
        "request_id": "req_write",
        "operation_id": "op_write",
        "time": "2026-10-19T00:00:00Z",
        "process": {
            "pid": 10,
            "tid": 11,
            "parent_pid": 9,
            "process_instance_id": "10:100",
            "image": r"C:\Windows\System32\cmd.exe",
            "identity": {"user_sid": "S-1-5-21-1", "integrity_level": "Medium"},
        },
        "operation": {
            "category": "file",
            "kind": "write",
            "access": "write",
            "resources": [{"path": "C:/Users/me/proj/a.py", "role": "target"}],
        },
    }
    allowed = settle_native_record(task, write, binding=binding)
    assert allowed["allow"] is True
    assert allowed["spec"] == "native-decision/v1"
    protected = {
        **write,
        "request_id": "req_del",
        "operation_id": "op_del",
        "operation": {
            "category": "file",
            "kind": "delete",
            "access": "delete",
            "resources": [{"path": "C:/Windows/System32/drivers/etc/hosts", "role": "target"}],
        },
    }
    denied = settle_native_record(task, protected, binding=binding)
    assert denied["allow"] is False
    assert denied["reason"] == "fs.delete.protectedFiles"
    assert host.prompts == 0


def test_binding_mismatch_is_denied():
    task = decide(FakeHost())
    record = {
        "spec": "native-record/v1",
        "request_id": "req",
        "operation_id": "op",
        "time": "2026-10-19T00:00:00Z",
        "process": {"pid": 99, "tid": 11, "process_instance_id": "10:100"},
        "operation": {
            "category": "file",
            "kind": "read",
            "access": "read",
            "resources": [{"path": "C:/Users/me/proj/a"}],
        },
    }
    result = settle_native_record(task, record, binding=_binding())
    assert result["allow"] is False
    assert result["reason"] == "process_identity_mismatch"


def test_bulk_delete_reservation():
    host = FakeHost(answer=True)
    task = decide(host, delete_threshold=1)
    binding = _binding()

    def record(operation_id: str) -> dict:
        return {
            "spec": "native-record/v1",
            "request_id": operation_id,
            "operation_id": operation_id,
            "time": "2026-10-19T00:00:00Z",
            "process": {
                "pid": 10,
                "tid": 11,
                "parent_pid": 9,
                "process_instance_id": "10:100",
                "image": r"C:\Windows\System32\cmd.exe",
            },
            "operation": {
                "category": "file",
                "kind": "delete",
                "access": "delete",
                "resources": [{"path": "C:/Users/me/proj/a.txt", "role": "target"}],
            },
        }

    first = settle_native_record(task, record("op1"), binding=binding)
    assert first["allow"] is True
    assert first["reason"] == "fs.delete.userFiles"
    task.handle_operation_result(
        {"spec": "native-operation-result/v1", "operation_id": "op1", "success": True, "disposition": "trash"}
    )
    second = settle_native_record(task, record("op2"), binding=binding)
    assert second["reason"] == "fs.delete.bulk"
    assert second["allow"] is True
    assert host.prompts == 1


def test_native_record_keeps_tool_cause_beside_native_name():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2"},
            "cause": {"tool_call_id": "call_7f3", "name": "bash"},
            "operation": {
                "category": "file",
                "kind": "open",
                "access": "read",
                "resources": [{"path": "C:/Users/me/proj/a.txt", "role": "subject"}],
            },
        },
        {
            "workspace": {"root": "C:/Users/me/proj", "trusted_dirs": [], "os": "windows"},
            "source": {"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"},
        },
    )
    assert event["cause"] == {"tool_call_id": "call_7f3", "name": "bash"}
    assert event["action"]["raw"]["name"] == "native"
    assert event["source"] == {"framework": "jiuwenswarm", "session_id": "sess", "agent_id": "leader"}
    assert "cause" not in event["source"]


def test_native_connect_does_not_invent_a_get():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2"},
            "operation": {
                "category": "network",
                "kind": "connect",
                "access": "connect",
                "resources": [{"ip": PUBLIC_DNS, "port": 443, "host": None}],
            },
        },
        _windows_context(),
    )
    kinds = [effect["type"] for effect in event["action"]["effects"]]
    assert kinds == ["net.connect"]


def test_copy_is_one_event_with_read_and_write():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2"},
            "operation": {
                "category": "file",
                "kind": "copy",
                "access": "write",
                "resources": [
                    {"path": "C:/Users/me/proj/a.txt", "role": "source"},
                    {"path": "D:/other/b.txt", "role": "target"},
                ],
            },
        },
        _windows_context(),
    )
    kinds = [effect["type"] for effect in event["action"]["effects"]]
    assert kinds == ["fs.read", "fs.write"]
    result = evaluate_event(event)
    assert result["action"] == "ask"
    assert result["winner_rule_id"] == "fs.write.outside"


def test_injected_rules_deny_the_record():
    record = {
        "spec": "native-record/v1",
        "request_id": "req",
        "operation_id": "op",
        "time": "2026-10-19T00:00:00Z",
        "grants": [],
        "process": {"pid": 10, "tid": 11, "parent_pid": 9, "process_instance_id": "10:100"},
        "operation": {
            "category": "file",
            "kind": "read",
            "access": "read",
            "resources": [{"path": "C:/Users/me/proj/a"}],
        },
    }
    injected = settle_native_record(decide(FakeHost()), record, binding=_binding())
    assert injected["allow"] is False
    assert injected["reason"] == "invalid_event"


def test_create_process_stamps_image_and_warns_on_program_mismatch():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2", "image": r"C:\Windows\System32\sc.exe"},
            "operation": {
                "category": "process",
                "kind": "create_process",
                "access": "execute",
                "resources": [
                    {"role": "image", "image": r"C:\Windows\System32\reg.exe", "command_line": "notepad.exe notes.txt"}
                ],
            },
        },
        _windows_context(),
    )
    execs = [effect for effect in event["action"]["effects"] if effect["type"] == "process.exec"]
    assert execs[0]["image"].endswith("reg.exe")
    assert execs[0]["command_tokens"][0].lower() == "notepad.exe"
    assert "image_command_mismatch" in event["action"]["normalization"]["warnings"]


def test_compound_command_keeps_tokens_on_each_segment():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2"},
            "operation": {
                "category": "process",
                "kind": "create_process",
                "access": "execute",
                "resources": [
                    {
                        "role": "image",
                        "image": r"C:\Windows\System32\cmd.exe",
                        "command_line": "git status && rm -rf C:\\tmp\\a",
                    }
                ],
            },
        },
        _windows_context(),
    )
    execs = [effect for effect in event["action"]["effects"] if effect.get("type") == "process.exec"]
    assert [effect["command_tokens"][0] for effect in execs] == ["git", "rm"]


def test_parent_process_image_does_not_mark_file_effects():
    event = native_record_to_event(
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {"pid": 1, "tid": 2, "process_instance_id": "1:2", "image": r"C:\Windows\System32\sc.exe"},
            "operation": {
                "category": "file",
                "kind": "delete",
                "access": "delete",
                "resources": [{"path": "C:/Users/me/proj/a.txt", "role": "target"}],
            },
        },
        _windows_context(),
    )
    assert event["action"]["effects"][0]["type"] == "fs.delete"
    assert "image" not in event["action"]["effects"][0]


def test_created_image_is_audited_when_the_command_name_differs():
    host = FakeHost(hitl=False)
    task = decide(host)
    settle_native_record(
        task,
        {
            "spec": "native-record/v1",
            "request_id": "req",
            "operation_id": "op",
            "time": "2026-10-19T00:00:00Z",
            "process": {
                "pid": 10,
                "tid": 11,
                "parent_pid": 9,
                "process_instance_id": "10:100",
                "image": r"C:\Windows\System32\cmd.exe",
            },
            "operation": {
                "category": "process",
                "kind": "create_process",
                "access": "execute",
                "resources": [
                    {"role": "image", "image": r"C:\Windows\System32\reg.exe", "command_line": "notepad.exe notes.txt"}
                ],
            },
        },
        binding=_binding(),
    )
    recorded = next(item for item in reversed(task.registry.audit) if item["op"] == "decide")
    assert recorded["images"][0].endswith("reg.exe")
    assert recorded["image_command_mismatch"]["command"].lower() == "notepad.exe"
