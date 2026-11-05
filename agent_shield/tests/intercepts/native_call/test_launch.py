"""Windows process guard preflight fails closed until the binaries are present."""

import pytest

from agent_shield.intercepts.native_call import ProcessGuardUnavailable, preflight, wrap


def test_preflight_does_not_allow_a_bare_process():
    result = preflight()
    assert result.ok is False
    assert result.intercept is False
    assert result.reason in {"unsupported_platform", "unsupported_architecture", "process_guard_binary_missing"}
    with pytest.raises(ProcessGuardUnavailable):
        wrap(["cmd.exe"])


def test_wrap_rejects_a_partial_tool_cause():
    with pytest.raises(ProcessGuardUnavailable) as raised:
        wrap(["cmd.exe"], tool_call_id="call_1")
    assert raised.value.reason == "invalid_tool_cause"
    with pytest.raises(ProcessGuardUnavailable) as raised:
        wrap(["cmd.exe"], tool_call_id="x" * 128, tool_name="bash")
    assert raised.value.reason == "invalid_tool_cause"
