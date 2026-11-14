"""Windows process guard preflight fails closed until the binaries are present."""

import pytest

from agent_shield.intercepts.native_call import ProcessGuardUnavailable, launch, preflight, wrap
from agent_shield.intercepts.native_call.dll_guard import bundle


def test_preflight_does_not_allow_a_bare_process(tmp_path, monkeypatch):
    monkeypatch.setattr(launch, "guard_binary_directory", lambda: tmp_path)
    result = preflight()
    assert result.ok is False
    assert result.intercept is False
    assert result.reason in {
        "unsupported_platform",
        "unsupported_architecture",
        "process_guard_binary_missing",
    }
    with pytest.raises(ProcessGuardUnavailable):
        wrap(["cmd.exe"])


def test_both_guards_resolve_the_installed_package(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(
        sys.modules, "agent_security_dll", SimpleNamespace(binary_directory=lambda: tmp_path)
    )
    with pytest.raises(bundle.GuardBundleMissingError, match="agent-security-dll"):
        bundle.locate_guard_dll()
    dll = tmp_path / "jiuwen_runtime_guard.dll"
    dll.touch()
    assert bundle.locate_guard_dll() == dll
    binaries = getattr(launch, "_binaries")
    names = getattr(launch, "_BINARIES")
    assert binaries() is None
    for name in names:
        (tmp_path / name).touch()
    assert binaries() == {name: str(tmp_path / name) for name in names}
    assert binaries(str(tmp_path / "explicit")) is None


def test_wrap_rejects_a_partial_tool_cause():
    with pytest.raises(ProcessGuardUnavailable) as raised:
        wrap(["cmd.exe"], tool_call_id="call_1")
    assert raised.value.reason == "invalid_tool_cause"
    with pytest.raises(ProcessGuardUnavailable) as raised:
        wrap(["cmd.exe"], tool_call_id="x" * 128, tool_name="bash")
    assert raised.value.reason == "invalid_tool_cause"
