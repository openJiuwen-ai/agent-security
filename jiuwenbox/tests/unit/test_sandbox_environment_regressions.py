# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Empty declarations must not widen the inherited command environment."""
import json

import pytest

from jiuwenbox.server.auth import get_configured_token
from jiuwenbox.server.environment import ENV_ALLOWLIST, inherited_environment
from jiuwenbox.supervisor.win_exec import _build_env_block


@pytest.mark.parametrize("value", ["", " ", "\t\r\n", "[]"])
@pytest.mark.parametrize("for_runner", [False, True])
def test_blank_environment_allowlist_is_an_empty_declaration(monkeypatch, value, for_runner):
    monkeypatch.setenv(ENV_ALLOWLIST, value)
    monkeypatch.setenv("UNDECLARED_SECRET", "not-inherited")
    result = inherited_environment(for_runner=for_runner)
    assert "UNDECLARED_SECRET" not in result


@pytest.mark.parametrize("value", ['{}', '[1]', '["bad-name"]', 'broken'])
def test_nonempty_invalid_environment_declarations_still_fail(monkeypatch, value):
    monkeypatch.setenv(ENV_ALLOWLIST, value)
    with pytest.raises(ValueError):
        inherited_environment()


def test_declared_empty_values_and_runner_loader_boundary_are_preserved(monkeypatch):
    monkeypatch.setenv(ENV_ALLOWLIST, '["TOOL_EMPTY", "PYTHONPATH"]')
    monkeypatch.setenv("TOOL_EMPTY", "")
    monkeypatch.setenv("PYTHONPATH", "service-only")
    assert inherited_environment()["TOOL_EMPTY"] == ""
    assert "PYTHONPATH" not in inherited_environment()
    assert inherited_environment(for_runner=True)["PYTHONPATH"] == "service-only"


@pytest.mark.parametrize("for_runner", [False, True])
def test_management_token_stays_in_service_even_when_explicitly_allowlisted(monkeypatch, for_runner):
    monkeypatch.setenv(ENV_ALLOWLIST, '["JIUWENBOX_API_TOKEN", "JIUWENBOX_INJECT_ENV"]')
    monkeypatch.setenv("JIUWENBOX_API_TOKEN", "service-test-token")
    monkeypatch.setenv("JIUWENBOX_INJECT_ENV", '{"jiuwenbox_api_token":"nested-test-token","TOOL_EMPTY":""}')
    result = inherited_environment(for_runner=for_runner)
    assert "JIUWENBOX_API_TOKEN" not in result
    assert json.loads(result["JIUWENBOX_INJECT_ENV"]) == {"TOOL_EMPTY": ""}
    assert get_configured_token() == "service-test-token"


def test_windows_process_environment_block_excludes_explicit_service_credentials():
    env = {
        "jiuwenbox_api_token": "direct-test-token",
        "jiuwenbox_inject_env": '{"JIUWENBOX_API_TOKEN":"nested-test-token","TOOL":"value"}',
        "PATH": "test-path",
    }
    block = "".join(_build_env_block(env))
    entries = dict(item.split("=", 1) for item in block.split("\0") if item)
    assert "jiuwenbox_api_token" not in entries
    assert json.loads(entries["jiuwenbox_inject_env"]) == {"TOOL": "value"}
    assert entries["PATH"] == "test-path"
    assert env["jiuwenbox_api_token"] == "direct-test-token"
