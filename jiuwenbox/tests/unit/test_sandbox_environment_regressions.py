# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Empty declarations must not widen the inherited command environment."""
import pytest

from jiuwenbox.server.environment import ENV_ALLOWLIST, inherited_environment


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
