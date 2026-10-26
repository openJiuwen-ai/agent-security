"""The engine and manager leave enough in the log to tell who decided a tool call."""

from __future__ import annotations

import logging

import pytest

from agent_shield.tool_permission import PermissionManager
from agent_shield.tool_permission.engine import PermissionEngine

ENGINE_LOGGER = "agent_shield.tool_permission.engine"
MANAGER_LOGGER = "agent_shield.tool_permission.manager"

CONFIG = {
    "defaults": {"*": "allow"},
    "tools": {"bash": "deny", "read_file": "deny", "web_search": "deny"},
    "shell_allowlist": None,
}


def _decisions(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == ENGINE_LOGGER and "permission.engine.decision" in r.getMessage()
    ]


@pytest.mark.asyncio
async def test_decision_line_names_winner_and_every_subscribed_component(caplog) -> None:
    engine = PermissionEngine(CONFIG, label="k1")
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        await engine.check_permission("bash", {"command": "ls"})

    (line,) = _decisions(caplog)
    assert "key=k1" in line
    assert "tool=bash kind=original shell=True decision=deny matched_rule=tools.bash" in line
    assert "winner=TieredPolicyComponent basis=component" in line
    assert "TieredPolicyComponent=deny(tools.bash)" in line
    assert "DestructiveWarningComponent=none" in line


@pytest.mark.asyncio
async def test_non_shell_tool_still_runs_tiered_and_logs(caplog) -> None:
    engine = PermissionEngine(CONFIG)
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        await engine.check_permission("web_search", {"query": "x"})

    (line,) = _decisions(caplog)
    assert "kind=original shell=False decision=deny matched_rule=tools.web_search" in line
    assert "TieredPolicyComponent=deny(tools.web_search)" in line
    assert "basis=component" in line


@pytest.mark.asyncio
async def test_file_tool_logs_tiered_and_file_guard(caplog) -> None:
    engine = PermissionEngine(CONFIG)
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER):
        await engine.check_permission("read_file", {"path": "a.txt"})

    (line,) = _decisions(caplog)
    assert "kind=original shell=False" in line
    assert "TieredPolicyComponent=deny(tools.read_file)" in line
    assert "FileGuardComponent=none" in line


@pytest.mark.asyncio
async def test_tool_arguments_are_not_logged(caplog) -> None:
    engine = PermissionEngine(CONFIG)
    with caplog.at_level(logging.DEBUG, logger="agent_shield"):
        await engine.check_permission("bash", {"command": "echo TOP-SECRET-TOKEN"})

    assert "TOP-SECRET-TOKEN" not in caplog.text


@pytest.mark.asyncio
async def test_component_failure_is_logged_and_still_raised(caplog, monkeypatch) -> None:
    engine = PermissionEngine(CONFIG, label="k2")

    async def boom(*args, **kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(engine.components[3], "evaluate", boom)
    with caplog.at_level(logging.INFO, logger=ENGINE_LOGGER), pytest.raises(RuntimeError):
        await engine.check_permission("bash", {"command": "ls"})

    assert any(
        "component_failed key=k2 tool=bash kind=original component=TieredPolicyComponent"
        in r.getMessage()
        for r in caplog.records
    )


@pytest.mark.asyncio
async def test_manager_tags_decisions_with_key_and_logs_config_changes(caplog) -> None:
    manager = PermissionManager()
    with caplog.at_level(logging.INFO, logger="agent_shield"):
        manager.update_config(CONFIG, "u1")
        manager.update_config(CONFIG, "u1")
        await manager.check_permission("bash", {"command": "ls"}, "u1")
        await manager.check_permission("bash", {"command": "ls"}, config=CONFIG)
        manager.remove_config("u1")

    messages = [r.getMessage() for r in caplog.records]
    assert "permission.manager.update key=u1 replaced=False" in messages
    assert "permission.manager.update key=u1 replaced=True" in messages
    assert "permission.manager.remove key=u1 removed=True" in messages
    lines = _decisions(caplog)
    assert "key=u1 " in lines[0]
    assert "key=(one-off) " in lines[1]


@pytest.mark.asyncio
async def test_unregistered_key_logs_a_warning(caplog) -> None:
    manager = PermissionManager()
    with caplog.at_level(logging.WARNING, logger=MANAGER_LOGGER), pytest.raises(KeyError):
        await manager.check_permission("bash", {"command": "ls"}, "nobody")

    assert any("unregistered_key key=nobody" in r.getMessage() for r in caplog.records)
