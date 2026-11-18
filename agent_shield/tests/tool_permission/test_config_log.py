"""Full-config map diff: leaf walk, print at top-level / approval id."""

from __future__ import annotations

import logging

from agent_shield.tool_permission.config_log import (
    _subtree_differs,
    flatten_config,
    log_config_diff,
)


def test_print_units_split_approval_overrides_by_id() -> None:
    units = flatten_config(
        {
            "tools": {"bash": "deny"},
            "approval_overrides": [
                {"id": "wild_014", "tools": ["bash"], "pattern": "x", "action": "allow"},
            ],
        }
    )
    assert units["tools"] == {"bash": "deny"}
    assert units["approval_overrides.wild_014"]["pattern"] == "x"
    assert "approval_overrides" not in units


def test_subtree_differs_short_circuits_after_first_leaf() -> None:
    left = {"a": 1, "b": {"c": 1, "d": 2}, "e": 3}
    right = {"a": 1, "b": {"c": 9, "d": 2}, "e": 3}
    assert _subtree_differs(left, right) is True
    assert _subtree_differs(left, left) is False


def test_log_config_diff_emits_create_update_remove(caplog) -> None:
    first = {
        "tools": {"bash": "deny", "read_file": "allow"},
        "host_guard": {"enabled": True},
        "approval_overrides": [
            {"id": "wild_014", "tools": ["bash"], "pattern": "echo A", "action": "allow"},
        ],
    }
    second = {
        "tools": {"bash": "allow", "read_file": "allow"},
        "approval_overrides": [
            {
                "id": "wild_014",
                "tools": ["bash"],
                "pattern": "echo B",
                "action": "allow",
            },
        ],
    }
    with caplog.at_level(logging.INFO, logger="agent_shield.tool_permission.config_log"):
        snap = log_config_diff(key="k", previous=None, config=first)
        log_config_diff(key="k", previous=snap, config=first)  # no-op
        log_config_diff(key="k", previous=snap, config=second)

    lines = [r.getMessage() for r in caplog.records]
    assert any("op=create field=tools value=" in line for line in lines)
    assert any("op=create field=host_guard value=" in line for line in lines)
    assert any(
        "op=create field=approval_overrides.wild_014 value=" in line for line in lines
    )
    assert sum("op=update field=tools value=" in line for line in lines) == 1
    assert any(
        "op=update field=tools value=" in line and "'bash': 'allow'" in line
        for line in lines
    )
    assert any(
        "op=update field=approval_overrides.wild_014 value=" in line
        and "echo B" in line
        for line in lines
    )
    assert any("op=remove field=host_guard" in line for line in lines)
    assert sum(1 for line in lines if "op=create field=tools" in line) == 1


def test_multi_leaf_change_under_one_unit_emits_once(caplog) -> None:
    previous = {
        "file_guard": {
            "enabled": True,
            "defaults": {"read": "ask", "write": "ask"},
            "workspace": {"read": "allow", "write": "allow"},
        }
    }
    current = {
        "file_guard": {
            "enabled": False,
            "defaults": {"read": "deny", "write": "deny"},
            "workspace": {"read": "ask", "write": "ask"},
        }
    }
    with caplog.at_level(logging.INFO, logger="agent_shield.tool_permission.config_log"):
        log_config_diff(key="k", previous=previous, config=current)

    lines = [r.getMessage() for r in caplog.records]
    updates = [line for line in lines if "op=update field=file_guard" in line]
    assert len(updates) == 1
    assert "'enabled': False" in updates[0]
