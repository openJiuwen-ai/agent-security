"""A model's final answer cannot stand in for a native tool success event."""

import importlib
from pathlib import Path

import pytest


@pytest.fixture
def verify(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "examples/demo"))
    return importlib.import_module("verify_native_file").verify_events


def test_native_success_requires_fixture_content(verify):
    report = verify(
        [{"event_type": "chat.tool_result", "tool_name": "read_file", "success": True, "result": "EXPECTED_MARKER"}],
        "EXPECTED_MARKER",
    )
    assert report["marker_seen"] is True


@pytest.mark.parametrize(
    "event",
    [
        {"event_type": "chat.final", "content": "EXPECTED_MARKER"},
        {"event_type": "chat.tool_result", "tool_name": "bash", "success": True, "result": "EXPECTED_MARKER"},
        {"event_type": "chat.tool_result", "tool_name": "read_file", "success": False, "result": "EXPECTED_MARKER"},
        {"event_type": "chat.tool_result", "tool_name": "read_file", "success": True, "result": "wrong file"},
    ],
)
def test_final_text_fallback_and_failed_tools_do_not_pass(verify, event):
    with pytest.raises(AssertionError):
        verify([event], "EXPECTED_MARKER")
