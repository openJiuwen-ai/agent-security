"""Unit tests for the P1 web byte relay (pure, cross-platform)."""

import pytest

from hypershell.runner.web_relay import RELAY_SOURCE, build_web_relay_command


def test_relay_source_compiles():
    compile(RELAY_SOURCE, "<web-relay>", "exec")


@pytest.mark.parametrize("port", [0, -1, 70000, "5173", None])
def test_build_rejects_bad_port(port):
    with pytest.raises(ValueError):
        build_web_relay_command("/usr/bin/python3", port=port)


def test_build_command_shape():
    argv = build_web_relay_command("/usr/bin/python3", port=5173)
    assert argv[0] == "/usr/bin/python3"
    assert argv[1:3] == ["-I", "-S"]
    assert argv[-1] == "5173"
    assert len(argv) == 6
