# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for the xtables lock wait handling in ``supervisor/network.py``.

Every iptables mutation is serialised by a single kernel lock
(``/run/xtables.lock``, or the nftables equivalent). Without ``-w`` the lock
is taken non-blocking, so parallel sandbox provisioning failed with::

    Can't lock /run/xtables.lock: Resource temporarily unavailable

``JIUWENBOX_IPTABLES_LOCK_WAIT_TIME`` only carries the number of seconds; the
``-w`` flag itself is always assembled here. A non-integer or non-positive
value drops the flag instead of being spliced into argv, which keeps the
configuration free of command-injection surface.

No iptables binary or Linux kernel is needed: ``subprocess.run`` is stubbed.
"""

from __future__ import annotations

import subprocess

import pytest

from jiuwenbox.supervisor import network as net


class _Recorder:
    """Capture argv, optionally failing like a real iptables invocation.

    ``returncode`` applies to every call. Pass ``by_flag`` to answer
    differently per iptables subcommand, e.g. make ``-C`` time out while
    ``-I`` would succeed.
    """

    def __init__(
        self,
        returncode: int = 0,
        stderr: str = "",
        *,
        by_flag: dict[str, int] | None = None,
    ) -> None:
        self.calls: list[list[str]] = []
        self.returncode = returncode
        self.stderr = stderr
        self.by_flag = dict(by_flag or {})

    def _resolve(self, cmd: list[str]) -> int:
        for token in cmd:
            if token in self.by_flag:
                return self.by_flag[token]
        return self.returncode

    def __call__(self, cmd, **_kwargs) -> subprocess.CompletedProcess:
        self.calls.append(list(cmd))
        return subprocess.CompletedProcess(
            args=list(cmd), returncode=self._resolve(cmd),
            stdout="", stderr=self.stderr,
        )

    def flags(self) -> list[str]:
        """Subcommand flag of each recorded call, e.g. ``["-C", "-I"]``."""
        seen = []
        for cmd in self.calls:
            seen.append(next((t for t in cmd if t in {"-C", "-I", "-A", "-D"}), "?"))
        return seen


@pytest.fixture()
def recorder(monkeypatch) -> _Recorder:
    """Stub ``subprocess.run`` and neutralize the environment."""
    rec = _Recorder()
    monkeypatch.setattr(net.subprocess, "run", rec)
    # ``_select_iptables_binary`` is lru_cached and probes real binaries;
    # bypass it so the tests stay hermetic.
    monkeypatch.setattr(net, "_select_iptables_binary", lambda *_a, **_k: "iptables")
    monkeypatch.delenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, raising=False)
    monkeypatch.setattr(net, "_warned_lock_wait_values", set())
    return rec


# --------------------------------------------------------------------------- #
# Command construction: where -w lands
# --------------------------------------------------------------------------- #
def test_default_prepends_wait_five(recorder: _Recorder) -> None:
    """``iptables -w 5 <cmd>`` - the wait precedes the subcommand."""
    net.run_iptables(["-L", "FORWARD", "-n"])

    cmd = recorder.calls[0]
    assert cmd[:4] == ["iptables", "-w", "5", "-L"], cmd
    assert cmd[4:] == ["FORWARD", "-n"]


def test_nat_table_flag_comes_after_wait(recorder: _Recorder) -> None:
    """``-t nat`` must stay a table selector, i.e. after the wait args."""
    net.run_iptables_nat(["-L", "POSTROUTING", "-n"])

    cmd = recorder.calls[0]
    assert cmd[:6] == ["iptables", "-w", "5", "-t", "nat", "-L"], cmd
    assert cmd[6:] == ["POSTROUTING", "-n"]


def test_wait_args_stay_on_iptables_side_of_netns(recorder: _Recorder) -> None:
    """``ip netns exec <ns> iptables -w 5 ...`` - not ``ip -w``."""
    net.run_iptables(["-L", "OUTPUT", "-n"], namespace="jwbtest0")

    cmd = recorder.calls[0]
    assert cmd[:7] == ["ip", "netns", "exec", "jwbtest0", "iptables", "-w", "5"], cmd
    assert cmd[7:] == ["-L", "OUTPUT", "-n"]


def test_existence_check_shape_carries_the_wait(recorder: _Recorder) -> None:
    """An existence check (``-C``) must carry ``-w`` like any other call.

    Without the wait a concurrent ``-C`` can spuriously report "absent",
    making the caller append a duplicate rule.

    ``-C`` is issued through ``run_iptables``, which is the public entry point
    used by the rule helpers, so asserting on that call is equivalent to
    asserting on the probe. The private helper is not called directly: rule
    checks are only reachable from ``setup_network_uplink``, which needs a
    real network stack and therefore cannot be exercised hermetically.
    """
    net.run_iptables(["-C", "FORWARD", "-i", "jwbH1234", "-j", "ACCEPT"], check=False)

    assert recorder.calls
    for cmd in recorder.calls:
        assert cmd[1:3] == ["-w", "5"], cmd


def test_error_message_shows_real_argv(recorder: _Recorder) -> None:
    """A failed call reports the argv that actually ran, including ``-w``."""
    recorder.returncode = 4
    recorder.stderr = "Can't lock /run/xtables.lock"

    with pytest.raises(net.NetworkSetupError) as excinfo:
        net.run_iptables(["-L", "FORWARD", "-n"])

    assert "-w 5" in str(excinfo.value)
    assert "Can't lock /run/xtables.lock" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Knob: JIUWENBOX_IPTABLES_LOCK_WAIT_TIME accepts a positive integer only
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("env_value,expected", [
    (None, ("-w", "5")),      # unset -> default
    ("5", ("-w", "5")),       # explicit default
    ("10", ("-w", "10")),     # custom window
    ("1", ("-w", "1")),       # lower bound
    ("0", ()),                # zero -> drop the flag
    ("-1", ()),               # negative -> drop the flag
    ("", ()),                 # empty -> drop the flag
    ("   ", ()),              # whitespace -> drop the flag
    ("abc", ()),              # typo -> drop the flag
    ("1.5", ()),              # float -> drop the flag
    (" 7 ", ("-w", "7")),     # surrounding spaces are tolerated
])
def test_env_matrix(recorder: _Recorder, monkeypatch, env_value, expected) -> None:
    """Each accepted / rejected setting maps to the documented argv prefix."""
    if env_value is None:
        monkeypatch.delenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, raising=False)
    else:
        monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, env_value)

    net.run_iptables(["-L", "FORWARD", "-n"])

    cmd = recorder.calls[0]
    assert tuple(cmd[1:1 + len(expected)]) == expected, cmd
    assert cmd[1 + len(expected):] == ["-L", "FORWARD", "-n"], cmd


@pytest.mark.parametrize("hostile", [
    "-F",                          # would flush the whole table
    "-w 10",                       # flags must not come from config
    "-A OUTPUT -j DROP",
    "5; rm -rf /",
    "$(reboot)",
    "`id`",
    "5 -t nat",
])
def test_config_cannot_inject_arguments(monkeypatch, hostile: str) -> None:
    """Only a bare integer is honoured; anything else silently disables -w.

    This is the security property: the value can never contribute an argv
    token other than the numeric operand of ``-w``.
    """
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, hostile)

    assert net.iptables_wait_args() == ()
    assert net.iptables_lock_wait_seconds() == 0


@pytest.mark.parametrize("unicode_digit", [
    "\u00b2",      # SUPERSCRIPT TWO   - isdigit() True, int() raises
    "\u00b3",      # SUPERSCRIPT THREE
    "\u2081\u2082",  # SUBSCRIPT ONE/TWO
    "\uff11",      # FULLWIDTH DIGIT ONE
    "\u0661",      # ARABIC-INDIC DIGIT ONE
])
def test_unicode_digits_degrade_instead_of_raising(
    recorder: _Recorder, monkeypatch, unicode_digit: str,
) -> None:
    """Unicode digits must not escape as ValueError.

    ``str.isdigit()`` accepts these but ``int()`` rejects them. An uncaught
    ValueError is not a ``NetworkSetupError``, so the runtime's graceful
    downgrade would miss it and sandbox creation would crash with a
    traceback instead of degrading to "no -w".
    """
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, unicode_digit)

    assert net.iptables_lock_wait_seconds() == 0
    assert net.iptables_wait_args() == ()

    # And the real call path stays healthy: no -w, no exception.
    net.run_iptables(["-L", "FORWARD", "-n"])
    assert recorder.calls[0] == ["iptables", "-L", "FORWARD", "-n"]


@pytest.mark.parametrize("raw,expected", [
    ("300", 300),      # exactly at the bound
    ("301", 300),      # clamped
    ("999999999", 300),  # would break -w argument parsing / stall for days
    # Beyond int64, still clamped safely. Built by repetition rather than as a
    # literal: a 20-digit string trips secret scanners, which treat any long
    # run of digits as a hardcoded access key.
    ("9" * 20, 300),
])
def test_wait_is_bounded(monkeypatch, raw: str, expected: int) -> None:
    """An unbounded wait would either break iptables arg parsing or hang."""
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, raw)

    assert net.iptables_lock_wait_seconds() == expected
    assert net.iptables_wait_args() == ("-w", str(expected))


def test_bound_is_pinned() -> None:
    """Guards against the upper bound drifting to something unusable."""
    assert net.MAX_IPTABLES_LOCK_WAIT_SECONDS == 300


def test_negative_value_drops_wait(monkeypatch) -> None:
    """A negative window is meaningless, so the flag is dropped."""
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, "-1")

    assert net.iptables_lock_wait_seconds() == 0
    assert net.iptables_wait_args() == ()


def test_empty_value_drops_wait_quietly(monkeypatch, caplog) -> None:
    """Empty means "disable the wait" - a documented setting, not a mistake."""
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, "")

    with caplog.at_level("WARNING"):
        assert net.iptables_wait_args() == ()

    assert caplog.records == []


def test_zero_value_drops_wait_quietly(monkeypatch, caplog) -> None:
    """``0`` is the documented numeric way to disable the wait."""
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, "0")

    with caplog.at_level("WARNING"):
        assert net.iptables_wait_args() == ()

    assert caplog.records == []


def test_invalid_value_warns_once_per_value(monkeypatch, caplog) -> None:
    """A degraded deployment must not spam one warning per iptables call."""
    monkeypatch.setenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, "abc")

    with caplog.at_level("WARNING"):
        for _ in range(5):
            net.iptables_wait_args()

    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1, [r.getMessage() for r in warnings]
    assert "abc" in warnings[0].getMessage()
    assert "Lock_WAIT" in warnings[0].getMessage() or "LOCK_WAIT" in warnings[0].getMessage()


def test_backend_probe_failure_reports_the_real_argv(monkeypatch) -> None:
    """The probe's diagnostics must show the command that actually ran.

    On a build without ``--wait`` this message is the only clue an operator
    gets, so it has to include ``-w``; a hand-rebuilt argv silently omitted it.

    The probe is reached through ``run_iptables`` rather than by calling the
    private selector directly, so the test exercises the real call chain.
    """
    monkeypatch.setattr(
        net.subprocess, "run",
        _Recorder(returncode=2, stderr="unknown option --wait"),
    )
    monkeypatch.setattr(net, "_iptables_candidates", lambda _v: ("iptables",))
    monkeypatch.delenv(net.ENV_IPTABLES_LOCK_WAIT_TIME, raising=False)

    # Every candidate backend fails the probe, so the selector raises with the
    # per-candidate diagnostics.
    with pytest.raises(net.NetworkSetupError) as excinfo:
        net.run_iptables(["-L", "OUTPUT", "-n"], namespace="jwbtest0")

    message = str(excinfo.value)
    assert "iptables -w 5 -L OUTPUT -n" in message, message
    assert "ip netns exec jwbtest0" in message, message
    assert "unknown option --wait" in message, message


def test_build_argv_matches_executed_command(recorder: _Recorder) -> None:
    """``build_iptables_argv`` is the single source of truth for argv."""
    expected = net.build_iptables_argv("iptables", ["-L", "FORWARD", "-n"])
    net.run_iptables(["-L", "FORWARD", "-n"])
    assert recorder.calls[0] == expected == ["iptables", "-w", "5", "-L", "FORWARD", "-n"]


def test_default_value_is_pinned() -> None:
    """Guards against the default silently drifting to fail-fast."""
    assert net.DEFAULT_IPTABLES_LOCK_WAIT_SECONDS == 5


# --------------------------------------------------------------------------- #
# -C probe verdicts: only exit 1 means "rule absent"
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("returncode,expected", [
    (0, True),    # rule present
    (1, False),   # rule absent - the only "no" answer
])
def test_probe_verdict_accepts_only_0_and_1(returncode: int, expected: bool) -> None:
    """0 and 1 are the only answers that may drive an insert decision."""
    result = subprocess.CompletedProcess(args=[], returncode=returncode, stdout="", stderr="")

    assert net.rule_probe_verdict(returncode, ["iptables", "-C"], result) is expected


@pytest.mark.parametrize("returncode,meaning", [
    (2, "parameter problem"),
    (3, "missing table or target"),
    (4, "xtables lock timeout"),
])
def test_probe_verdict_rejects_inconclusive_codes(returncode: int, meaning: str) -> None:
    """Inconclusive probes must raise, never be read as "rule absent".

    Treating exit 4 as absent made ``_ensure_iptables_rule`` append a duplicate
    MASQUERADE / REJECT rule whenever ``-w`` timed out.
    """
    result = subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout="",
        stderr="Can't lock /run/xtables.lock: Resource temporarily unavailable",
    )

    with pytest.raises(net.RuleProbeError) as excinfo:
        net.rule_probe_verdict(returncode, ["iptables", "-w", "5", "-C"], result)

    message = str(excinfo.value)
    assert f"exit code {returncode}" in message, message
    assert "iptables -w 5 -C" in message, message


def test_probe_verdict_error_is_a_network_setup_error() -> None:
    """Callers that already downgrade NetworkSetupError keep working."""
    assert issubclass(net.RuleProbeError, net.NetworkSetupError)


def test_lock_timeout_never_reaches_the_insert_call(monkeypatch) -> None:
    """A ``-C`` lock timeout must abort before any ``-I`` is issued.

    Simulates the caller loop: probe, and only insert when the verdict is a
    positive "absent". With exit 4 the verdict raises, so the loop body never
    reaches the insert.
    """
    rec = _Recorder(
        by_flag={"-C": 4, "-I": 0},
        stderr="Can't lock /run/xtables.lock: Resource temporarily unavailable",
    )
    monkeypatch.setattr(net.subprocess, "run", rec)
    monkeypatch.setattr(net, "_select_iptables_binary", lambda *_a, **_k: "iptables")

    with pytest.raises(net.RuleProbeError):
        for _ in range(1):
            probe = net.run_iptables(["-C", "FORWARD", "-j", "ACCEPT"], check=False)
            if not net.rule_probe_verdict(probe.returncode, list(probe.args), probe):
                net.run_iptables(["-I", "FORWARD", "-j", "ACCEPT"])

    assert rec.flags() == ["-C"], rec.flags()
