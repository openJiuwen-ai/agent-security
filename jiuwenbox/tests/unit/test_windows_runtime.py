# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for the Windows sandbox backend (phase 4, no host setup).

These tests exercise only the pure-logic, cross-platform surface of the
Windows backend: platform guarding, capability advertisement (soft delete
is intentionally excluded), egress filtering semantics, loopback-port
allocation, and the background-job downgrade path. No ``jbx-sandbox``
account, WFP filter, Job Object, or NTFS DACL mutation is required.
"""

from __future__ import annotations

import sys

import pytest

from jiuwenbox.models.policy import NetworkRulePolicy
from jiuwenbox.models.sandbox import BackgroundJobStatus, ExecResult
from jiuwenbox.server.runtime.base import RuntimeExecRequest
from jiuwenbox.server.runtime.errors import RuntimeUnavailableError
from jiuwenbox.server.runtime.windows.runtime import (
    BackgroundJob,
    WindowsRuntime,
    _alloc_loopback_port,
    _summarize_command,
)
from jiuwenbox.supervisor.win_proxy import EgressFilter


class TestPlatformGuard:
    @staticmethod
    def test_runtime_requires_windows(monkeypatch):
        if sys.platform == "win32":
            pytest.skip("runs on non-win32 hosts only")
        monkeypatch.setattr("jiuwenbox.server.runtime.windows.runtime.sys.platform", "linux")
        with pytest.raises(RuntimeUnavailableError):
            WindowsRuntime().ensure_platform()

    @staticmethod
    def test_runtime_name_and_supported_platforms():
        runtime = WindowsRuntime()
        assert runtime.runtime_name == "windows"
        assert runtime.supported_platforms == ("win32",)


class TestCapabilities:
    @staticmethod
    def test_soft_delete_is_excluded():
        caps = WindowsRuntime().capabilities()
        assert caps.runtime_name == "windows"
        assert caps.soft_delete is False
        assert caps.filesystem_acl is True
        assert caps.process_tree_containment is True
        assert caps.egress_filter is True
        assert caps.local_pid is True
        assert caps.fast_file_io is True
        assert caps.network_identity is False


class TestLoopbackPort:
    @staticmethod
    def test_allocates_ephemeral_port():
        port = _alloc_loopback_port()
        assert 1024 <= port <= 65535

    @staticmethod
    def test_allocated_ports_differ():
        ports = {_alloc_loopback_port() for _ in range(8)}
        assert len(ports) > 1


class TestSummarizeCommand:
    @staticmethod
    def test_short_command_is_verbatim():
        assert _summarize_command(["echo", "hi"]) == '["echo", "hi"]'

    @staticmethod
    def test_long_command_is_truncated():
        summary = _summarize_command(["python", "-c", "x" * 300])
        assert summary.endswith(" chars)")


class TestBackgroundJobModel:
    @staticmethod
    def test_job_defaults_running():
        job = BackgroundJob(
            job_id="job-1", sandbox_id="sb-1", command=["echo"], pid=42, workdir=None,
        )
        assert job.exit_code is None
        assert job.finished_at is None

    @staticmethod
    def test_status_maps_fields():
        job = BackgroundJob(
            job_id="job-1", sandbox_id="sb-1", command=["echo"], pid=42,
            workdir="C:\\ws", exit_code=0,
        )
        status = WindowsRuntime.job_status(job)
        assert isinstance(status, BackgroundJobStatus)
        assert status.job_id == "job-1"
        assert status.sandbox_id == "sb-1"
        assert status.running is False
        assert status.exit_code == 0


class TestFileOpHelpers:
    @staticmethod
    def test_unavailable_result():
        result = WindowsRuntime.file_op_unavailable("sb-1")
        assert result.ok is False
        assert result.error == "daemon_unavailable"

    @staticmethod
    def test_result_from_response_ok():
        result = WindowsRuntime.file_op_result_from_response({"ok": True})
        assert result.ok is True

    @staticmethod
    def test_result_from_response_errno():
        result = WindowsRuntime.file_op_result_from_response(
            {"ok": False, "error": "io_error", "errno": 2, "stderr": "nope"},
        )
        assert result.ok is False
        assert result.errno == 2
        assert result.error == "io_error"


class TestEgressFilter:
    @staticmethod
    def _filter(egress: NetworkRulePolicy) -> EgressFilter:
        return EgressFilter(egress, ingress=None)

    def test_default_deny_rejects_without_rules(self):
        f = self._filter(NetworkRulePolicy(default="deny"))
        assert f.allow("example.com", 443) == (False, "default deny (no allow rules)")

    def test_default_allow_passes_without_rules(self):
        f = self._filter(NetworkRulePolicy(default="allow"))
        assert f.allow("example.com", 443)[0] is True

    def test_blocked_domain_wins_over_default_allow(self):
        f = self._filter(NetworkRulePolicy(
            default="allow", blocked_domains=["evil.com"],
        ))
        allowed, reason = f.allow("evil.com", 443)
        assert allowed is False
        assert "blocked" in reason

    def test_wildcard_domain_matches_subdomains(self):
        f = self._filter(NetworkRulePolicy(
            default="deny", allowed_domains=["*.example.com"],
        ))
        assert f.allow("a.example.com", 443)[0] is True
        assert f.allow("example.com", 443)[0] is True
        assert f.allow("b.a.example.com", 443)[0] is True
        assert f.allow("example.org", 443)[0] is False

    def test_allowed_ip_cidr(self):
        f = self._filter(NetworkRulePolicy(
            default="deny", allowed_ips=["10.0.0.0/8"],
        ))
        assert f.allow("10.1.2.3", 443)[0] is True
        assert f.allow("192.168.1.1", 443)[0] is False

    def test_blocked_ip_wins_over_allowed(self):
        f = self._filter(NetworkRulePolicy(
            default="deny",
            allowed_ips=["0.0.0.0/0"],
            blocked_ips=["169.254.169.254/32"],
        ))
        assert f.allow("169.254.169.254", 80)[0] is False
        assert f.allow("8.8.8.8", 80)[0] is True

    def test_blocked_port(self):
        f = self._filter(NetworkRulePolicy(
            default="allow", blocked_ports=[22],
        ))
        assert f.allow("example.com", 22)[0] is False
        assert f.allow("example.com", 443)[0] is True

    def test_disable_all_short_circuits(self):
        f = self._filter(NetworkRulePolicy(default="allow"))
        f.disable_all = True
        assert f.allow("example.com", 443) == (False, "network disabled (disable_all)")


class TestExecDowngradeToSync:
    @pytest.mark.asyncio
    async def test_exec_background_records_finished_job(self):
        runtime = WindowsRuntime.__new__(WindowsRuntime)
        runtime.bind_exec_state(
            {"sb-1": {"control_port": 1, "control_token": "t", "pid": 1}},
        )

        async def fake_exec(sandbox_id, request):
            return ExecResult(exit_code=0, stdout="ok")

        runtime.exec = fake_exec
        from jiuwenbox.server.runtime.base import RuntimeBackgroundExecRequest

        result = await runtime.exec_background(
            "sb-1", RuntimeBackgroundExecRequest(command=["echo", "ok"], job_id="job-1"),
        )
        assert result.job_id == "job-1"
        assert result.running is False
        assert result.exit_code == 0
        stored = runtime.background_job("sb-1", "job-1")
        assert stored.exit_code == 0


class TestExecUnavailable:
    @pytest.mark.asyncio
    async def test_exec_reports_unavailable_runner(self):
        runtime = WindowsRuntime.__new__(WindowsRuntime)
        runtime.bind_exec_state({})

        result = await runtime.exec("sb-1", RuntimeExecRequest(command=["echo"]))
        assert result.exit_code == 1
        assert "不可用" in result.stderr
