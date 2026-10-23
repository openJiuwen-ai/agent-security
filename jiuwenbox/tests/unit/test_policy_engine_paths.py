# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Policy path checks accept both POSIX and Windows absolute paths."""

from __future__ import annotations

import pytest

from jiuwenbox.models.policy import SecurityPolicy
from jiuwenbox.server.policy_engine import PolicyEngine, PolicyValidationError
from jiuwenbox.server.workspace import SANDBOX_WORKSPACE


def _engine(tmp_path) -> PolicyEngine:
    return PolicyEngine(policies_dir=tmp_path)


def _policy(**filesystem_policy: object) -> SecurityPolicy:
    return SecurityPolicy.model_validate(
        {"name": "paths", "filesystem_policy": filesystem_policy}
    )


class TestAbsoluteSandboxPaths:
    def test_posix_absolute_read_write_passes(self, tmp_path):
        policy = _policy(read_write=["/opt/project"])
        assert policy.filesystem_policy.read_write == ["/opt/project"]
        _engine(tmp_path).validate_policy(policy)

    def test_windows_drive_paths_pass(self, tmp_path):
        engine = _engine(tmp_path)
        for path in (r"C:\Users\project", "C:/Users/project", "D:/work/repo"):
            policy = _policy(read_write=[path])
            engine.validate_policy(policy)

    def test_unc_path_passes(self, tmp_path):
        policy = _policy(read_write=[r"\\server\share\project"])
        _engine(tmp_path).validate_policy(policy)

    def test_relative_path_still_rejected(self, tmp_path):
        policy = _policy(read_write=["project/files"])
        with pytest.raises(PolicyValidationError, match="absolute sandbox paths"):
            _engine(tmp_path).validate_policy(policy)

    def test_bind_mount_accepts_windows_and_posix(self, tmp_path):
        engine = _engine(tmp_path)
        windows = _policy(
            bind_mounts=[{
                "host_path": r"C:\Users\project",
                "sandbox_path": r"C:\Users\project",
                "mode": "rw",
            }]
        )
        posix = _policy(
            bind_mounts=[{
                "host_path": "/host/project",
                "sandbox_path": "/sandbox/project",
                "mode": "rw",
            }]
        )
        engine.validate_policy(windows)
        engine.validate_policy(posix)

    def test_relative_bind_mount_rejected(self, tmp_path):
        policy = _policy(
            bind_mounts=[{
                "host_path": "relative/host",
                "sandbox_path": "/sandbox/project",
                "mode": "rw",
            }]
        )
        with pytest.raises(PolicyValidationError, match="absolute paths"):
            _engine(tmp_path).validate_policy(policy)

    def test_windows_workspace_path_stays_reserved(self, tmp_path):
        reserved = str(SANDBOX_WORKSPACE / "sbx")
        policy = _policy(read_write=[reserved])
        with pytest.raises(PolicyValidationError, match="server-managed backing storage"):
            _engine(tmp_path).validate_policy(policy)

    def test_posix_reserved_launcher_path_stays_rejected(self, tmp_path):
        policy = _policy(read_write=["/jiuwenbox/bin"])
        with pytest.raises(PolicyValidationError, match="reserved by"):
            _engine(tmp_path).validate_policy(policy)
