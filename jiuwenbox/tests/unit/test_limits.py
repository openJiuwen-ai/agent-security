# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for the control-plane limits layer."""

from __future__ import annotations

from jiuwenbox.api.limits import resolve_limits


class TestLimits:
    @staticmethod
    def test_defaults():
        limits = resolve_limits(environ={})
        assert limits.max_request_body_bytes == 16 * 1024 * 1024
        assert limits.max_file_bytes == 256 * 1024 * 1024
        assert limits.max_exec_timeout_seconds == 3600.0

    @staticmethod
    def test_mb_env_override():
        limits = resolve_limits(environ={"JIUWENBOX_MAX_FILE_MB": "1"})
        assert limits.max_file_bytes == 1 * 1024 * 1024

    @staticmethod
    def test_kb_env_override():
        limits = resolve_limits(environ={"JIUWENBOX_MAX_STDIN_KB": "1024"})
        assert limits.max_stdin_bytes == 1024 * 1024

    @staticmethod
    def test_seconds_env_override():
        limits = resolve_limits(environ={"JIUWENBOX_EXEC_TIMEOUT_SECONDS": "60"})
        assert limits.max_exec_timeout_seconds == 60.0

    @staticmethod
    def test_invalid_env_falls_back():
        limits = resolve_limits(environ={"JIUWENBOX_MAX_FILE_MB": "not-a-number"})
        assert limits.max_file_bytes == 256 * 1024 * 1024