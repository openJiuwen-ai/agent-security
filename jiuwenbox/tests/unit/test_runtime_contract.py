# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for runtime contract modules (no sandbox execution needed).

These tests run cross-platform and cover the pure-logic parts of the
unified-runtime refactor: error codes, capabilities, runtime selection, and
the runtime instance contract.
"""

from __future__ import annotations

import pytest

from jiuwenbox.models.sandbox import SandboxSpec
from jiuwenbox.server.runtime.base import RuntimeInstance
from jiuwenbox.server.runtime.capabilities import (
    RuntimeCapabilities,
    SECURITY_CAPABILITIES,
)
from jiuwenbox.server.runtime.errors import (
    CapabilityUnsupportedError,
    ErrorCode,
    HTTP_STATUS_BY_CODE,
    JiuwenboxError,
)
from jiuwenbox.server.runtime.registry import (
    RUNTIME_PROFILE_ENV,
    RuntimeResolutionError,
    platform_default_runtime,
    resolve_runtime_name,
)


class TestErrorCodes:
    @staticmethod
    def test_status_mapping_is_stable():
        assert HTTP_STATUS_BY_CODE[ErrorCode.POLICY_VALIDATION] == 400
        assert HTTP_STATUS_BY_CODE[ErrorCode.AUTH_FAILED] == 401
        assert HTTP_STATUS_BY_CODE[ErrorCode.NOT_FOUND] == 404
        assert HTTP_STATUS_BY_CODE[ErrorCode.CONFLICT] == 409
        assert HTTP_STATUS_BY_CODE[ErrorCode.CAPABILITY_UNSUPPORTED] == 422
        assert HTTP_STATUS_BY_CODE[ErrorCode.LIMIT_EXCEEDED] == 413
        assert HTTP_STATUS_BY_CODE[ErrorCode.RUNTIME_UNAVAILABLE] == 503

    @staticmethod
    def test_error_to_dict():
        err = CapabilityUnsupportedError("policy wants filesystem_acl")
        assert err.code == ErrorCode.CAPABILITY_UNSUPPORTED
        assert err.status_code == 422
        assert err.to_dict() == {
            "error": "capability_unsupported",
            "detail": "policy wants filesystem_acl",
        }

    @staticmethod
    def test_subclasses_are_jiuwenbox_errors():
        err = JiuwenboxError("generic")
        assert err.code == ErrorCode.INTERNAL_ERROR


class TestRuntimeCapabilities:
    @staticmethod
    def test_default_capabilities_are_false():
        caps = RuntimeCapabilities(runtime_name="stub")
        assert caps.local_pid is False
        assert caps.soft_delete is False
        assert caps.egress_filter is False

    @staticmethod
    def test_security_capabilities_set():
        assert "filesystem_acl" in SECURITY_CAPABILITIES
        assert "process_tree_containment" in SECURITY_CAPABILITIES
        assert "egress_filter" in SECURITY_CAPABILITIES
        assert "soft_delete" in SECURITY_CAPABILITIES
        # Non-security capabilities are allowed to fall back.
        assert "local_pid" not in SECURITY_CAPABILITIES
        assert "fast_file_io" not in SECURITY_CAPABILITIES


class TestRuntimeInstance:
    @staticmethod
    def test_instance_defaults():
        inst = RuntimeInstance(runtime_name="bubblewrap", instance_id="abc")
        assert inst.pid is None
        assert inst.ip_address is None
        assert inst.metadata == {}

    @staticmethod
    def test_instance_with_fields():
        inst = RuntimeInstance(
            runtime_name="bubblewrap",
            instance_id="abc",
            pid=42,
            ip_address="10.0.0.2",
            metadata={"netns": "sb-abc"},
        )
        assert inst.pid == 42
        assert inst.ip_address == "10.0.0.2"
        assert inst.metadata["netns"] == "sb-abc"


class TestRuntimeSelection:
    @staticmethod
    def test_platform_default_matches_host():
        import sys

        expected = "windows" if sys.platform == "win32" else "bubblewrap"
        assert platform_default_runtime() == expected

    @staticmethod
    def test_explicit_runtime_wins():
        assert resolve_runtime_name("windows") == "windows"
        assert resolve_runtime_name("bubblewrap") == "bubblewrap"

    @staticmethod
    def test_alias_mapping():
        assert resolve_runtime_name("process") == "bubblewrap"
        assert resolve_runtime_name("linux") == "bubblewrap"

    @staticmethod
    def test_env_profile_is_used():
        assert resolve_runtime_name(None, env={RUNTIME_PROFILE_ENV: "windows"}) == "windows"

    @staticmethod
    def test_explicit_beats_env_profile():
        assert (
            resolve_runtime_name("bubblewrap", env={RUNTIME_PROFILE_ENV: "windows"})
            == "bubblewrap"
        )

    @staticmethod
    def test_unknown_runtime_raises_on_load():
        from jiuwenbox.server.runtime.registry import load_runtime_class

        with pytest.raises(RuntimeResolutionError):
            load_runtime_class("definitely-not-a-runtime")


class TestSandboxSpecRuntimeField:
    @staticmethod
    def test_sandbox_spec_carries_runtime():
        spec = SandboxSpec(env={}, sandbox_runtime="windows")
        assert spec.sandbox_runtime == "windows"

    @staticmethod
    def test_sandbox_spec_default_none():
        spec = SandboxSpec(env={})
        assert spec.sandbox_runtime is None