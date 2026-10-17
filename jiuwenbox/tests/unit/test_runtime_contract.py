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
    def test_status_mapping_is_stable(self):
        assert HTTP_STATUS_BY_CODE[ErrorCode.POLICY_VALIDATION] == 400
        assert HTTP_STATUS_BY_CODE[ErrorCode.AUTH_FAILED] == 401
        assert HTTP_STATUS_BY_CODE[ErrorCode.NOT_FOUND] == 404
        assert HTTP_STATUS_BY_CODE[ErrorCode.CONFLICT] == 409
        assert HTTP_STATUS_BY_CODE[ErrorCode.CAPABILITY_UNSUPPORTED] == 422
        assert HTTP_STATUS_BY_CODE[ErrorCode.LIMIT_EXCEEDED] == 413
        assert HTTP_STATUS_BY_CODE[ErrorCode.RUNTIME_UNAVAILABLE] == 503

    def test_error_to_dict(self):
        err = CapabilityUnsupportedError("policy wants filesystem_acl")
        assert err.code == ErrorCode.CAPABILITY_UNSUPPORTED
        assert err.status_code == 422
        assert err.to_dict() == {
            "error": "capability_unsupported",
            "detail": "policy wants filesystem_acl",
        }

    def test_subclasses_are_jiuwenbox_errors(self):
        err = JiuwenboxError("generic")
        assert err.code == ErrorCode.INTERNAL_ERROR


class TestRuntimeCapabilities:
    def test_default_capabilities_are_false(self):
        caps = RuntimeCapabilities(runtime_name="stub")
        assert caps.local_pid is False
        assert caps.soft_delete is False
        assert caps.egress_filter is False

    def test_security_capabilities_set(self):
        assert "filesystem_acl" in SECURITY_CAPABILITIES
        assert "process_tree_containment" in SECURITY_CAPABILITIES
        assert "egress_filter" in SECURITY_CAPABILITIES
        assert "soft_delete" in SECURITY_CAPABILITIES
        # Non-security capabilities are allowed to fall back.
        assert "local_pid" not in SECURITY_CAPABILITIES
        assert "fast_file_io" not in SECURITY_CAPABILITIES


class TestRuntimeInstance:
    def test_instance_defaults(self):
        inst = RuntimeInstance(runtime_name="bubblewrap", instance_id="abc")
        assert inst.pid is None
        assert inst.ip_address is None
        assert inst.metadata == {}

    def test_instance_with_fields(self):
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
    def test_platform_default_matches_host(self):
        import sys

        expected = "windows" if sys.platform == "win32" else "bubblewrap"
        assert platform_default_runtime() == expected

    def test_explicit_runtime_wins(self):
        assert resolve_runtime_name("windows") == "windows"
        assert resolve_runtime_name("bubblewrap") == "bubblewrap"

    def test_alias_mapping(self):
        assert resolve_runtime_name("process") == "bubblewrap"
        assert resolve_runtime_name("linux") == "bubblewrap"

    def test_env_profile_is_used(self):
        assert resolve_runtime_name(None, env={RUNTIME_PROFILE_ENV: "windows"}) == "windows"

    def test_explicit_beats_env_profile(self):
        assert (
            resolve_runtime_name("bubblewrap", env={RUNTIME_PROFILE_ENV: "windows"})
            == "bubblewrap"
        )

    def test_unknown_runtime_raises_on_load(self):
        from jiuwenbox.server.runtime.registry import load_runtime_class

        with pytest.raises(RuntimeResolutionError):
            load_runtime_class("definitely-not-a-runtime")


class TestSandboxSpecRuntimeField:
    def test_sandbox_spec_carries_runtime(self):
        spec = SandboxSpec(env={}, sandbox_runtime="windows")
        assert spec.sandbox_runtime == "windows"

    def test_sandbox_spec_default_none(self):
        spec = SandboxSpec(env={})
        assert spec.sandbox_runtime is None