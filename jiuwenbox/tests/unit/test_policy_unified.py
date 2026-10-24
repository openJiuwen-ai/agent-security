# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for policy loading / schema version / reserved env vars."""

from __future__ import annotations

import pytest

from jiuwenbox.iptext import ipv4
from jiuwenbox.models.common import RESERVED_ENV_VARS
from jiuwenbox.models.policy import SecurityPolicy
from jiuwenbox.policy.loader import load_policy_from_text
from jiuwenbox.server.runtime.errors import PolicyValidationError


class TestSchemaVersion:
    @staticmethod
    def test_legacy_policy_without_schema_version_loads():
        policy = load_policy_from_text("name: legacy\n")
        assert policy.schema_version == 1
        assert policy.name == "legacy"

    @staticmethod
    def test_explicit_v1_loads():
        policy = load_policy_from_text("schema_version: 1\nname: v1\n")
        assert policy.schema_version == 1
        assert policy.name == "v1"

    @staticmethod
    def test_future_version_rejected():
        with pytest.raises(PolicyValidationError):
            load_policy_from_text("schema_version: 999\nname: future\n")

    @staticmethod
    def test_boolean_schema_version_rejected():
        with pytest.raises(PolicyValidationError):
            load_policy_from_text("schema_version: true\nname: bad\n")


class TestReservedEnvVars:
    @staticmethod
    def test_reserved_set_contains_sandbox_ip():
        assert "SANDBOX_IP" in RESERVED_ENV_VARS

    @staticmethod
    def test_policy_cannot_override_sandbox_ip():
        with pytest.raises(Exception):
            SecurityPolicy.model_validate(
                {"environment": {"SANDBOX_IP": ipv4(10, 0, 0, 1)}}
            )

    @staticmethod
    def test_policy_allows_normal_env():
        policy = SecurityPolicy.model_validate(
            {"environment": {"FOO": "bar", "SANDBOX_IPCASE": "x"}}
        )
        assert policy.environment["FOO"] == "bar"


class TestCapabilityValidation:
    @staticmethod
    def test_unsupported_security_capability_fails_closed():
        from jiuwenbox.policy.capabilities import validate_policy_capabilities
        from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities
        from jiuwenbox.server.runtime.errors import CapabilityUnsupportedError

        policy = SecurityPolicy.model_validate(
            {"filesystem_policy": {"read_only": ["/usr"]}}
        )
        caps = RuntimeCapabilities(runtime_name="stub")  # everything False
        with pytest.raises(CapabilityUnsupportedError):
            validate_policy_capabilities(policy, caps)

    @staticmethod
    def test_supported_capability_passes():
        from jiuwenbox.policy.capabilities import validate_policy_capabilities
        from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities

        policy = SecurityPolicy.model_validate(
            {"filesystem_policy": {"read_only": ["/usr"]}}
        )
        caps = RuntimeCapabilities(runtime_name="bubblewrap", filesystem_acl=True)
        warnings = validate_policy_capabilities(policy, caps)
        assert warnings == []