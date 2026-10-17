# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Unit tests for policy loading / schema version / reserved env vars."""

from __future__ import annotations

import pytest

from jiuwenbox.models.common import RESERVED_ENV_VARS
from jiuwenbox.models.policy import SecurityPolicy
from jiuwenbox.policy.loader import load_policy_from_text
from jiuwenbox.server.runtime.errors import PolicyValidationError


class TestSchemaVersion:
    def test_legacy_policy_without_schema_version_loads(self):
        policy = load_policy_from_text("name: legacy\n")
        assert policy.schema_version == 1
        assert policy.name == "legacy"

    def test_explicit_v1_loads(self):
        policy = load_policy_from_text("schema_version: 1\nname: v1\n")
        assert policy.schema_version == 1
        assert policy.name == "v1"

    def test_future_version_rejected(self):
        with pytest.raises(PolicyValidationError):
            load_policy_from_text("schema_version: 999\nname: future\n")

    def test_boolean_schema_version_rejected(self):
        with pytest.raises(PolicyValidationError):
            load_policy_from_text("schema_version: true\nname: bad\n")


class TestReservedEnvVars:
    def test_reserved_set_contains_sandbox_ip(self):
        assert "SANDBOX_IP" in RESERVED_ENV_VARS

    def test_policy_cannot_override_sandbox_ip(self):
        with pytest.raises(Exception):
            SecurityPolicy.model_validate(
                {"environment": {"SANDBOX_IP": "10.0.0.1"}}
            )

    def test_policy_allows_normal_env(self):
        policy = SecurityPolicy.model_validate(
            {"environment": {"FOO": "bar", "SANDBOX_IPCASE": "x"}}
        )
        assert policy.environment["FOO"] == "bar"


class TestCapabilityValidation:
    def test_unsupported_security_capability_fails_closed(self):
        from jiuwenbox.policy.capabilities import validate_policy_capabilities
        from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities
        from jiuwenbox.server.runtime.errors import CapabilityUnsupportedError

        policy = SecurityPolicy.model_validate(
            {"filesystem_policy": {"read_only": ["/usr"]}}
        )
        caps = RuntimeCapabilities(runtime_name="stub")  # everything False
        with pytest.raises(CapabilityUnsupportedError):
            validate_policy_capabilities(policy, caps)

    def test_supported_capability_passes(self):
        from jiuwenbox.policy.capabilities import validate_policy_capabilities
        from jiuwenbox.server.runtime.capabilities import RuntimeCapabilities

        policy = SecurityPolicy.model_validate(
            {"filesystem_policy": {"read_only": ["/usr"]}}
        )
        caps = RuntimeCapabilities(runtime_name="bubblewrap", filesystem_acl=True)
        warnings = validate_policy_capabilities(policy, caps)
        assert warnings == []