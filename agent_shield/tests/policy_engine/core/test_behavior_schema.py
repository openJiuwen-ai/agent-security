"""Load-time behavior clause checks. Failures are PolicyError."""

import pytest

from agent_shield.policy_engine.core.behavior_schema import validate_behavior_clause
from agent_shield.policy_engine.errors import PolicyError


def test_kubectl_delete_shape_is_accepted():
    validate_behavior_clause(
        {
            "effect": "process.exec",
            "argv0": ["kubectl", "oc"],
            "argv_prefix": ["delete"],
            "not": {"argv_has_any": ["--dry-run"]},
        }
    )


def test_effect_list_accepts_shared_keys_only():
    validate_behavior_clause({"effect": ["fs.read", "fs.write", "fs.delete"], "path.glob_any": ["**/.env"]})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": ["fs.read", "fs.write", "fs.delete"], "force": True})


def test_empty_unknown_and_old_negation_fail():
    with pytest.raises(PolicyError):
        validate_behavior_clause({})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": "process.exec", "argv_regex": ".*"})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": "net.fetch", "endpoint.not_in_any_catalog": ["allowlist_hosts"]})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": "fs.read", "path.in_catalog": {"not": "sensitiveFiles"}})


def test_not_cannot_carry_effect_or_another_not():
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": "process.exec", "not": {"effect": "fs.read"}})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"effect": "process.exec", "not": {"not": {"argv0": "rm"}}})


def test_any_branch_must_declare_effect_when_the_top_does_not():
    validate_behavior_clause(
        {"any": [{"effect": "privilege.escalate"}, {"effect": "process.exec", "shell_meta.privilege": True}]}
    )
    with pytest.raises(PolicyError):
        validate_behavior_clause({"any": [{"argv0": "sudo"}]})
    with pytest.raises(PolicyError):
        validate_behavior_clause({"argv0": "kubectl"})
