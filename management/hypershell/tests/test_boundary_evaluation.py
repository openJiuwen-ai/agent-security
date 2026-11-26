"""Uncertain, incomplete or substituted observations must not pass acceptance."""

from copy import deepcopy
import errno
from ipaddress import IPv4Address

import pytest

from hypershell.runner.boundary_evaluation import evaluate_observation

HASH = "a" * 64
NAMESPACES = ("mnt", "net", "pid", "ipc", "uts", "cgroup")


@pytest.fixture
def sample():
    observed = {
        "schema_version": 1,
        "observations": {
            "linux_available": True,
            "identity": {
                "uid": 2001,
                "euid": 2001,
                "gid": 2001,
                "egid": 2001,
                "groups": [],
                "pid": 10,
                "cwd": "/workspace",
            },
            "proc_status": {"CapEff": 0, "CapBnd": 0xFFFFFFFF, "NoNewPrivs": 1, "Seccomp": 2},
            "cgroup": "0::/",
            "namespaces": {name: f"{name}:[{100 + index}]" for index, name in enumerate(NAMESPACES)},
        },
        "errors": [],
        "checks": [
            {
                "name": "own-file",
                "operation": "read",
                "executed": True,
                "outcome": "succeeded",
                "sha256": HASH,
                "bytes": 12,
                "path": "/workspace/test",
            },
            {
                "name": "private-file",
                "operation": "read",
                "executed": True,
                "outcome": "denied",
                "error_code": "ACCESS_DENIED",
                "errno": errno.EACCES,
                "path": "/private/test",
            },
        ],
    }
    host = deepcopy(observed)
    host["observations"]["namespaces"] = {name: f"{name}:[{200 + index}]" for index, name in enumerate(NAMESPACES)}
    expected = {
        "own-file": {"operation": "read", "outcome": "succeeded", "sha256": HASH, "path": "/workspace/test"},
        "private-file": {
            "operation": "read",
            "outcome": "blocked",
            "allow_errno": [errno.EACCES],
            "path": "/private/test",
        },
    }
    return observed, host, expected


def evaluate(sample, **kwargs):
    observed, host, expected = sample
    return evaluate_observation(
        observed, expected_uid=2001, expected_gid=2001, host_observation=host, expected_checks=expected, **kwargs
    )


def test_complete_observations_can_pass_without_claiming_individual_mechanism_attestation(sample):
    result = evaluate(sample)
    assert result["passed"]
    assert all(check["passed"] for check in result["checks"].values())
    assert any("Landlock" in text for text in result["limitations"])
    assert any("quotas" in text for text in result["limitations"])


@pytest.mark.parametrize(
    "field,value",
    [("uid", 0), ("euid", 0), ("gid", 0), ("egid", 0), ("uid", "2001"), ("groups", [2001]), ("groups", None)],
)
def test_wrong_or_unknown_identity_fails(sample, field, value):
    sample[0]["observations"]["identity"][field] = value
    assert not evaluate(sample)["passed"]


@pytest.mark.parametrize(
    "field,value",
    [("CapEff", 1), ("CapEff", False), ("NoNewPrivs", 0), ("NoNewPrivs", True), ("Seccomp", 0), ("Seccomp", None)],
)
def test_required_process_flags_are_strict_integer_evidence(sample, field, value):
    sample[0]["observations"]["proc_status"][field] = value
    assert not evaluate(sample)["passed"]


@pytest.mark.parametrize("namespace", NAMESPACES)
def test_every_namespace_including_cgroup_must_differ_from_host(sample, namespace):
    sample[0]["observations"]["namespaces"][namespace] = sample[1]["observations"]["namespaces"][namespace]
    assert not evaluate(sample)["passed"]


@pytest.mark.parametrize("value", [None, "", "different", "mnt:[0]", "net:[123]"])
def test_missing_or_malformed_namespace_is_not_isolation_evidence(sample, value):
    sample[0]["observations"]["namespaces"]["mnt"] = value
    assert not evaluate(sample)["passed"]


def test_missing_host_namespace_fails_closed(sample):
    sample[1]["observations"]["namespaces"].pop("net")
    assert not evaluate(sample)["passed"]


def test_virtual_root_cgroup_text_may_equal_host_but_namespace_must_differ(sample):
    assert sample[0]["observations"]["cgroup"] == sample[1]["observations"]["cgroup"] == "0::/"
    assert evaluate(sample, expected_cgroup="0::/")["passed"]
    assert not evaluate(sample, expected_cgroup="/")["passed"]
    assert not evaluate(sample, expected_cgroup="0::/other")["passed"]


@pytest.mark.parametrize("value", [None, "", "/", "not-membership", "0::/\x00"])
def test_cgroup_must_have_complete_proc_membership_data(sample, value):
    sample[0]["observations"]["cgroup"] = value
    assert not evaluate(sample)["passed"]


def test_reference_cgroup_requires_both_membership_and_same_namespace(sample):
    reference = deepcopy(sample[0])
    assert evaluate(sample, reference_observation=reference)["passed"]
    reference["observations"]["namespaces"]["cgroup"] = "cgroup:[999]"
    assert not evaluate(sample, reference_observation=reference)["passed"]
    reference = deepcopy(sample[0])
    reference["observations"]["cgroup"] = "0::/another"
    assert not evaluate(sample, reference_observation=reference)["passed"]


@pytest.mark.parametrize(
    "mutation", ["missing", "duplicate", "extra", "unexecuted", "wrong-operation", "wrong-target", "wrong-hash"]
)
def test_missing_duplicate_unexecuted_or_substituted_checks_fail(sample, mutation):
    checks = sample[0]["checks"]
    if mutation == "missing":
        checks.pop()
    elif mutation == "duplicate":
        checks.append(deepcopy(checks[0]))
    elif mutation == "extra":
        checks.append({**checks[0], "name": "unrequested"})
    elif mutation == "unexecuted":
        checks[0]["executed"] = False
    elif mutation == "wrong-operation":
        checks[0]["operation"] = "create"
    elif mutation == "wrong-target":
        checks[0]["path"] = "/unrelated/test"
    else:
        checks[0]["sha256"] = "b" * 64
    assert not evaluate(sample)["passed"]


def test_successful_read_requires_an_independently_expected_hash(sample):
    sample[2]["own-file"].pop("sha256")
    assert not evaluate(sample)["passed"]


@pytest.mark.parametrize(
    "error",
    [
        {"outcome": "error", "error_code": "PROBE_CHECK_ERROR", "errno": errno.EACCES},
        {"outcome": "error", "error_code": "TARGET_NOT_FOUND", "errno": errno.ENOENT},
        {"outcome": "denied", "error_code": "ACCESS_DENIED", "errno": None},
        {"outcome": "denied", "error_code": "ACCESS_DENIED", "errno": True},
        {"outcome": "succeeded", "error_code": "ACCESS_DENIED", "errno": errno.EACCES},
    ],
)
def test_unknown_inconsistent_and_non_allowlisted_errors_cannot_count_as_denial(sample, error):
    sample[0]["checks"][1].update(error)
    assert not evaluate(sample)["passed"]


def test_missing_path_is_accepted_only_when_explicitly_permitted_by_control_spec(sample):
    sample[0]["checks"][1].update(outcome="error", error_code="TARGET_NOT_FOUND", errno=errno.ENOENT)
    sample[2]["private-file"]["allow_errno"] = [errno.ENOENT]
    assert evaluate(sample)["passed"]


def test_network_timeout_requires_precise_exception_and_explicit_permission(sample):
    peer = str(IPv4Address(bytes((192, 0, 2, 1))))  # TEST-NET-1; this test evaluates records only.
    result = sample[0]["checks"][1]
    result.update(
        operation="tcp_connect",
        host=peer,
        port=19555,
        outcome="error",
        error_code="CONNECT_TIMEOUT",
        exception_type="TimeoutError",
        errno=None,
    )
    spec = sample[2]["private-file"]
    spec.update(operation="tcp_connect", allow_errno=[errno.ETIMEDOUT], host=peer, port=19555)
    spec.pop("path")
    assert evaluate(sample)["passed"]
    spec["allow_errno"] = [errno.EACCES]
    assert not evaluate(sample)["passed"]
    spec["allow_errno"] = [errno.ETIMEDOUT]
    result["exception_type"] = "RuntimeError"
    assert not evaluate(sample)["passed"]


def test_create_success_requires_own_file_cleanup_and_written_bytes(sample):
    sample[0]["checks"][0] = {
        "name": "own-file",
        "operation": "create",
        "path": "/workspace",
        "executed": True,
        "outcome": "succeeded",
        "created": True,
        "cleanup_succeeded": True,
        "bytes_written": 26,
    }
    sample[2]["own-file"] = {"operation": "create", "path": "/workspace", "outcome": "succeeded"}
    assert evaluate(sample)["passed"]
    sample[0]["checks"][0]["cleanup_succeeded"] = False
    assert not evaluate(sample)["passed"]


def test_create_expected_blocked_cannot_pass_after_a_file_was_created(sample):
    sample[0]["checks"][1].update(operation="create", created=True, cleanup_succeeded=True)
    sample[2]["private-file"]["operation"] = "create"
    assert not evaluate(sample)["passed"]


@pytest.mark.parametrize("envelope", [None, {}, {"observations": []}, {"observations": {"linux_available": False}}])
def test_malformed_or_non_linux_probe_fails_without_crashing(sample, envelope):
    result = evaluate_observation(
        envelope, expected_uid=2001, expected_gid=2001, host_observation=sample[1], expected_checks=sample[2]
    )
    assert not result["passed"]


def test_observation_errors_cannot_be_ignored(sample):
    sample[0]["errors"].append({"scope": "proc_status", "code": "READ_FAILED"})
    assert not evaluate(sample)["passed"]


def test_host_and_reference_accept_inner_observation_dicts(sample):
    assert evaluate_observation(
        sample[0],
        expected_uid=2001,
        expected_gid=2001,
        host_observation=sample[1]["observations"],
        expected_checks=sample[2],
        reference_observation=sample[0]["observations"],
    )["passed"]
