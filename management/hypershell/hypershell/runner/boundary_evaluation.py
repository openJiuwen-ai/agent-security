"""Fail-closed evaluation of live entry observations against trusted controls.

The probe reports facts; this module applies administrator expectations. Neither
an observation nor a successful behavioral sample independently attests every
kernel mechanism or establishes the provenance of the reporting process.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
import errno
import re
from typing import Any

_NAMESPACES = ("mnt", "net", "pid", "ipc", "uts", "cgroup")
_OPERATIONS = {"read", "create", "tcp_connect"}
_LIMITATIONS = [
    "Landlock behavioral coverage does not independently certify Landlock installation or its complete ruleset.",
    "Seccomp mode and sampled behavior do not certify the complete syscall filter.",
    "Cgroup namespace identity and /proc/self/cgroup do not independently prove effective controller quotas.",
    "Allowed missing-path or network-failure results require independent host/peer positive controls.",
    "Results apply to the measured entry, process, fixtures and runtime; "
    "they are not production multi-tenant certification.",
]


def _mapping(value: Any) -> Mapping:
    return value if isinstance(value, Mapping) else {}


def _observations(value: Any) -> Mapping:
    value = _mapping(value)
    return _mapping(value["observations"]) if "observations" in value else value


def _namespace(value: Any, name: str) -> bool:
    return isinstance(value, str) and re.fullmatch(re.escape(name) + r":\[[1-9][0-9]*\]", value) is not None


def _cgroup(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip() or len(value) > 65536:
        return None
    lines = value.strip().splitlines()
    if not all(re.fullmatch(r"[0-9]+:[a-zA-Z0-9_,=-]*:/[^\x00-\x1f]*", line) for line in lines):
        return None
    return "\n".join(lines)


def _integer(value: Any) -> bool:
    return type(value) is int


def _behavior(result: Mapping, spec: Mapping) -> tuple[bool, str]:
    operation = spec.get("operation")
    if not isinstance(operation, str) or operation not in _OPERATIONS:
        return False, "expected operation is missing or unsupported"
    if result.get("operation") != operation:
        return False, "observed operation differs from the expected operation"
    if result.get("executed") is not True:
        return False, "operation was not actually executed"
    for field in ("path", "host", "port", "timeout"):
        if field in spec and (type(result.get(field)) is not type(spec[field]) or result.get(field) != spec[field]):
            return False, "observed target differs from the expected " + field
    expected_outcome = spec.get("outcome")
    if expected_outcome == "succeeded":
        if (
            result.get("outcome") != "succeeded"
            or result.get("error_code") is not None
            or result.get("errno") is not None
        ):
            return False, "expected successful operation did not succeed cleanly"
        if operation == "read":
            if not isinstance(spec.get("sha256"), str) or re.fullmatch(r"[0-9a-f]{64}", spec["sha256"]) is None:
                return False, "successful read requires an independently expected SHA-256"
            if result.get("sha256") != spec["sha256"]:
                return False, "read contents do not match the expected SHA-256"
            if not _integer(result.get("bytes")) or result["bytes"] < 0:
                return False, "successful read lacks a valid byte count"
        elif operation == "create":
            if result.get("created") is not True or result.get("cleanup_succeeded") is not True:
                return False, "create did not complete and clean up its own probe file"
            if not _integer(result.get("bytes_written")) or result["bytes_written"] <= 0:
                return False, "successful create lacks evidence of written bytes"
        for field in ("sha256", "bytes", "bytes_written"):
            if field in spec and (type(result.get(field)) is not type(spec[field]) or result.get(field) != spec[field]):
                return False, "observed content differs from the expected " + field
        return True, "executed operation matched its expected successful result"
    if expected_outcome != "blocked":
        return False, "expected outcome must be succeeded or blocked"
    allowed = spec.get("allow_errno")
    if (
        not isinstance(allowed, (list, tuple))
        or not allowed
        or any(not _integer(number) or number <= 0 for number in allowed)
    ):
        return False, "blocked expectation requires an explicit nonempty errno allowlist"
    if operation == "create" and result.get("created") is not False:
        return False, "create succeeded or lacks evidence that no file was created"
    code, number, outcome = result.get("error_code"), result.get("errno"), result.get("outcome")
    known_failure = False
    if code == "ACCESS_DENIED":
        known_failure = outcome == "denied" and _integer(number) and number in {errno.EACCES, errno.EPERM, errno.EROFS}
    elif code == "TARGET_NOT_FOUND" and operation in {"read", "create"}:
        known_failure = outcome == "error" and _integer(number) and number == errno.ENOENT
    elif code == "CONNECT_TIMEOUT" and operation == "tcp_connect":
        # Python's socket TimeoutError often carries no numeric errno. Accept
        # that precise exception only when ETIMEDOUT was explicitly allowed.
        if number is None and result.get("exception_type") == "TimeoutError":
            number = errno.ETIMEDOUT
        known_failure = outcome == "error" and _integer(number) and number == errno.ETIMEDOUT
    elif code == "CONNECTION_REFUSED" and operation == "tcp_connect":
        known_failure = outcome == "error" and _integer(number) and number == errno.ECONNREFUSED
    elif code == "NETWORK_UNREACHABLE" and operation == "tcp_connect":
        known_failure = outcome == "error" and _integer(number) and number in {errno.ENETUNREACH, errno.EHOSTUNREACH}
    if not known_failure:
        return False, "unknown or inconsistent failure cannot establish that access was blocked"
    if number not in allowed:
        return False, "failure errno was not explicitly allowed by the expectation"
    return True, "executed operation produced an explicitly allowed blocking result"


def evaluate_observation(
    observed,
    *,
    expected_uid: int,
    expected_gid: int,
    host_observation: dict,
    expected_checks: Mapping[str, dict],
    expected_cgroup: str | None = None,
    reference_observation: dict | None = None,
) -> dict:
    """Compare a full probe envelope with independent, administrator-set facts.

    Host/reference arguments accept either a full probe envelope or its inner
    ``observations`` mapping. Check expectations require ``operation`` and
    ``outcome``. Successful reads require ``sha256``; blocked operations require
    explicit integer ``allow_errno`` values. Optional target fields are matched
    exactly. ``expected_cgroup`` is the complete /proc/self/cgroup content, not a
    substring or a path alone. A virtualized ``0::/`` remains valid evidence.
    """
    results = {}

    def record(name, passed, reason, **detail):
        results[name] = {"passed": bool(passed), "reason": reason, **detail}

    envelope = _mapping(observed)
    data = _mapping(envelope.get("observations"))
    host = _observations(host_observation)
    record(
        "observation.errors",
        isinstance(envelope.get("errors"), list) and not envelope["errors"],
        "probe observations must have an explicit empty error list",
    )
    record(
        "observation.schema",
        bool(data)
        and (
            "schema_version" not in envelope
            or type(envelope["schema_version"]) is int
            and envelope["schema_version"] == 1
        ),
        "probe must contain supported structured observations",
    )
    record("observation.linux", data.get("linux_available") is True, "live kernel observations require Linux")
    identity = _mapping(data.get("identity"))
    for field, expected in (
        ("uid", expected_uid),
        ("euid", expected_uid),
        ("gid", expected_gid),
        ("egid", expected_gid),
    ):
        actual = identity.get(field)
        record(
            "identity." + field,
            _integer(expected) and expected > 0 and _integer(actual) and actual == expected,
            "workload identity must equal the expected non-root identity",
            actual=actual,
            expected=expected,
        )
    record(
        "identity.groups",
        isinstance(identity.get("groups"), list) and not identity["groups"],
        "workload must have an explicitly empty supplementary group list",
    )
    status = _mapping(data.get("proc_status"))
    for field, expected in (("CapEff", 0), ("NoNewPrivs", 1), ("Seccomp", 2)):
        actual = status.get(field)
        record(
            "proc_status." + field,
            _integer(actual) and actual == expected,
            "required observed kernel process flag",
            actual=actual,
            expected=expected,
        )
    namespaces, host_namespaces = _mapping(data.get("namespaces")), _mapping(host.get("namespaces"))
    for name in _NAMESPACES:
        actual, baseline = namespaces.get(name), host_namespaces.get(name)
        record(
            "namespace." + name,
            _namespace(actual, name) and _namespace(baseline, name) and actual != baseline,
            "workload namespace must be observed and differ from the independently observed host namespace",
            actual=actual,
            host=baseline,
        )
    if "observations" in _mapping(host_observation):
        host_errors = _mapping(host_observation).get("errors")
        record(
            "host.errors",
            isinstance(host_errors, list) and not host_errors,
            "host control observations must have no observation errors",
        )
    cgroup = _cgroup(data.get("cgroup"))
    record("cgroup.observed", cgroup is not None, "cgroup membership must have complete, nonempty proc data")
    if expected_cgroup is not None:
        expected = _cgroup(expected_cgroup)
        record(
            "cgroup.expected",
            expected is not None and cgroup == expected,
            "cgroup membership must match the complete independently expected proc data",
        )
    if reference_observation is not None:
        reference = _observations(reference_observation)
        reference_cgroup = _cgroup(reference.get("cgroup"))
        record(
            "cgroup.reference",
            cgroup is not None and reference_cgroup is not None and cgroup == reference_cgroup,
            "entry cgroup membership must match the reference entry",
        )
        reference_ns = _mapping(reference.get("namespaces")).get("cgroup")
        record(
            "cgroup.reference_namespace",
            _namespace(reference_ns, "cgroup") and namespaces.get("cgroup") == reference_ns,
            "entry and reference must share the same cgroup namespace as well as its virtual membership text",
        )
        if "observations" in _mapping(reference_observation):
            reference_errors = _mapping(reference_observation).get("errors")
            record(
                "reference.errors",
                isinstance(reference_errors, list) and not reference_errors,
                "reference observations must have no observation errors",
            )
    specifications = _mapping(expected_checks)
    valid_specs = isinstance(expected_checks, Mapping) and all(
        isinstance(name, str) and name for name in specifications
    )
    raw_checks = envelope.get("checks")
    raw_checks = raw_checks if isinstance(raw_checks, list) else None
    names = [item.get("name") for item in raw_checks if isinstance(item, Mapping)] if raw_checks is not None else []
    valid_names = all(isinstance(name, str) and name for name in names)
    counts = Counter(name for name in names if isinstance(name, str))
    inventory_ok = (
        valid_specs
        and raw_checks is not None
        and valid_names
        and len(names) == len(raw_checks)
        and len(names) == len(counts)
        and set(counts) == set(specifications)
    )
    record(
        "checks.inventory",
        inventory_ok,
        "every expected check must occur exactly once, with no missing, malformed, duplicate or extra checks",
    )
    indexed = {
        item["name"]: item
        for item in raw_checks or []
        if isinstance(item, Mapping) and isinstance(item.get("name"), str)
    }
    for name, spec in specifications.items():
        if not isinstance(name, str):
            continue
        if counts.get(name) != 1:
            record("probe." + name, False, "expected check is missing or duplicated")
        elif not isinstance(spec, Mapping):
            record("probe." + name, False, "expected check specification must be a mapping")
        else:
            passed, reason = _behavior(indexed[name], spec)
            record("probe." + name, passed, reason)
    return {
        "passed": all(item["passed"] for item in results.values()),
        "checks": results,
        "limitations": list(_LIMITATIONS),
    }
