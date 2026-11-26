"""Contracts that prevent one administrator-selected workspace affecting another."""

from copy import deepcopy
from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
import socket
from types import SimpleNamespace
import sys

import pytest
import yaml
from hypothesis import given, settings, strategies as st

from hypershell.config import AdminConfig
from hypershell.runner.client import RunnerError
from hypershell.runner.managed import ManagedRunner
from hypershell.runner.network import boundary_commands, install_boundary
from hypershell.runner.workspaces import validate_live_profiles, workspace_state_path
from hypershell.runner.engine import configure_workspace

PUBLIC_IPV4 = st.ip_addresses(v=4).filter(lambda address: address.is_global and not address.is_multicast).map(str)
PRIVATE_NETWORK = IPv4Network((IPv4Address(bytes((10, 0, 0, 0))), 8))


def config():
    data = yaml.safe_load((Path(__file__).parents[1] / "examples/demo/hypershell.yaml").read_text())
    data["users"]["u2"] = deepcopy(data["users"]["u1"])
    data["users"]["u2"].update(login_uid=1001, run_as_user="hs-u2", run_as_group="hs-u2")
    for suffix in ("state", "home", "project"):
        rid = "u2." + suffix
        data["resources"][rid] = deepcopy(data["resources"]["u1." + suffix])
        data["resources"][rid]["host_path"] = data["resources"][rid]["host_path"].replace("/u1/", "/u2/")
    # Use the real strict parser without a filesystem fixture.
    from unittest.mock import patch

    with patch("hypershell.config.load_document", return_value=data):
        for field in ("grants", "required"):
            data["users"]["u2"][field] = {k.replace("u1.", "u2."): v for k, v in data["users"]["u2"][field].items()}
        return AdminConfig.load("unused")


def identities(admin_config, second_uid=2002, second_gid=2002):
    return validate_live_profiles(
        admin_config,
        lambda name: SimpleNamespace(pw_uid=2001 if name == "hs-u1" else second_uid),
        lambda name: SimpleNamespace(gr_gid=2001 if name == "hs-u1" else second_gid),
    )


def test_workspace_state_is_namespaced_and_legacy_is_single_user_only():
    raw = {"state_root": "/var/lib/hypershell-managed"}
    assert workspace_state_path(raw, "u1", 2) != workspace_state_path(raw, "u2", 2)
    assert workspace_state_path({"state_dir": "/var/lib/old/u1"}, "u1", 1) == "/var/lib/old/u1"
    with pytest.raises(RunnerError, match="multiple users require"):
        workspace_state_path({"state_dir": "/var/lib/old/u1"}, "u2", 2)


@pytest.mark.parametrize("user", ["../u1", "/root", "u1/other", ".", "", "a" * 65])
def test_workspace_id_cannot_escape_state_root(user):
    with pytest.raises(RunnerError):
        workspace_state_path({"state_root": "/var/lib/hypershell-managed"}, user, 2)


@pytest.mark.parametrize("raw", [{}, {"state_dir": "/a", "state_root": "/b"}])
def test_ambiguous_state_configuration_is_rejected(raw):
    with pytest.raises(RunnerError):
        workspace_state_path(raw, "u1", 2)


def test_private_paths_and_read_only_shared_knowledge_are_compatible():
    assert identities(config()) == {"u1": (2001, 2001), "u2": (2002, 2002)}


@pytest.mark.parametrize("uid,gid", [(2001, 2002), (2002, 2001), (0, 2002), (2002, 0)])
def test_account_aliases_and_root_are_rejected(uid, gid):
    with pytest.raises(RunnerError):
        identities(config(), uid, gid)


@pytest.mark.parametrize(
    "path", ["/srv/hypershell/users/u1/project", "/srv/hypershell/users/u1/project/nested", "/srv/hypershell/users"]
)
def test_overlapping_private_resource_trees_are_rejected(path):
    from dataclasses import replace

    current = config()
    current.catalog["u2.project"] = replace(current.catalog["u2.project"], backend_ref=path)
    with pytest.raises(RunnerError, match="share writable"):
        identities(current)


def test_unknown_account_fails_closed():
    def missing(name):
        raise KeyError(name)

    with pytest.raises(RunnerError, match="does not exist"):
        validate_live_profiles(config(), missing, missing)


def test_engine_cannot_inherit_secrets_or_sweep_other_workspaces(monkeypatch):
    runner = object.__new__(ManagedRunner)
    runner.bin, runner.prefix, runner.base = Path("/runtime/bin"), Path("/runtime"), Path("/state/u1")
    runner.node_prefix = Path("/opt/node20")
    monkeypatch.setenv("PRIVATE_TEST_SECRET", "do-not-inherit")
    environment = runner.engine_environment()
    assert environment["JIUWENBOX_SKIP_ORPHAN_NET_CLEANUP"] == "1"
    assert "PRIVATE_TEST_SECRET" not in environment
    assert f"{runner.node_prefix}/bin" in environment["PATH"].split(":")
    assert environment["PYTHONDONTWRITEBYTECODE"] == "1"


@given(model_address=PUBLIC_IPV4)
def test_network_boundary_precedes_engine_exceptions_and_covers_ipv6(model_address):
    commands = boundary_commands("sandbox-1", [model_address])
    for binary in ("iptables", "ip6tables"):
        rules = [command[7:] for command in commands if command[4] == binary]
        assert ["-I", "OUTPUT", "1", "-j", "HS_OUTPUT"] in rules
        assert ["-I", "INPUT", "1", "-j", "HS_INPUT"] in rules
        assert ["-A", "HS_OUTPUT", "-j", "DROP"] in rules
        assert not any("53" in rule for rule in rules)
        external = [rule for rule in rules if "--dport" in rule]
        assert len(external) == (1 if binary == "iptables" else 0)
        if external:
            assert model_address in external[0]


@pytest.mark.parametrize("addresses", [[], [str(IPv4Address(socket.INADDR_LOOPBACK))]])
def test_model_boundary_rejects_missing_or_loopback_destinations(addresses):
    with pytest.raises(RunnerError):
        boundary_commands("sandbox-1", addresses)


@pytest.mark.parametrize("address_strategy", [st.ip_addresses(network=PRIVATE_NETWORK), st.ip_addresses(v=6)])
@given(data=st.data())
def test_model_boundary_rejects_private_or_ipv6_destinations(address_strategy, data):
    address = data.draw(address_strategy)
    with pytest.raises(RunnerError, match="requires public IPv4"):
        boundary_commands("sandbox-1", [str(address)])


@settings(max_examples=10)
@given(model_address=PUBLIC_IPV4)
def test_network_tool_failure_cannot_silently_downgrade(model_address):
    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("hypershell.runner.network.subprocess.run", lambda *a, **k: SimpleNamespace(returncode=1))
        with pytest.raises(RunnerError, match="boundary failed"):
            install_boundary("sandbox-1", [model_address])


@settings(max_examples=10)
@given(model_address=PUBLIC_IPV4)
def test_network_tool_timeout_is_a_structured_failure(model_address):
    import subprocess

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired("iptables", 15)

    with pytest.MonkeyPatch.context() as monkeypatch:
        monkeypatch.setattr("hypershell.runner.network.subprocess.run", timeout)
        with pytest.raises(RunnerError, match="tool unavailable"):
            install_boundary("sandbox-1", [model_address])


@pytest.mark.skipif(sys.platform != "linux", reason="requires Linux flock")
def test_workspaces_have_independent_locks_and_state(tmp_path):
    first, second = object.__new__(ManagedRunner), object.__new__(ManagedRunner)
    for runner, user in [(first, "u1"), (second, "u2")]:
        runner.base, runner.user_id = tmp_path / user, user
        runner.base.mkdir()
        runner.save({"user_id": user, "phase": "STOPPED"})
    with first.locked():
        with second.locked():
            second.save({"user_id": "u2", "phase": "STARTING"})
        with pytest.raises(RunnerError, match="busy"):
            with first.locked():
                pytest.fail("same-user lock was acquired twice")
    assert first.read_state()["phase"] == "STOPPED"
    assert second.read_state()["phase"] == "STARTING"


def test_multiuser_start_selects_own_request_even_if_missing(monkeypatch):
    import hypershell.cli as cli

    selected = []

    class Runner:
        def __init__(self, *args):
            pass

        @staticmethod
        def start(request):
            return {"phase": "RUNNING"}

    monkeypatch.setattr("hypershell.runner.managed.require_admin", lambda: None)
    monkeypatch.setattr("hypershell.runner.managed.trusted", lambda path: path)
    monkeypatch.setattr("hypershell.runner.managed.ManagedRunner", Runner)
    monkeypatch.setattr(cli.AdminConfig, "load", lambda path: SimpleNamespace(users={"u1": None, "u2": None}))
    monkeypatch.setattr(cli, "load_document", lambda path: selected.append(Path(path).name) or {"resources": []})
    assert cli.main(["start", "--user", "u2", "--config", "/nonexistent/admin.yaml"]) == 0
    assert selected == ["request-u2.yaml"]


def test_engine_storage_is_explicitly_scoped_before_imports():
    workspace = SimpleNamespace(
        JIUWENBOX_HOME=Path("/root/.jiuwenbox"), SANDBOX_WORKSPACE=Path("/root/.jiuwenbox/workspace")
    )
    configure_workspace(workspace, Path("/state/u2/engine-home"))
    assert workspace.JIUWENBOX_HOME == Path("/state/u2/engine-home")
    assert workspace.SANDBOX_WORKSPACE == Path("/state/u2/engine-home/workspace")


def test_engine_storage_configuration_refuses_late_mutation(monkeypatch):
    monkeypatch.setitem(sys.modules, "jiuwenbox.server.policy_engine", SimpleNamespace())
    with pytest.raises(RuntimeError, match="before workspace"):
        configure_workspace(SimpleNamespace(), Path("/state/u2"))
