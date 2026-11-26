"""Role composition must never bypass administrator bounds or isolation."""

from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from hypershell.cli import main
from hypershell.config import AdminConfig, ConfigError
from hypershell.policy import AccessMode, LaunchRequest, PolicyError
from hypershell.runner.client import RunnerError
from hypershell.runner.workspaces import validate_live_profiles


def data():
    value = yaml.safe_load((Path(__file__).parents[1] / "examples/demo/hypershell.yaml").read_text())
    value["version"] = 2
    value["roles"] = {
        "employee": {"description": "Shared knowledge", "grants": {"company-knowledge": "read"}},
        "viewer": {"grants": {"desktop-project": "read"}},
        "editor": {"grants": {"desktop-project": "read_write"}},
    }
    user = value["users"]["u1"]
    user["roles"] = ["employee", "viewer"]
    del user["grants"]["company-knowledge"]
    return value


def load(value):
    with patch("hypershell.config.load_document", return_value=value):
        return AdminConfig.load("unused")


def test_role_and_direct_grants_feed_same_compiler_and_request_stays_explicit():
    config = load(data())
    user = config.users["u1"]
    assert user.grants["company-knowledge"] == AccessMode.READ
    assert "company-knowledge" not in user.direct_grants
    plan = config.compile("u1", LaunchRequest(resources=user.required))
    assert "company-knowledge" not in plan.resources
    assert config.explain("u1", "company-knowledge")["resources"]["company-knowledge"]["sources"] == [
        {"source": "role:employee", "mode": "read"}
    ]


def test_union_is_order_independent_and_direct_grants_add_or_upgrade():
    value = data()
    user = value["users"]["u1"]
    user["roles"] += ["editor"]
    first = load(value)
    user["roles"].reverse()
    second = load(value)
    assert first.users["u1"].grants["desktop-project"] == AccessMode.READ_WRITE
    assert first.explain("u1") == second.explain("u1")
    del value["roles"]["editor"]
    user["roles"].remove("editor")
    user["grants"]["desktop-project"] = "read_write"
    assert load(value).users["u1"].grants["desktop-project"] == AccessMode.READ_WRITE


def test_deleting_one_source_keeps_other_sources_and_limits_dominate_all():
    value = data()
    user = value["users"]["u1"]
    user["grants"]["desktop-project"] = "read_write"
    user["roles"].remove("viewer")
    assert load(value).users["u1"].grants["desktop-project"] == AccessMode.READ_WRITE
    user["roles"].append("editor")
    user["resource_limits"] = {"desktop-project": "read", "company-knowledge": "none"}
    config = load(value)
    assert config.users["u1"].grants["desktop-project"] == AccessMode.READ
    assert "company-knowledge" not in config.users["u1"].grants
    assert config.users["u1"].grants["u1.project"] == AccessMode.READ_WRITE
    assert config.explain("u1")["resources"]["company-knowledge"]["effective"] == "none"
    with pytest.raises(PolicyError):
        config.compile(
            "u1", LaunchRequest(resources={**config.users["u1"].required, "company-knowledge": AccessMode.READ})
        )


def test_sparse_limits_alone_never_grant_and_empty_v2_user_is_allowed():
    value = data()
    user = value["users"]["u1"]
    for field in ("roles", "grants", "required"):
        user.pop(field, None)
    user["resource_limits"] = {"desktop-project": "read_write"}
    config = load(value)
    assert config.users["u1"].grants == {}
    assert config.explain("u1")["resources"]["desktop-project"]["effective"] == "none"


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d["users"]["u1"].update(roles=["missing"]),
        lambda d: d["users"]["u1"].update(roles=["employee", "employee"]),
        lambda d: d["users"]["u1"].update(roles=[{}]),
        lambda d: d["users"]["u1"].update(roles="employee"),
        lambda d: d["users"]["u1"].update(roles=None),
        lambda d: d.update(roles=None),
        lambda d: d["roles"]["editor"].update(quotas={"cpu": 1}),
        lambda d: d["roles"]["editor"].update(description=1),
        lambda d: d["roles"]["editor"].update(roles=["employee"]),
        lambda d: d["roles"]["editor"]["grants"].update(unknown="read"),
        lambda d: d["roles"]["editor"]["grants"].update({"company-knowledge": "read_write"}),
        lambda d: d["roles"]["editor"]["grants"].update({"company-knowledge": "none"}),
        lambda d: d["users"]["u1"]["grants"].update({"desktop-project": "none"}),
        lambda d: d["users"]["u1"]["grants"].update({"company-knowledge": "read_write"}),
        lambda d: d["users"]["u1"].update(resource_limits={"unknown": "none"}),
        lambda d: d["users"]["u1"].update(resource_limits={"company-knowledge": "read_write"}),
        lambda d: d["users"]["u1"].update(resource_limits={"u1.state": "none"}),
        lambda d: d["users"]["u1"].update(resource_limits={"u1.home": "read"}),
    ],
)
def test_invalid_bindings_unused_roles_raw_grants_and_required_fail_closed(change):
    value = data()
    change(value)
    with pytest.raises(PolicyError):
        load(value)


@pytest.mark.parametrize(
    "path", ["/srv/hypershell/users/u1/project", "/srv/hypershell/users/u1/project/child", "/srv/hypershell/users/u1"]
)
def test_parent_child_and_alias_mounts_cannot_bypass_personal_limits(path):
    value = data()
    value["resources"]["alias"] = {
        **value["resources"]["u1.project"],
        "host_path": path,
        "sandbox_path": "/resources/alias",
    }
    value["users"]["u1"]["resource_limits"] = {"alias": "none"}
    with pytest.raises(PolicyError, match="overlapping"):
        load(value)


def test_role_private_mounts_participate_in_cross_user_checks():
    value = data()
    user = value["users"]["u2"] = deepcopy(value["users"]["u1"])
    user.update(login_uid=1001, run_as_user="hs-u2", run_as_group="hs-u2", grants={}, required={}, roles=["private"])
    value["roles"]["private"] = {"grants": {"u1.project": "read_write"}}
    config = load(value)
    with pytest.raises(RunnerError, match="share writable"):
        validate_live_profiles(
            config,
            lambda name: SimpleNamespace(pw_uid=2001 if name == "hs-u1" else 2002),
            lambda name: SimpleNamespace(gr_gid=2001 if name == "hs-u1" else 2002),
        )


def test_v1_rejects_new_fields_and_v2_without_roles_preserves_plan():
    value = data()
    value["version"] = 1
    with pytest.raises(ConfigError):
        load(value)
    original = yaml.safe_load((Path(__file__).parents[1] / "examples/demo/hypershell.yaml").read_text())
    old = load(original)
    original["version"] = 2
    new = load(original)
    request = LaunchRequest(resources=old.users["u1"].grants)
    assert old.compile("u1", request) == new.compile("u1", request)


def test_cli_validation_and_explanation_are_read_only_and_structured(capsys):
    with patch("hypershell.config.load_document", return_value=data()):
        assert main(["config", "validate", "--config", "unused"]) == 0
        assert json.loads(capsys.readouterr().out)["valid"] is True
        assert main(["grants", "explain", "--config", "unused", "--user", "u1", "--resource", "company-knowledge"]) == 0
        output = json.loads(capsys.readouterr().out)
        assert output["resources"]["company-knowledge"]["effective"] == "read"
        assert main(["grants", "explain", "--config", "unused", "--user", "missing"]) == 2
        assert json.loads(capsys.readouterr().err)["error"]["code"] == "INVALID_REQUEST"


def test_request_cannot_assign_roles_or_direct_grants():
    for field in ("roles", "grants", "resource_limits"):
        with pytest.raises(PolicyError):
            LaunchRequest.from_dict({"resources": [], field: []})


def test_installed_entrypoint_ignores_a_hostile_current_directory():
    import ast
    import os
    import shlex
    import subprocess
    import sys
    from uuid import uuid4

    repository = Path(__file__).parents[1]
    installer = ast.parse((repository / "examples/demo/install_vm_demo.py").read_text())
    function = next(
        node for node in installer.body if isinstance(node, ast.FunctionDef) and node.name == "control_wrapper"
    )
    namespace = {"shlex": shlex}
    exec(compile(ast.Module(body=[function], type_ignores=[]), "<control-wrapper>", "exec"), namespace)
    wrapper = namespace.get("control_wrapper")
    assert callable(wrapper)
    script = wrapper(sys.executable)
    arguments = shlex.split(script.splitlines()[1])
    interpreter = arguments.index(sys.executable)
    start = interpreter + 1
    hostile = repository / ".test-tmp" / ("hostile-entry-" + uuid4().hex)
    hostile.mkdir(parents=True)
    marker = hostile / "imported.txt"
    (hostile / "hypershell.py").write_text(
        "from pathlib import Path\nPath('imported.txt').touch()\nraise SystemExit(47)\n"
    )
    environment = {**os.environ, "PYTHONPATH": str(repository)}
    result = subprocess.run(
        [
            sys.executable,
            *arguments[start:-1],
            "config",
            "validate",
            "--config",
            str(repository / "examples/demo/hypershell-roles.yaml"),
        ],
        cwd=hostile,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert not marker.exists()
    assert json.loads(result.stdout)["valid"] is True
