"""Exercise configuration boundaries and the actual demo command interface."""

import json
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from hypershell.cli import main
from hypershell.config import AdminConfig, ConfigError, load_document
from hypershell.policy import InvalidRequest, LaunchRequest, PolicyError

DEMO = Path(__file__).resolve().parents[1] / "examples/demo"


@pytest.fixture
def tmp_path():
    # The desktop sandbox cannot traverse pytest's private system-temp ACLs.
    path = DEMO.parents[1] / ".test-tmp" / ("config-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


def admin_data():
    return yaml.safe_load((DEMO / "hypershell.yaml").read_text(encoding="utf-8"))


def write_config(tmp_path, data):
    path = tmp_path / "admin.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_allowed_request_projects_identity_mounts_and_minimum_quotas():
    config = AdminConfig.load(DEMO / "hypershell.yaml")
    request = LaunchRequest.from_dict(load_document(DEMO / "request-allowed.yaml"))
    preview = config.preview("u1", request, simulated=True)
    assert preview["deployed"] is False
    assert preview["identity"]["simulated"] is True
    policy = preview["jiuwenbox_policy"]
    assert policy["process"] == {"run_as_user": "hs-u1", "run_as_group": "hs-u1"}
    mounts = {m["sandbox_path"]: m for m in policy["filesystem_policy"]["bind_mounts"]}
    assert mounts["/workspace"]["mode"] == "rw"
    assert mounts["/resources/knowledge"]["mode"] == "ro"
    assert "/resources/desktop-project" not in mounts
    assert policy["cgroup"] == {"memory_max": 2147483648, "cpu_max": (100000, 100000), "pids_max": 128}
    assert policy["landlock"]["compatibility"] == "hard_requirement"


@pytest.mark.parametrize("request_file", ["request-denied-write.yaml", "request-denied-desktop.yaml"])
def test_cli_rejects_entire_overprivileged_request(request_file, capsys):
    code = main(
        ["plan", "--config", str(DEMO / "hypershell.yaml"), "--request", str(DEMO / request_file), "--demo-user", "u1"]
    )
    result = capsys.readouterr()
    assert code == 2 and result.out == ""
    assert json.loads(result.err)["error"]["code"] == "PERMISSION_EXCEEDS_BOUNDARY"


def test_duplicate_yaml_keys_rejected(tmp_path):
    path = tmp_path / "duplicate.yaml"
    path.write_text("version: 1\nversion: 2\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="duplicate"):
        AdminConfig.load(path)


@pytest.mark.parametrize(
    "change",
    [
        lambda d: d.update(version=True),
        lambda d: d.update(version=3),
        lambda d: d.update(mounts=[]),
        lambda d: d.update(allowed_roots=["/"]),
        lambda d: d["resources"]["u1.project"].update(host_path="/etc"),
        lambda d: d["resources"]["u1.project"].update(host_path="/srv/hypershell/users/../secret"),
        lambda d: d["users"]["u1"].update(run_as_user="root"),
        lambda d: d["users"]["u1"].update(login_uid=True),
        lambda d: d["users"]["u1"]["grants"].update(unknown="read"),
        lambda d: d["users"]["u1"]["grants"].update({"company-knowledge": "read_write"}),
        lambda d: d["users"]["u1"]["quotas"].update(pids=1.5),
        lambda d: d["users"]["u1"]["quotas"].update(cpu=float("inf")),
        lambda d: d["users"]["u1"]["quotas"].update(cpu=1e308),
        lambda d: d["users"]["u1"]["quotas"].update(memory_bytes=2**60),
        lambda d: d["users"]["u1"]["quotas"].update(disk_bytes=100),
    ],
)
def test_invalid_admin_config_fails_closed(tmp_path, change):
    data = admin_data()
    change(data)
    with pytest.raises(PolicyError):
        AdminConfig.load(write_config(tmp_path, data))


def test_duplicate_login_uid_has_no_ambiguous_identity(tmp_path):
    data = admin_data()
    data["users"]["other"] = dict(data["users"]["u1"])
    with pytest.raises(ConfigError, match="unique"):
        AdminConfig.load(write_config(tmp_path, data))


def test_real_uid_mapping_and_unregistered_caller():
    config = AdminConfig.load(DEMO / "hypershell.yaml")
    assert config.user_for_uid(1000) == "u1"
    with pytest.raises(InvalidRequest):
        config.user_for_uid(1001)


def test_cli_maps_os_uid_without_user_selected_identity(monkeypatch, capsys):
    monkeypatch.setattr("hypershell.cli.os.getuid", lambda: 1000, raising=False)
    assert (
        main(["plan", "--config", str(DEMO / "hypershell.yaml"), "--request", str(DEMO / "request-allowed.yaml")]) == 0
    )
    result = json.loads(capsys.readouterr().out)
    assert result["identity"]["source"] == "os_real_uid"
    assert result["deployed"] is False


def test_request_cannot_override_execution_identity(tmp_path, capsys):
    path = write_config(tmp_path, {"resources": [], "run_as_user": "root"})
    assert main(["plan", "--config", str(DEMO / "hypershell.yaml"), "--request", str(path), "--demo-user", "u1"]) == 2
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "INVALID_REQUEST"


def test_cli_missing_config_is_structured_error(tmp_path, capsys):
    assert (
        main(
            [
                "plan",
                "--config",
                str(tmp_path / "missing"),
                "--request",
                str(DEMO / "request-allowed.yaml"),
                "--demo-user",
                "u1",
            ]
        )
        == 2
    )
    assert json.loads(capsys.readouterr().err)["error"]["code"] == "INVALID_CONFIG"
