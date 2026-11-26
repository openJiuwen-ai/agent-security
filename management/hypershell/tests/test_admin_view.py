"""Administrator views must distinguish saved permissions from live instances."""

from copy import deepcopy
import json
from pathlib import Path
from uuid import uuid4

import pytest
import yaml

from hypershell.config import AdminConfig, load_document
from hypershell.policy import LaunchRequest
from hypershell.web.admin_view import build_instance_view, build_preview, startup_request_path

DEMO = Path(__file__).resolve().parents[1] / "examples/demo"


@pytest.fixture
def tmp_path():
    # Match the repository's desktop-sandbox workaround, without system-temp ACLs.
    path = DEMO.parents[1] / ".test-tmp" / ("admin-view-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


@pytest.fixture
def deployment(tmp_path):
    data = yaml.safe_load((DEMO / "hypershell-roles.yaml").read_text(encoding="utf-8"))
    path = tmp_path / "admin.yaml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    request = yaml.safe_load((DEMO / "request-roles-allowed.yaml").read_text(encoding="utf-8"))
    request["resources"] = [item for item in request["resources"] if item["id"] != "company-knowledge"]
    (tmp_path / "request-u1.yaml").write_text(yaml.safe_dump(request), encoding="utf-8")
    return AdminConfig.load(path), path, data


def _rows(preview):
    return {row["id"]: row for row in preview["rows"]}


def _running(config, path):
    request = LaunchRequest.from_dict(load_document(startup_request_path(path, "u1")))
    return {
        "phase": "RUNNING",
        "roles": list(config.users["u1"].roles),
        "authorization_digest": config.explain("u1")["authorization_digest"],
        "plan_digest": config.compile("u1", request).digest,
        # A backend projection digest is deliberately unrelated to drift checks.
        "policy_digest": "runtime-policy-with-added-mounts-and-environment",
    }


def test_default_preview_uses_actual_request_and_explanation(deployment):
    config, path, _ = deployment
    preview = build_preview(config, path, "u1")
    assert preview["error"] is None
    assert preview["request_name"] == "request-u1.yaml"
    assert preview["mode"] == "request"
    rows = _rows(preview)
    assert rows["company-knowledge"]["effective"] == "只读"
    assert rows["company-knowledge"]["requested"] == "未申请"
    assert rows["company-knowledge"]["mount_mode"] == "不挂载"
    assert rows["company-knowledge"]["source_text"] == "角色 employee（只读）"
    limited = rows["desktop-project"]
    assert limited["granted"] == "读写" and limited["limit"] == "只读"
    assert limited["effective"] == limited["requested"] == limited["mount_mode"] == "只读"
    assert "用户追加授权（读写）" in limited["source_text"]
    assert "company-knowledge" not in json.loads(preview["plan"])["resources"]
    assert "运行时附加挂载" in preview["scope"]


def test_all_authorized_preview_requires_explicit_mode(deployment):
    config, path, _ = deployment
    preview = build_preview(config, path, "u1", mode="authorized")
    assert preview["error"] is None
    assert _rows(preview)["company-knowledge"]["mount_mode"] == "只读"
    assert "非启动请求" in preview["request_name"]


def test_request_selection_does_not_fallback_from_existing_broken_user_file(deployment):
    config, path, _ = deployment
    (path.parent / "request.yaml").write_text("resources: []", encoding="utf-8")
    (path.parent / "request-u1.yaml").write_text("resources: broken", encoding="utf-8")
    assert startup_request_path(path, "u1").name == "request-u1.yaml"
    preview = build_preview(config, path, "u1")
    assert preview["error"]["code"] == "INVALID_REQUEST"
    assert preview["plan"] is preview["policy"] is preview["digest"] is None
    assert _rows(preview)["company-knowledge"]["effective"] == "只读"
    assert _rows(preview)["company-knowledge"]["requested"] == "无法确认"


def test_common_request_selected_only_when_no_user_file(deployment):
    config, path, _ = deployment
    startup_request_path(path, "u1").rename(path.parent / "request.yaml")
    assert startup_request_path(path, "u1").name == "request.yaml"
    assert build_preview(config, path, "u1")["error"] is None


def test_denied_request_keeps_explanation_without_partial_plan(deployment):
    config, path, _ = deployment
    request_path = startup_request_path(path, "u1")
    request = load_document(request_path)
    request["resources"].append({"id": "company-knowledge", "mode": "read_write"})
    request_path.write_text(yaml.safe_dump(request), encoding="utf-8")
    preview = build_preview(config, path, "u1")
    assert preview["error"]["code"] == "PERMISSION_EXCEEDS_BOUNDARY"
    assert preview["plan"] is preview["policy"] is None
    assert all(row["mount_mode"] == "未生成计划" for row in preview["rows"])
    assert _rows(preview)["company-knowledge"]["requested"] == "读写"
    assert _rows(preview)["company-knowledge"]["effective"] == "只读"


def test_missing_request_and_unknown_user_remain_errors(deployment):
    config, path, _ = deployment
    startup_request_path(path, "u1").unlink()
    preview = build_preview(config, path, "u1")
    assert preview["error"]["code"] == "INVALID_CONFIG" and preview["rows"]
    assert preview["plan"] is None
    unknown = build_preview(config, path, "missing")
    assert unknown["error"]["code"] == "INVALID_REQUEST" and unknown["rows"] == []
    assert build_preview(config, path, "u1", mode="invalid")["error"]["code"] == "INVALID_REQUEST"


def test_aligned_view_checks_plan_and_authorization_not_backend_policy(deployment):
    config, path, _ = deployment
    status = _running(config, path)
    view = build_instance_view(config, "u1", status, path)
    assert view["drift"]["state"] == "aligned"
    assert view["drift"]["label"] == "一致"
    assert [a["action"] for a in view["actions"]] == ["stop"]
    assert view["raw"] == status
    assert "完整隔离边界" in view["drift"]["description"]


@pytest.mark.parametrize("change", ["authorization", "request", "roles", "path"])
def test_pending_view_detects_changed_authorization_request_roles_or_mount(deployment, change):
    config, path, data = deployment
    status = _running(config, path)
    data = deepcopy(data)
    if change == "authorization":
        data["users"]["u1"]["resource_limits"]["desktop-project"] = "none"
        request = load_document(startup_request_path(path, "u1"))
        request["resources"] = [item for item in request["resources"] if item["id"] != "desktop-project"]
        startup_request_path(path, "u1").write_text(yaml.safe_dump(request), encoding="utf-8")
    elif change == "request":
        request = load_document(startup_request_path(path, "u1"))
        request["resources"].append({"id": "company-knowledge", "mode": "read"})
        startup_request_path(path, "u1").write_text(yaml.safe_dump(request), encoding="utf-8")
    elif change == "roles":
        data["users"]["u1"]["roles"].remove("project_viewer")
    else:
        data["resources"]["u1.project"]["host_path"] += "-new"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    changed = AdminConfig.load(path)
    assert build_instance_view(changed, "u1", status, path)["drift"]["state"] == "pending"


@pytest.mark.parametrize("missing", ["authorization_digest", "plan_digest", "request"])
def test_missing_evidence_cannot_claim_configuration_applied(deployment, missing):
    config, path, _ = deployment
    status = _running(config, path)
    if missing == "request":
        startup_request_path(path, "u1").unlink()
    else:
        status.pop(missing)
    view = build_instance_view(config, "u1", status, path)
    assert view["drift"]["state"] == "unknown"
    assert view["drift"]["label"] == "无法确认"


def test_revoked_permission_with_invalid_old_request_still_reports_pending(deployment):
    config, path, data = deployment
    status = _running(config, path)
    data["users"]["u1"]["resource_limits"]["desktop-project"] = "none"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    changed = AdminConfig.load(path)
    view = build_instance_view(changed, "u1", status, path)
    assert view["drift"]["state"] == "pending"
    assert view["drift"]["current_plan_digest"] is None
    assert "先修正请求" in view["drift"]["description"]
    # A lost or broken instance remains an operational exception before drift.
    for phase in ("LOST", "ERROR"):
        failed = build_instance_view(changed, "u1", {**status, "phase": phase}, path)
        assert failed["drift"]["state"] == "unknown"
        assert failed["drift"]["label"] == "异常待处理"


def test_known_role_change_remains_pending_when_request_is_missing(deployment):
    config, path, _ = deployment
    status = _running(config, path)
    status["roles"] = ["employee"]
    startup_request_path(path, "u1").unlink()
    assert build_instance_view(config, "u1", status, path)["drift"]["state"] == "pending"


def test_invalid_request_without_known_authorization_change_is_unknown(deployment):
    config, path, _ = deployment
    status = _running(config, path)
    startup_request_path(path, "u1").write_text("resources: broken", encoding="utf-8")
    assert build_instance_view(config, "u1", status, path)["drift"]["state"] == "unknown"
    status.pop("authorization_digest")
    assert build_instance_view(config, "u1", status, path)["drift"]["state"] == "unknown"


@pytest.mark.parametrize(
    "phase,actions,drift",
    [
        ("STOPPED", ["start"], "stopped"),
        ("LOST", ["recover"], "unknown"),
        ("ERROR", ["stop"], "unknown"),
        ("ERROR_CLEANUP_REQUIRED", ["stop"], "unknown"),
        ("STARTING", [], "unknown"),
        ("UNKNOWN", [], "unknown"),
    ],
)
def test_actions_follow_observed_state_without_promising_recovery(deployment, phase, actions, drift):
    config, path, _ = deployment
    status = {**_running(config, path), "phase": phase}
    view = build_instance_view(config, "u1", status, path)
    assert [a["action"] for a in view["actions"]] == actions
    assert view["drift"]["state"] == drift
    if phase == "LOST":
        action = view["actions"][0]
        assert action["label"] == "检查并恢复"
        assert all(word in action["confirm"] for word in ("跨开机", "无相关残留", "保持原状态"))
        assert view["drift"]["label"] == "异常待处理"
    elif phase in {"ERROR", "ERROR_CLEANUP_REQUIRED"}:
        action = view["actions"][0]
        assert action["label"] == "尝试停止"
        assert all(word in action["confirm"] for word in ("先查看诊断", "引擎身份", "清理结果", "不会自动恢复或启动"))
