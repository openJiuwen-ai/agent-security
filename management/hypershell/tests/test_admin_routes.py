"""Exercise administrator HTTP flows with real policy files and a fake runner.

No test starts a sandbox, invokes a model or needs root.  Authentication is
stubbed here; password verification has its own tests in test_web.py.
"""

from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import re
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest
import yaml

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient  # noqa: E402

from hypershell.config import AdminConfig, load_document  # noqa: E402
from hypershell.policy import LaunchRequest  # noqa: E402
import hypershell.web.app as web_app  # noqa: E402

BASE = Path(__file__).resolve().parents[1]


@pytest.fixture
def tmp_path():
    # mkdir's default mode preserves the desktop sandbox's inherited ACLs.
    # pytest's system-temp fixture creates private 0700 directories instead.
    path = BASE / ".test-tmp" / ("admin-routes-" + uuid4().hex)
    path.mkdir(parents=True)
    return path


def _csrf(response) -> str:
    match = re.search(r'name="csrf" value="([^"]+)"', response.text)
    assert match, "the rendered form must include a CSRF token"
    return match.group(1)


_LOGIN_VALUE = uuid4().hex


def _login(client, username="admin"):
    response = client.get("/login")
    response = client.post(
        "/login",
        data={
            "username": username,
            "password": _LOGIN_VALUE,
            "csrf": _csrf(response),
        },
    )
    assert response.status_code == 200
    return response


def _row_for_user(response, user_id: str) -> str:
    # Restrict assertions to one user's row: the help text can mention rebuilds
    # even when this particular instance is already up to date.
    for row in re.findall(r"<tr\b[^>]*>.*?</tr>", response.text, re.S):
        cells = re.findall(r"<td\b[^>]*>(.*?)</td>", row, re.S)
        if cells and re.search(rf"<strong>\s*{re.escape(user_id)}\s*</strong>", cells[0]):
            return row
    raise AssertionError(f"dashboard did not render a row for {user_id}")


@pytest.fixture
def admin_site(tmp_path, monkeypatch):
    data = {
        "version": 2,
        "allowed_roots": ["/srv/hypershell"],
        "resources": {
            "u1.project": {
                "type": "directory",
                "host_path": "/srv/hypershell/users/u1/project",
                "sandbox_path": "/workspace",
                "max_mode": "read_write",
            },
            "u2.project": {
                "type": "directory",
                "host_path": "/srv/hypershell/users/u2/project",
                "sandbox_path": "/workspace",
                "max_mode": "read_write",
            },
            "company-knowledge": {
                "type": "directory",
                "host_path": "/srv/hypershell/resources/knowledge",
                "sandbox_path": "/resources/knowledge",
                "max_mode": "read",
            },
        },
        "roles": {"employee": {"grants": {"company-knowledge": "read"}}},
        "users": {
            user_id: {
                "login_uid": 1000 + index,
                "run_as_user": f"hs-{user_id}",
                "run_as_group": f"hs-{user_id}",
                "roles": ["employee"],
                "grants": {f"{user_id}.project": "read_write"},
                "required": {f"{user_id}.project": "read_write"},
                "quotas": {"cpu": 1},
            }
            for index, user_id in enumerate(("u1", "u2"))
        },
    }
    config_path = tmp_path / "admin.yaml"
    config_path.write_text(yaml.safe_dump(data), encoding="utf-8")
    for user_id in data["users"]:
        (tmp_path / f"request-{user_id}.yaml").write_text(
            yaml.safe_dump(
                {
                    "resources": [{"id": f"{user_id}.project", "mode": "read_write"}],
                }
            ),
            encoding="utf-8",
        )

    config = AdminConfig.load(config_path)
    states = {}
    for user_id in config.users:
        request = LaunchRequest.from_dict(load_document(tmp_path / f"request-{user_id}.yaml"))
        states[user_id] = {
            "ok": True,
            "phase": "RUNNING",
            "user_id": user_id,
            "authorization_digest": config.explain(user_id)["authorization_digest"],
            "plan_digest": config.compile(user_id, request).digest,
        }
    calls = []
    outcomes = {}
    session_records = {}

    class FakeRunner:
        def __init__(self, config, runtime_path, user_id):
            assert user_id in config.users
            self.user_id = user_id

        def status(self):
            calls.append(("status", self.user_id))
            return deepcopy(states[self.user_id])

        def list_sessions(self):
            calls.append(("list_sessions", self.user_id))
            return deepcopy(session_records.get(self.user_id, []))

        def terminate_session(self, session_id):
            calls.append(("terminate_session", self.user_id, session_id))
            session_records[self.user_id] = [
                item for item in session_records.get(self.user_id, []) if item.get("id") != session_id
            ]
            return {"session_id": session_id, "terminated": True}

        def _action(self, action, request=None):
            calls.append((action, self.user_id, request))
            outcome = outcomes.get(action, {"ok": True, "phase": "STOPPED"})
            if isinstance(outcome, Exception):
                raise outcome
            return deepcopy(outcome)

        def start(self, request):
            return self._action("start", request)

        def stop(self):
            return self._action("stop")

        def recover(self):
            return self._action("recover")

    principals = {
        "admin": {"username": "admin", "role": "admin", "user_id": None, "display": "Admin"},
        "u1": {"username": "u1", "role": "user", "user_id": "u1", "display": "User One"},
    }
    monkeypatch.setattr(web_app, "load_accounts", lambda _: {})
    monkeypatch.setattr(
        web_app,
        "authenticate",
        lambda _, username, password: principals.get(username) if password == _LOGIN_VALUE else None,
    )
    monkeypatch.setattr("hypershell.runner.managed.ManagedRunner", FakeRunner)
    app = web_app.create_app(
        config_path=str(config_path),
        runtime_path=str(tmp_path / "runtime.yaml"),
        accounts_path=str(tmp_path / "accounts.yaml"),
        backup_dir=str(tmp_path / "backups"),
        audit_path=str(tmp_path / "audit.jsonl"),
        secret_key=uuid4().hex,
    )
    with TestClient(app) as client:
        yield SimpleNamespace(
            client=client,
            path=tmp_path,
            config_path=config_path,
            data=data,
            states=states,
            calls=calls,
            outcomes=outcomes,
            sessions=session_records,
        )


def _mutations(site):
    return [call for call in site.calls if call[0] in {"start", "stop", "recover"}]


@pytest.mark.parametrize("invalid_kind", ["schema", "policy"])
def test_valid_draft_can_repair_an_invalid_current_configuration(admin_site, invalid_kind):
    site = admin_site
    _login(site.client)
    valid_text = site.config_path.read_text(encoding="utf-8")
    if invalid_kind == "schema":
        invalid_text = "version: [broken]\n"
    else:
        invalid = deepcopy(site.data)
        invalid["users"]["u1"]["required"]["company-knowledge"] = "read_write"
        invalid_text = yaml.safe_dump(invalid)
    site.config_path.write_text(invalid_text, encoding="utf-8")
    csrf = _csrf(site.client.get("/admin/config"))
    payload = {"text": valid_text, "csrf": csrf}
    validated = site.client.post("/admin/config/validate", data=payload)
    assert validated.status_code == 200
    assert validated.context["validation"]["ok"]
    assert validated.context["comparison_warning"]
    assert validated.context["affected_users"] == ["u1", "u2"]
    saved = site.client.post("/admin/config/save", data=payload)
    assert saved.status_code == 200
    assert saved.context["comparison_warning"]
    assert set(AdminConfig.load(site.config_path).users) == {"u1", "u2"}
    assert not _mutations(site)


@pytest.mark.parametrize("action", ["validate", "save"])
def test_policy_invalid_draft_returns_structured_error_without_saving(admin_site, action):
    site = admin_site
    _login(site.client)
    original = site.config_path.read_text(encoding="utf-8")
    invalid = deepcopy(site.data)
    invalid["users"]["u1"]["required"]["company-knowledge"] = "read_write"
    response = site.client.post(
        f"/admin/config/{action}",
        data={
            "text": yaml.safe_dump(invalid),
            "csrf": _csrf(site.client.get("/admin/config")),
        },
    )
    assert response.status_code == 200
    assert response.context["validation"]["ok"] is False
    assert response.context["validation"]["error"]["code"] == "INCOMPATIBLE_PROFILE"
    assert site.config_path.read_text(encoding="utf-8") == original
    assert not (site.path / "audit.jsonl").exists()
    assert not _mutations(site)


def test_preview_uses_start_request_and_authorized_mode_is_explicit(admin_site):
    site = admin_site
    _login(site.client)
    response = site.client.get("/admin/preview?user=u1")
    assert response.status_code == 200
    plan = json.loads(response.context["plan"])
    assert set(plan["resources"]) == {"u1.project"}
    assert {mount["resource_id"] for mount in plan["mounts"]} == {"u1.project"}

    authorized = site.client.get("/admin/preview?user=u1&mode=authorized")
    assert set(json.loads(authorized.context["plan"])["resources"]) == {
        "u1.project",
        "company-knowledge",
    }
    assert not _mutations(site)


def test_preview_falls_back_to_common_request_when_user_request_is_absent(admin_site):
    site = admin_site
    _login(site.client)
    (site.path / "request-u1.yaml").rename(site.path / "request.yaml")
    response = site.client.get("/admin/preview?user=u1")
    assert response.context["error"] is None
    assert set(json.loads(response.context["plan"])["resources"]) == {"u1.project"}


def test_preview_does_not_replace_a_missing_request_with_all_grants(admin_site):
    site = admin_site
    _login(site.client)
    (site.path / "request-u1.yaml").unlink()
    response = site.client.get("/admin/preview?user=u1")
    assert response.status_code == 200
    assert response.context["error"]
    assert response.context["plan"] is None
    assert "request" in response.text
    assert not _mutations(site)


def test_invalid_user_request_is_not_silently_replaced_by_common_request(admin_site):
    site = admin_site
    _login(site.client)
    (site.path / "request.yaml").write_text(
        (site.path / "request-u1.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (site.path / "request-u1.yaml").write_text("resources: [broken]\n", encoding="utf-8")
    response = site.client.get("/admin/preview?user=u1")
    assert response.context["error"]
    assert response.context["plan"] is None


def test_running_instance_with_changed_authorization_is_marked_for_rebuild(admin_site):
    site = admin_site
    _login(site.client)
    site.states["u1"]["authorization_digest"] = "previous-authorization"
    response = site.client.get("/admin")
    u1_row = _row_for_user(response, "u1")
    assert "RUNNING" in u1_row
    assert "运行中" in u1_row
    assert "待重建" in u1_row
    assert "待重建" not in _row_for_user(response, "u2")
    assert response.context["instance_views"]["u1"]["drift"]["state"] == "pending"
    assert response.context["instance_views"]["u2"]["drift"]["state"] == "aligned"
    assert response.context["counts"]["pending"] == 1


def test_lost_instance_explains_recovery_before_restart(admin_site):
    site = admin_site
    site.states["u2"].update(ok=False, phase="LOST", reason="ENGINE_IDENTITY_MISSING", recovery_required=True)
    response = _login(site.client)
    u2_row = _row_for_user(response, "u2")
    assert "LOST" in u2_row
    assert "恢复" in u2_row
    assert "/admin/instances/u2/recover" in u2_row
    assert not _mutations(site)


@pytest.mark.parametrize("path", ["/admin", "/admin/config", "/admin/users", "/admin/preview"])
def test_normal_user_cannot_read_administrator_pages(admin_site, path):
    site = admin_site
    _login(site.client, "u1")
    site.calls.clear()
    response = site.client.get(path, follow_redirects=False)
    assert response.status_code in {303, 401, 403}
    assert "admin.yaml" not in response.text
    assert not site.calls


def test_normal_user_cannot_save_configuration_even_with_valid_csrf(admin_site):
    site = admin_site
    response = _login(site.client, "u1")
    original = site.config_path.read_text(encoding="utf-8")
    changed = deepcopy(site.data)
    changed["users"]["u1"]["quotas"]["cpu"] = 0.5
    response = site.client.post(
        "/admin/config/save",
        data={
            "text": yaml.safe_dump(changed),
            "csrf": _csrf(response),
        },
        follow_redirects=False,
    )
    assert response.status_code in {303, 401, 403}
    assert site.config_path.read_text(encoding="utf-8") == original
    assert not (site.path / "audit.jsonl").exists()
    assert not _mutations(site)


def test_csrf_failure_does_not_save_or_operate_on_instances(admin_site):
    site = admin_site
    _login(site.client)
    original = site.config_path.read_text(encoding="utf-8")
    changed = deepcopy(site.data)
    changed["users"]["u1"]["quotas"]["cpu"] = 0.5
    response = site.client.post(
        "/admin/config/save",
        data={
            "text": yaml.safe_dump(changed),
            "csrf": "invalid-token",
        },
    )
    assert response.status_code in {200, 403}
    assert "CSRF" in response.text or "会话已过期" in response.text
    assert site.config_path.read_text(encoding="utf-8") == original
    assert not (site.path / "audit.jsonl").exists()
    assert not _mutations(site)


def test_validate_and_save_report_changes_without_implicit_stop_or_start(admin_site):
    site = admin_site
    _login(site.client)
    original = site.config_path.read_text(encoding="utf-8")
    changed = deepcopy(site.data)
    changed["users"]["u1"]["quotas"]["cpu"] = 0.5
    config_page = site.client.get("/admin/config")
    form = {"text": yaml.safe_dump(changed), "csrf": _csrf(config_page)}
    validated = site.client.post("/admin/config/validate", data=form)
    assert validated.context["validation"]["ok"] is True
    assert validated.context["affected_users"] == ["u1"]
    assert "可能受影响的用户" in validated.text
    assert site.config_path.read_text(encoding="utf-8") == original
    assert not (site.path / "audit.jsonl").exists()

    saved = site.client.post("/admin/config/save", data=form)
    assert saved.context["validation"]["ok"] is True
    assert yaml.safe_load(site.config_path.read_text(encoding="utf-8")) == changed
    assert saved.context["affected_users"] == ["u1"]
    assert {note["user"] for note in saved.context["application_notes"]} == {"u1"}
    assert "重建" in saved.text
    assert list((site.path / "backups").glob("admin-*.yaml"))
    assert "CONFIG_SAVED" in (site.path / "audit.jsonl").read_text(encoding="utf-8")
    assert not _mutations(site)


@pytest.mark.parametrize(
    "outcome",
    [
        RuntimeError("instance operation blocked"),
        {"ok": False, "phase": "ERROR", "reason": "instance operation blocked"},
    ],
)
def test_failed_instance_operation_is_rendered_as_error_message(admin_site, outcome):
    site = admin_site
    dashboard = _login(site.client)
    site.outcomes["stop"] = outcome
    response = site.client.post("/admin/instances/u1/stop", data={"csrf": _csrf(dashboard)})
    assert response.status_code == 200
    assert response.context["message_level"] == "error"
    assert "instance operation blocked" in response.text


@pytest.mark.parametrize("phase", ["ERROR", "ERROR_CLEANUP_REQUIRED"])
def test_error_instance_can_attempt_stop_without_implicit_restart(admin_site, phase):
    site = admin_site
    site.states["u1"]["phase"] = phase
    dashboard = _login(site.client)
    row = _row_for_user(dashboard, "u1")
    assert "/admin/instances/u1/stop" in row
    assert "尝试停止" in row and "先查看诊断" in row
    assert "data-confirm=" in row
    assert "/admin/instances/u1/start" not in row
    assert "/admin/instances/u1/recover" not in row
    site.outcomes["stop"] = RuntimeError("engine lost; cannot confirm sandbox cleanup")
    response = site.client.post("/admin/instances/u1/stop", data={"csrf": _csrf(dashboard)})
    assert response.status_code == 200
    assert response.context["message_level"] == "error"
    assert "cannot confirm sandbox cleanup" in response.text
    assert [(call[0], call[1]) for call in _mutations(site)] == [("stop", "u1")]


def test_role_save_explains_rebuild_without_implicitly_restarting(admin_site):
    site = admin_site
    _login(site.client)
    users_page = site.client.get("/admin/users")
    response = site.client.post(
        "/admin/users/roles",
        data={
            "user": "u1",
            "csrf": _csrf(users_page),
        },
    )
    assert response.status_code == 200
    assert yaml.safe_load(site.config_path.read_text(encoding="utf-8"))["users"]["u1"]["roles"] == []
    assert "不会热更新" in response.context["message"]
    assert "停止并重建" in response.context["message"]
    assert response.context["message_level"] == "warning"
    assert not _mutations(site)


def test_start_and_default_preview_use_the_same_user_request(admin_site):
    site = admin_site
    _login(site.client)
    # A broader shared request must not replace the user-specific request.
    (site.path / "request.yaml").write_text(
        yaml.safe_dump(
            {
                "resources": [{"id": "u1.project", "mode": "read_write"}, {"id": "company-knowledge", "mode": "read"}],
            }
        ),
        encoding="utf-8",
    )
    preview = site.client.get("/admin/preview?user=u1")
    site.outcomes["start"] = {"ok": True, "phase": "RUNNING"}
    site.client.post("/admin/instances/u1/start", data={"csrf": _csrf(preview)})
    mutations = _mutations(site)
    assert len(mutations) == 1
    action, user_id, request = mutations[0]
    assert (action, user_id) == ("start", "u1")
    assert set(request.resources) == set(json.loads(preview.context["plan"])["resources"]) == {"u1.project"}


def test_dashboard_lists_active_sessions_and_can_terminate(admin_site):
    site = admin_site
    session_id = "a" * 32
    site.sessions["u1"] = [
        {
            "id": session_id,
            "kind": "web",
            "pid": 4321,
            "user_id": "u1",
            "started": time.time() - 125,
            "last_seen": time.time(),
        }
    ]
    dashboard = _login(site.client)
    assert "活跃会话" in dashboard.text
    assert f"/admin/sessions/u1/{session_id}/terminate" in dashboard.text
    assert "当前没有活跃的 TUI/Web 会话" not in dashboard.text

    response = site.client.post(f"/admin/sessions/u1/{session_id}/terminate", data={"csrf": _csrf(dashboard)})
    assert response.status_code == 200
    assert ("terminate_session", "u1", session_id) in site.calls
    assert "已终止" in response.text


def test_session_terminate_requires_csrf(admin_site):
    site = admin_site
    session_id = "b" * 32
    site.sessions["u1"] = [
        {
            "id": session_id,
            "kind": "tui",
            "pid": 99,
            "user_id": "u1",
            "started": time.time(),
            "last_seen": time.time(),
        }
    ]
    _login(site.client)
    response = site.client.post(f"/admin/sessions/u1/{session_id}/terminate", data={"csrf": "invalid"})
    assert response.status_code in {200, 403}
    assert not [c for c in site.calls if c[0] == "terminate_session"]
    assert "会话已过期" in response.text or "CSRF" in response.text
