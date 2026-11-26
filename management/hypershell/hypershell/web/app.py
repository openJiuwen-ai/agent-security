"""Server-rendered demo web UI: administrator configuration + normal-user entry.

Security posture for the demo:
* passwords are only ever stored as Argon2id hashes (``auth.py``);
* signed-cookie session, CSRF token on every POST;
* admin routes require role ``admin``; user routes require role ``user`` and use
  the ``user_id`` bound to the session -- never a value supplied by the client;
* config writes are validated with ``AdminConfig.load``, backed up and audited
  (``ConfigStore``), and take effect on the next instance start (no hot reload).

This runs as an administrator process because it drives ``ManagedRunner``. A
production deployment must split the privileged controller from the web tier.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import time
from urllib.parse import urlencode

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

from ..config import AdminConfig, load_document
from ..policy import LaunchRequest, PolicyError
from .admin_view import build_instance_view, build_preview, startup_request_path
from .auth import authenticate, check_csrf, load_accounts, new_csrf_token
from .config_store import ConfigStore

TEMPLATES = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


def _summarize(config: AdminConfig) -> dict:
    return {
        "version": config.version,
        "allowed_roots": list(config.allowed_roots),
        "resources": [
            {
                "id": r.id,
                "kind": r.kind,
                "host_path": r.backend_ref,
                "sandbox_path": r.sandbox_target,
                "max_mode": r.max_mode.name.lower(),
            }
            for r in config.catalog.values()
        ],
        "users": [
            {
                "id": name,
                "login_uid": u.login_uid,
                "run_as_user": u.run_as_user,
                "run_as_group": u.run_as_group,
                "roles": list(u.roles),
                "grants": {rid: mode.name.lower() for rid, mode in sorted(u.grants.items())},
                "direct_grants": {rid: mode.name.lower() for rid, mode in sorted(u.direct_grants.items())},
                "resource_limits": {rid: mode.name.lower() for rid, mode in sorted(u.resource_limits.items())},
                "required": {rid: mode.name.lower() for rid, mode in sorted(u.required.items())},
                "quotas": u.quotas,
            }
            for name, u in config.users.items()
        ],
        "roles": [
            {
                "id": name,
                "description": role.description,
                "grants": {rid: mode.name.lower() for rid, mode in sorted(role.grants.items())},
            }
            for name, role in config.roles.items()
        ],
    }


def create_app(
    *,
    config_path: str,
    runtime_path: str,
    accounts_path: str,
    backup_dir: str,
    audit_path: str,
    secret_key: str,
    relay_config: dict | None = None,
) -> FastAPI:
    app = FastAPI(title="HyperShell demo web")
    app.add_middleware(SessionMiddleware, secret_key=secret_key, same_site="lax", https_only=False)
    store = ConfigStore(config_path, backup_dir, audit_path)
    accounts = load_accounts(accounts_path)

    def principal(request: Request) -> dict | None:
        return request.session.get("user")

    def login_redirect() -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    def render(request: Request, name: str, **extra) -> HTMLResponse:
        level = request.query_params.get("level", "success")
        base = {
            "user": request.session.get("user"),
            "csrf": request.session.get("csrf", ""),
            "message_level": level if level in {"success", "warning", "error"} else "success",
        }
        base.update(extra)
        return TEMPLATES.TemplateResponse(request=request, name=name, context=base)

    def flash(request: Request) -> str | None:
        return request.query_params.get("msg")

    def admin_redirect(message: str, *, path: str = "/admin", level: str = "success"):
        return RedirectResponse(path + "?" + urlencode({"msg": message, "level": level}), status_code=303)

    def runner_for(user_id: str):
        from ..runner.managed import ManagedRunner

        config = AdminConfig.load(config_path)
        return ManagedRunner(config, runtime_path, user_id)

    def status_for(user_id: str) -> dict:
        try:
            return runner_for(user_id).status()
        except Exception as exc:  # noqa: BLE001 - surfaced to the admin UI
            return {"phase": "ERROR", "error": str(exc)}

    def sessions_for(user_id: str) -> list[dict]:
        """Return live web/TUI sessions, annotated for display.

        A broken runner must not blank the whole dashboard, so failures here
        degrade to an empty list rather than raising.
        """
        try:
            raw = runner_for(user_id).list_sessions()
        except Exception:  # noqa: BLE001
            return []
        now = time.time()
        rows = []
        for session in raw:
            started = session.get("started")
            started_text = "未知"
            duration_text = "未知"
            if isinstance(started, (int, float)):
                started_text = datetime.fromtimestamp(started, tz=timezone(timedelta(hours=8))).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                age = max(0, int(now - started))
                if age >= 3600:
                    duration_text = f"{age // 3600}h{(age % 3600) // 60:02d}m"
                elif age >= 60:
                    duration_text = f"{age // 60}m{age % 60:02d}s"
                else:
                    duration_text = f"{age}s"
            rows.append({**session, "started_text": started_text, "duration_text": duration_text})
        return rows

    # P3: the control plane owns the per-user web relay lifecycle. When a
    # relay_config is supplied, a supervisor starts one relay per RUNNING user
    # on a deterministic port, stops it otherwise, and reconciles periodically.
    relay_supervisor = None
    if relay_config:
        from .relays import RelaySupervisor, spawn_relay_process

        def _relay_users():
            try:
                return list(AdminConfig.load(config_path).users)
            except Exception:  # noqa: BLE001
                return []

        def _relay_port(user_id):
            users = list(AdminConfig.load(config_path).users)
            return int(relay_config["port_base"]) + users.index(user_id)

        def _relay_spawn(user_id, port):
            return spawn_relay_process(
                user_id,
                port,
                python=relay_config.get("python") or sys.executable,
                host=relay_config.get("host", "0.0.0.0"),
                frontend_port=int(relay_config.get("frontend_port", 5173)),
                gate_url=relay_config.get("gate_url"),
                login_url=relay_config.get("login_url"),
                log_dir=relay_config.get("log_dir", "/tmp"),
            )

        relay_supervisor = RelaySupervisor(
            users=_relay_users, port_for=_relay_port, status=status_for, spawn=_relay_spawn
        )

        @app.on_event("startup")
        def _start_relay_supervisor():
            relay_supervisor.start()

        @app.on_event("shutdown")
        def _stop_relay_supervisor():
            relay_supervisor.shutdown()

    def change_fingerprint(config: AdminConfig, user_id: str) -> dict:
        profile = config.users[user_id]
        try:
            req = LaunchRequest.from_dict(load_document(startup_request_path(config_path, user_id)))
            requested = config.compile(user_id, req).digest
        except (PolicyError, OSError, ValueError) as exc:
            requested = str(exc)
        return {
            "authorization": config.explain(user_id)["authorization_digest"],
            "roles": sorted(profile.roles),
            "requested_plan": requested,
            "authorized_plan": config.compile(user_id, LaunchRequest(resources=profile.grants)).digest,
            "identity": (profile.login_uid, profile.run_as_user, profile.run_as_group),
            "allowed_roots": sorted(config.allowed_roots),
        }

    def changed_users(text: str) -> tuple[list[str], str | None]:
        after = store.load_config(text)
        try:
            before = AdminConfig.load(config_path)
        except (PolicyError, OSError, ValueError):
            return sorted(after.users), (
                "原配置无法解析，影响范围仅按新配置估算；" "请另外核查可能从配置中移除的旧工作区。"
            )
        before_users, after_users = before.users.keys(), after.users.keys()
        affected = before_users ^ after_users
        for uid in sorted(before_users & after_users):
            if change_fingerprint(before, uid) != change_fingerprint(after, uid):
                affected.add(uid)
        return sorted(affected), None

    def application_notes(affected: list[str]) -> list[dict]:
        config = AdminConfig.load(config_path)
        notes = []
        for uid in affected:
            if uid not in config.users:
                notes.append(
                    {
                        "user": uid,
                        "label": "已从配置移除",
                        "description": "删除配置不会停止旧实例。请使用备份配置核查并处理原工作区。",
                    }
                )
                continue
            view = build_instance_view(config, uid, status_for(uid), config_path)
            notes.append({"user": uid, "label": view["drift"]["label"], "description": view["drift"]["description"]})
        return notes

    @app.get("/healthz")
    def healthz() -> JSONResponse:
        return JSONResponse({"ok": True})

    @app.get("/_gate/whoami")
    def gate_whoami(request: Request) -> JSONResponse:
        """Internal endpoint used by the web relay to authorize a browser session.

        The relay forwards the browser Cookie header here; a 200 with a matching
        ``user`` principal means the first request may tunnel to the sandbox.
        Loopback-only deployment keeps this off the public surface.
        """
        who = principal(request)
        if not who:
            return JSONResponse({"ok": False}, status_code=401)
        return JSONResponse({"ok": True, "user": who})

    # ----- authentication -----
    @app.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> HTMLResponse:
        if principal(request):
            return RedirectResponse("/", status_code=303)
        request.session["csrf"] = new_csrf_token()
        return render(request, "login.html", error=None)

    @app.post("/login")
    def do_login(request: Request, username: str = Form(...), password: str = Form(...), csrf: str = Form("")):
        if not check_csrf(request.session.get("csrf"), csrf):
            return render(request, "login.html", error="会话已过期，请重试")
        who = authenticate(accounts, username.strip(), password)
        if who is None:
            return render(request, "login.html", error="用户名或密码错误")
        request.session.clear()
        request.session["user"] = who
        request.session["csrf"] = new_csrf_token()
        return RedirectResponse("/", status_code=303)

    @app.post("/logout")
    def logout(request: Request, csrf: str = Form("")):
        if check_csrf(request.session.get("csrf"), csrf):
            request.session.clear()
        return RedirectResponse("/login", status_code=303)

    @app.get("/")
    def home(request: Request):
        who = principal(request)
        if not who:
            return login_redirect()
        return RedirectResponse("/admin" if who["role"] == "admin" else "/me", status_code=303)

    # ----- administrator: dashboard / instances -----
    @app.get("/admin", response_class=HTMLResponse)
    def admin_dashboard(request: Request):
        who = principal(request)
        if not who:
            return login_redirect()
        if who["role"] != "admin":
            return RedirectResponse("/me", status_code=303)
        config = AdminConfig.load(config_path)
        summary = _summarize(config)
        statuses = {uid: status_for(uid) for uid in config.users}
        views = {uid: build_instance_view(config, uid, statuses[uid], config_path) for uid in config.users}
        session_rows = [{"user_id": uid, **row} for uid in config.users for row in sessions_for(uid)]
        return render(
            request,
            "admin_dashboard.html",
            summary=summary,
            statuses=statuses,
            instance_views=views,
            session_rows=session_rows,
            session_count=len(session_rows),
            checked_at=datetime.now(timezone(timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S UTC+8"),
            counts={
                "running": sum(v["phase"] == "RUNNING" for v in views.values()),
                "attention": sum(
                    v["phase"] in {"LOST", "ERROR", "ERROR_CLEANUP_REQUIRED", "UNKNOWN"} for v in views.values()
                ),
                "pending": sum(v["drift"]["state"] == "pending" for v in views.values()),
            },
            message=flash(request),
        )

    @app.get("/admin/config", response_class=HTMLResponse)
    def admin_config(request: Request):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        return render(
            request,
            "admin_config.html",
            text=store.read_text(),
            validation=None,
            backups=store.list_backups(),
            message=flash(request),
        )

    @app.post("/admin/config/validate", response_class=HTMLResponse)
    def admin_config_validate(request: Request, text: str = Form(...), csrf: str = Form("")):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        if not check_csrf(request.session.get("csrf"), csrf):
            return render(
                request,
                "admin_config.html",
                text=text,
                validation={"ok": False, "error": {"code": "CSRF", "message": "会话已过期"}},
                backups=store.list_backups(),
                message=None,
            )
        ok, result = store.validate(text)
        affected, warning = changed_users(text) if ok else (None, None)
        return render(
            request,
            "admin_config.html",
            text=text,
            validation=result,
            affected_users=affected,
            comparison_warning=warning,
            backups=store.list_backups(),
            message=None,
        )

    @app.post("/admin/config/save", response_class=HTMLResponse)
    def admin_config_save(request: Request, text: str = Form(...), csrf: str = Form("")):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        if not check_csrf(request.session.get("csrf"), csrf):
            return render(
                request,
                "admin_config.html",
                text=text,
                validation={"ok": False, "error": {"code": "CSRF", "message": "会话已过期"}},
                backups=store.list_backups(),
                message=None,
            )
        ok, result = store.validate(text)
        if not ok:
            return render(
                request, "admin_config.html", text=text, validation=result, backups=store.list_backups(), message=None
            )
        affected, warning = changed_users(text)
        store.save(text, actor=who["username"])
        return render(
            request,
            "admin_config.html",
            text=store.read_text(),
            validation={"ok": True},
            backups=store.list_backups(),
            affected_users=affected,
            comparison_warning=warning,
            application_notes=application_notes(affected),
            message="已保存并备份。运行中的实例未被修改；受影响工作区需要停止并重新启动后应用。",
        )

    @app.get("/admin/users", response_class=HTMLResponse)
    def admin_users(request: Request):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        config = AdminConfig.load(config_path)
        return render(request, "admin_users.html", summary=_summarize(config), message=flash(request))

    @app.post("/admin/users/roles")
    def admin_users_roles(
        request: Request, user: str = Form(...), csrf: str = Form(""), roles: list[str] = Form(default=[])
    ):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        if not check_csrf(request.session.get("csrf"), csrf):
            return admin_redirect("会话已过期", path="/admin/users", level="error")
        try:
            data = yaml.safe_load(store.read_text())
            if data.get("version") != 2:
                raise ValueError("只有 version: 2 配置支持角色绑定")
            if user not in data.get("users", {}):
                raise ValueError("未知用户")
            data["users"][user]["roles"] = list(roles)
            text = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
            store.save(text, actor=who["username"])
            return admin_redirect(
                f"已保存 {user} 的角色。运行中实例不会热更新，请停止并重建后应用。",
                path="/admin/users",
                level="warning",
            )
        except Exception as exc:  # noqa: BLE001
            return admin_redirect("更新失败: " + str(exc), path="/admin/users", level="error")

    @app.get("/admin/preview", response_class=HTMLResponse)
    def admin_preview(request: Request, user: str | None = None, mode: str = "request"):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        config = AdminConfig.load(config_path)
        uid = user or next(iter(config.users), "")
        return render(
            request,
            "admin_preview.html",
            summary=_summarize(config),
            **build_preview(config, config_path, uid, mode=mode),
        )

    @app.post("/admin/instances/{user}/{action}")
    def admin_instance(request: Request, user: str, action: str, csrf: str = Form("")):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        if not check_csrf(request.session.get("csrf"), csrf):
            return admin_redirect("会话已过期", level="error")
        labels = {"start": "启动", "stop": "停止", "recover": "检查并恢复", "status": "检查状态"}
        label = labels.get(action)
        if label is None:
            return admin_redirect("非法操作", level="error")
        try:
            runner = runner_for(user)
            if action == "start":
                req_path = startup_request_path(config_path, user)
                result = runner.start(LaunchRequest.from_dict(load_document(req_path)))
            elif action == "stop":
                result = runner.stop()
            elif action == "recover":
                result = runner.recover()
            else:
                result = runner.status()
            phase = result.get("phase", "OK")
            ok = result.get("ok", True) and phase not in {"ERROR", "LOST"}
            detail = result.get("error") or result.get("reason")
            message = f"{user} {label}：{phase}" + (f"（{detail}）" if detail else "")
            if relay_supervisor is not None:
                try:
                    relay_supervisor.ensure(user, running=(phase == "RUNNING"))
                except Exception:  # noqa: BLE001 - never block the admin action
                    pass
            return admin_redirect(message, level="success" if ok else "error")
        except Exception as exc:  # noqa: BLE001
            return admin_redirect(f"{user} {action} 失败: {exc}", level="error")

    @app.post("/admin/sessions/{user}/{session_id}/terminate")
    def admin_session_terminate(request: Request, user: str, session_id: str, csrf: str = Form("")):
        who = principal(request)
        if not who or who["role"] != "admin":
            return login_redirect()
        if not check_csrf(request.session.get("csrf"), csrf):
            return admin_redirect("会话已过期", level="error")
        try:
            runner_for(user).terminate_session(session_id)
            return admin_redirect(f"{user} 会话 {session_id[:8]} 已终止", level="success")
        except Exception as exc:  # noqa: BLE001
            return admin_redirect(f"终止会话失败: {exc}", level="error")

    # ----- normal user entry -----
    @app.get("/me", response_class=HTMLResponse)
    def user_home(request: Request):
        who = principal(request)
        if not who:
            return login_redirect()
        if who["role"] != "user":
            return RedirectResponse("/admin", status_code=303)
        status = status_for(who["user_id"])
        return render(request, "user_home.html", status=status, reply=None, error=None)

    @app.post("/me/chat", response_class=HTMLResponse)
    def user_chat(request: Request, prompt: str = Form(...), csrf: str = Form("")):
        who = principal(request)
        if not who or who["role"] != "user":
            return login_redirect()
        status = None
        reply = None
        error = None
        if not check_csrf(request.session.get("csrf"), csrf):
            error = "会话已过期，请重试"
        else:
            try:
                runner = runner_for(who["user_id"])
                result = runner.chat(prompt, "web-" + who["user_id"])
                if isinstance(result, dict) and result.get("exit_code", 0) == 0:
                    stdout = result.get("stdout") or ""
                    payload = None
                    if isinstance(stdout, str):
                        try:
                            payload = json.loads(stdout)
                        except ValueError:
                            payload = None
                    if isinstance(payload, dict) and "content" in payload:
                        reply = str(payload["content"])
                    elif isinstance(stdout, str) and stdout.strip():
                        reply = stdout.strip()
                    else:
                        reply = json.dumps(result, ensure_ascii=False, indent=2)
                else:
                    error = json.dumps(result, ensure_ascii=False, indent=2)
            except Exception as exc:  # noqa: BLE001
                error = str(exc)
        try:
            status = status_for(who["user_id"])
        except Exception:
            status = {"phase": "UNKNOWN"}
        return render(request, "user_home.html", status=status, reply=reply, error=error)

    return app
