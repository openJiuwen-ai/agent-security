"""Permission preview and Linux managed-workspace CLI."""

from __future__ import annotations

import argparse
import json
import logging
import os

from .config import AdminConfig, load_document
from .console import log_console
from .policy import InvalidRequest, LaunchRequest, PolicyError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HyperShell policy preview and Linux managed demo")
    commands = parser.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan", help="validate a request and preview its sandbox policy")
    plan.add_argument("--config", required=True, help="administrator YAML configuration")
    plan.add_argument("--request", required=True, help="resource request YAML")
    plan.add_argument("--demo-user", help="simulate a user profile; does not authenticate or deploy")
    config_parser = commands.add_parser("config", help="validate administrator configuration")
    validate = config_parser.add_subparsers(dest="config_action", required=True).add_parser("validate")
    validate.add_argument("--config", required=True)
    grants_parser = commands.add_parser("grants", help="explain administrator-assigned authorization")
    explain = grants_parser.add_subparsers(dest="grants_action", required=True).add_parser("explain")
    explain.add_argument("--config", required=True)
    explain.add_argument("--user", required=True, help="profile to inspect; does not authenticate")
    explain.add_argument("--resource", help="optional resource id")
    for name in ("start", "status", "chat", "tui", "web", "stop", "doctor", "recover"):
        live = commands.add_parser(name, help="Linux administrator managed workspace: " + name)
        live.add_argument("--config", default="/etc/hypershell-demo/admin.yaml")
        live.add_argument("--runtime", default="/etc/hypershell-demo/runtime.yaml")
        live.add_argument("--user", default="u1", help="admin-selected workspace; live commands require root")
        if name == "start":
            live.add_argument(
                "--request", help="resource request; defaults to request-USER.yaml, or legacy request.yaml"
            )
        if name == "web":
            live.add_argument(
                "--listen-host", default="127.0.0.1", help="host loopback endpoint for the browser/gateway"
            )
            live.add_argument("--listen-port", type=int, default=8091)
            live.add_argument("--frontend-port", type=int, default=5173, help="in-sandbox app_web loopback port")
            live.add_argument(
                "--gate-url",
                default=None,
                help="HyperShell gateway URL for session gating (e.g. http://127.0.0.1:8090)",
            )
            live.add_argument("--login-url", default=None, help="redirect target for unauthenticated browsers")
        if name == "recover":
            live.add_argument(
                "--legacy-after-reboot",
                action="store_true",
                help="administrator confirms a reboot for legacy states without a boot ID",
            )
        if name == "chat":
            live.add_argument("prompt")
            live.add_argument("--session", default="hypershell-managed-demo")
    args = parser.parse_args(argv)
    try:
        if args.command in ("config", "grants"):
            config = AdminConfig.load(args.config)
            result = (
                {"valid": True, "version": config.version, "users": sorted(config.users), "roles": sorted(config.roles)}
                if args.command == "config"
                else config.explain(args.user, args.resource)
            )
            log_console(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
            return 0
        if args.command != "plan":
            from .runner.managed import ManagedRunner, require_admin, trusted

            require_admin()
            config = AdminConfig.load(trusted(args.config))
            runner = ManagedRunner(config, args.runtime, args.user)
            if args.command == "start":
                try:
                    from pathlib import Path

                    request_path = args.request
                    if request_path is None:
                        candidate = Path(args.config).parent / ("request-" + args.user + ".yaml")
                        request_path = (
                            candidate
                            if candidate.exists() or len(config.users) > 1
                            else Path(args.config).parent / "request.yaml"
                        )
                    result = runner.start(LaunchRequest.from_dict(load_document(request_path)))
                except PolicyError as exc:
                    runner.audit("REQUEST_REJECTED", code=exc.code)
                    raise
            elif args.command == "chat":
                result = runner.chat(args.prompt, args.session)
            elif args.command == "tui":
                return runner.tui()
            elif args.command == "web":
                logging.basicConfig(level=logging.INFO, format="%(message)s")
                result = runner.web(
                    host=args.listen_host,
                    port=args.listen_port,
                    frontend_port=args.frontend_port,
                    gate_url=args.gate_url,
                    login_url=args.login_url,
                )
                log_console(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
                return 0
            elif args.command == "recover":
                result = runner.recover(legacy_after_reboot=args.legacy_after_reboot)
            else:
                result = getattr(runner, args.command)()
            success = args.command != "chat" or result["exit_code"] == 0
            if args.command == "doctor":
                success = result["ready"]
            if args.command == "status":
                success = result["phase"] in ("RUNNING", "STOPPED")
            log_console(json.dumps({"ok": success, **result}, ensure_ascii=False, indent=2))
            return 0 if success else 1
        config = AdminConfig.load(args.config)
        if args.demo_user is not None:
            user_id = args.demo_user
        elif hasattr(os, "getuid"):
            user_id = config.user_for_uid(os.getuid())
        else:
            raise InvalidRequest("OS UID mapping requires Linux; use --demo-user for a simulated preview")
        request = LaunchRequest.from_dict(load_document(args.request))
        result = config.preview(user_id, request, simulated=args.demo_user is not None)
    except PolicyError as exc:
        log_console(json.dumps({"ok": False, "error": exc.to_dict()}, ensure_ascii=False, indent=2), error=True)
        return 2
    except (OSError, KeyError, ValueError) as exc:
        log_console(json.dumps({"ok": False, "error": {"code": "RUNTIME_ERROR", "message": str(exc)}}), error=True)
        return 2
    log_console(json.dumps({"ok": True, **result}, ensure_ascii=False, indent=2))
    return 0
