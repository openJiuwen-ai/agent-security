"""Run the loopback demo web UI: ``python -m hypershell.web --port 8090``."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import secrets
import stat

_LEGACY_SECRET_FILE = Path("/etc/hypershell-demo/web-secret")


def _load_session_secret(path: Path | None) -> str:
    key_file = _LEGACY_SECRET_FILE if path is None else path
    try:
        descriptor = os.open(key_file, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0), 0o600)
    except FileNotFoundError:
        if path is not None:
            raise
        # A standalone demo can run without configuring persistent credentials.
        return secrets.token_hex(32)
    try:
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise ValueError("session signing key must be a regular file")
        if os.name == "posix" and mode & 0o077:
            raise ValueError("session signing key file must have no group or other permissions")
        try:
            with os.fdopen(descriptor, encoding="utf-8", closefd=False) as handle:
                secret = handle.read().strip()
        except UnicodeError as exc:
            raise ValueError("session signing key file must contain nonempty UTF-8 text") from exc
    finally:
        os.close(descriptor)
    if not secret:
        raise ValueError("session signing key file must contain nonempty UTF-8 text")
    return secret


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HyperShell demo web UI")
    parser.add_argument("--host", default=os.environ.get("HYPERSHELL_WEB_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("HYPERSHELL_WEB_PORT", "8090")))
    parser.add_argument(
        "--config", default=os.environ.get("HYPERSHELL_ADMIN_CONFIG", "/etc/hypershell-demo/admin.yaml")
    )
    parser.add_argument("--runtime", default=os.environ.get("HYPERSHELL_RUNTIME", "/etc/hypershell-demo/runtime.yaml"))
    parser.add_argument(
        "--accounts", default=os.environ.get("HYPERSHELL_ACCOUNTS", "/etc/hypershell-demo/accounts.yaml")
    )
    parser.add_argument("--backup-dir", default=os.environ.get("HYPERSHELL_BACKUP_DIR", "/etc/hypershell-demo/backups"))
    parser.add_argument(
        "--audit", default=os.environ.get("HYPERSHELL_WEB_AUDIT", "/var/lib/hypershell-managed/web-audit.jsonl")
    )
    parser.add_argument(
        "--secret-file",
        type=Path,
        default=os.environ.get("HYPERSHELL_WEB_SECRET"),
        help="read an existing session signing key file provisioned by the administrator",
    )
    parser.add_argument(
        "--relay-host",
        default=os.environ.get("HYPERSHELL_RELAY_HOST", "0.0.0.0"),
        help="listen host for per-user web relays",
    )
    parser.add_argument(
        "--relay-port-base",
        type=int,
        default=int(os.environ.get("HYPERSHELL_RELAY_PORT_BASE", "0")),
        help="first per-user relay port (user index added); 0 disables auto-relay",
    )
    parser.add_argument(
        "--relay-frontend-port", type=int, default=int(os.environ.get("HYPERSHELL_RELAY_FRONTEND_PORT", "5173"))
    )
    parser.add_argument(
        "--relay-gate-url",
        default=os.environ.get("HYPERSHELL_RELAY_GATE_URL"),
        help="gateway URL used by relays for session gating; defaults to loopback of --port",
    )
    parser.add_argument(
        "--relay-login-url",
        default=os.environ.get("HYPERSHELL_RELAY_LOGIN_URL"),
        help="browser redirect target for unauthenticated relay requests",
    )
    parser.add_argument("--relay-log-dir", default=os.environ.get("HYPERSHELL_RELAY_LOG_DIR", "/tmp"))
    parser.add_argument(
        "--relay-python",
        default=os.environ.get("HYPERSHELL_RELAY_PYTHON"),
        help="interpreter for relay subprocesses; defaults to this interpreter",
    )
    args = parser.parse_args(argv)
    try:
        secret = _load_session_secret(args.secret_file)
    except OSError as exc:
        parser.error(f"cannot read session signing key file: {exc.strerror}")
    except ValueError as exc:
        parser.error(str(exc))

    import uvicorn

    from .app import create_app

    relay_config = None
    if args.relay_port_base > 0:
        relay_config = {
            "port_base": args.relay_port_base,
            "host": args.relay_host,
            "frontend_port": args.relay_frontend_port,
            "gate_url": args.relay_gate_url or f"http://127.0.0.1:{args.port}",
            "login_url": args.relay_login_url,
            "log_dir": args.relay_log_dir,
            "python": args.relay_python or None,
        }

    app = create_app(
        config_path=args.config,
        runtime_path=args.runtime,
        accounts_path=args.accounts,
        backup_dir=args.backup_dir,
        audit_path=args.audit,
        secret_key=secret,
        relay_config=relay_config,
    )
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
