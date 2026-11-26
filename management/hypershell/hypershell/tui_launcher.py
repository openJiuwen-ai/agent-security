"""Privileged TUI launcher for normal users (demo, scheme A).

This module is *only* meant to run as root, invoked by a sudoers-whitelisted
wrapper (see ``scripts/dev/install_tui_launcher.sh``). It:

1. prompts for the HyperShell account (same Argon2id store as the web UI);
2. maps the authenticated principal to a configured ``user_id``;
3. reuses :meth:`ManagedRunner.tui`, which starts the TUI through the restricted
   backend's PTY broker and only forwards terminal bytes through a fixed relay.

The interactive TUI and fixed host relay run as the workload identity. The root
coordinator remains for the session to hold the workspace lock and manage jobs.
"""

from __future__ import annotations

import argparse
import getpass
import os
from typing import Any, Mapping

from .console import log_console

DEFAULT_ACCOUNTS = "/etc/hypershell-demo/accounts.yaml"
DEFAULT_CONFIG = "/etc/hypershell-demo/admin.yaml"
DEFAULT_RUNTIME = "/etc/hypershell-demo/runtime.yaml"


class LauncherError(Exception):
    """Authentication or account-mapping failure."""


def resolve_user_id(accounts: Mapping[str, dict[str, Any]], username: str, password: str) -> str:
    """Authenticate and return the configured ``user_id`` (rejecting admins)."""
    from .web.auth import authenticate

    principal = authenticate(accounts, username, password)
    if principal is None:
        raise LauncherError("账号或密码错误")
    if principal["role"] != "user":
        raise LauncherError("管理员账号请使用管理员 CLI：sudo hypershell-demo tui --user ...")
    user_id = principal.get("user_id")
    if not user_id:
        raise LauncherError("账号未绑定 user_id")
    return user_id


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hypershell-tui",
        description="Authenticate and attach to your HyperShell workspace TUI",
    )
    parser.add_argument("--accounts", default=os.environ.get("HYPERSHELL_ACCOUNTS", DEFAULT_ACCOUNTS))
    parser.add_argument("--config", default=os.environ.get("HYPERSHELL_ADMIN_CONFIG", DEFAULT_CONFIG))
    parser.add_argument("--runtime", default=os.environ.get("HYPERSHELL_RUNTIME", DEFAULT_RUNTIME))
    parser.add_argument("--dry-run", action="store_true", help="authenticate and print the mapping, do not attach")
    args = parser.parse_args(argv)

    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        log_console("hypershell-tui 需要以特权方式运行，请使用 /usr/local/bin/hypershell-tui", error=True)
        return 3

    from .config import AdminConfig
    from .web.auth import load_accounts

    try:
        accounts = load_accounts(args.accounts)
    except Exception as exc:  # noqa: BLE001
        log_console(f"无法加载账号文件：{exc}", error=True)
        return 3

    try:
        username = input("HyperShell 账号：").strip()
        password = getpass.getpass("密码：")
    except (EOFError, KeyboardInterrupt):
        log_console("\n已取消", error=True)
        return 130

    try:
        user_id = resolve_user_id(accounts, username, password)
    except LauncherError as exc:
        log_console(f"认证失败：{exc}", error=True)
        return 1

    config = AdminConfig.load(args.config)
    if user_id not in config.users:
        log_console(f"账号映射的用户 {user_id!r} 不在管理员配置中", error=True)
        return 3

    profile = config.users[user_id]
    if args.dry_run:
        log_console(f"AUTH_OK user_id={user_id} run_as_user={profile.run_as_user}")
        return 0

    from .runner.managed import ManagedRunner

    runner = ManagedRunner(config, args.runtime, user_id)
    try:
        state = runner.status()
        if state.get("phase") != "RUNNING":
            log_console(f"工作区未运行（{state.get('phase')}），请联系管理员启动后再试", error=True)
            return 3
        runner.audit("TUI_LOGIN", account=username)
        return runner.tui()
    except Exception as exc:  # noqa: BLE001
        log_console(f"启动 TUI 失败：{exc}", error=True)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
