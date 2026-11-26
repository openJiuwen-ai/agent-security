"""Create the demo ``accounts.yaml`` with Argon2id password hashes.

Run on the VM with the web virtualenv (which has argon2-cffi installed):

    sudo /opt/hypershell-control/bin/python scripts/dev/create_accounts.py \
        --out /etc/hypershell-demo/accounts.yaml

Default demo accounts: ``admin`` (admin) plus ``u1`` and ``u2`` (normal users).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

import yaml

from hypershell.console import log_console
from hypershell.web.auth import hash_password


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="/etc/hypershell-demo/accounts.yaml")
    parser.add_argument(
        "--password-stdin", action="store_true", help="read one password per account from stdin (admin first)"
    )
    parser.add_argument("--admin-user", default="admin")
    parser.add_argument("--users", default="u1,u2", help="comma-separated normal user ids")
    args = parser.parse_args(argv)
    users = [u.strip() for u in args.users.split(",") if u.strip()]
    names = [args.admin_user, *users]
    if any(not name or name != name.strip() for name in names) or len(set(names)) != len(names):
        parser.error("account names must be non-empty and unique (including the administrator)")
    out = Path(args.out)
    if out.exists() or out.is_symlink():
        parser.error("accounts file already exists; refusing to overwrite credentials")

    accounts: dict[str, dict] = {}
    for name in names:
        if args.password_stdin:
            password = sys.stdin.readline().rstrip("\r\n")
        else:
            password = getpass.getpass(f"Password for {name}: ")
            if password != getpass.getpass(f"Confirm password for {name}: "):
                parser.error("passwords do not match")
        if len(password) < 12:
            parser.error("each password must contain at least 12 characters")
        password_hash = hash_password(password)
        if name == args.admin_user:
            accounts[name] = {"role": "admin", "display": "Administrator", "password_hash": password_hash}
        else:
            accounts[name] = {"role": "user", "user_id": name, "display": name.upper(), "password_hash": password_hash}

    text = yaml.safe_dump({"version": 1, "accounts": accounts}, sort_keys=False, allow_unicode=True)
    out.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(out, 0o600)
    log_console(f"wrote {out} with accounts: {', '.join(accounts)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
