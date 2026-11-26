"""Bootstrap the stock JiuwenBox launcher with private storage paths.

JiuwenBox deliberately ignores HOME and uses the effective account's home.
Configure its workspace module before importing any consumer; forked launcher
children inherit these constants. No JiuwenBox source files are patched.
"""

import argparse
import os
from pathlib import Path
import sys


def configure_workspace(workspace, path):
    if any(name in sys.modules for name in ("jiuwenbox.server.policy_engine", "jiuwenbox.server.sandbox_manager")):
        raise RuntimeError("JiuwenBox storage consumers were imported before workspace configuration")
    workspace.JIUWENBOX_HOME = path
    workspace.SANDBOX_WORKSPACE = path / "workspace"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", required=True)
    args, remaining = parser.parse_known_args()
    if os.geteuid() != 0:
        raise SystemExit("engine bootstrap requires a Linux administrator")
    path = Path(args.state_dir).absolute()
    if path.resolve() != path:
        raise SystemExit("engine storage path must not contain symlinks")
    path.mkdir(mode=0o700, exist_ok=True)
    for item in (path, *path.parents):
        info = item.stat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise SystemExit("engine storage must be root-controlled")
    from jiuwenbox.server import workspace

    configure_workspace(workspace, path)
    from jiuwenbox.server.launcher import main as launch

    sys.argv = ["jiuwenbox-server", *remaining]
    return launch()


if __name__ == "__main__":
    raise SystemExit(main())
